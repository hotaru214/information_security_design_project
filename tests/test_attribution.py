import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.analysis import build_attribution_profile, correlate_events
from backend.routers import attack_chain as attack_chain_module
from backend.routers.attack_chain import router as attack_chain_router


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_PATH = PROJECT_ROOT / "data" / "sample_events" / "d_attack_chain_events.json"


def load_sample():
    return json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))


def test_attribution_profile_extracts_fingerprints_and_c2():
    sample = load_sample()
    steps = correlate_events(sample["events"], sample["host_map"])

    profile = build_attribution_profile(sample["events"], steps, sample["host_map"])

    assert profile["case_id"] == "apt29_case_001"
    assert "bash" in profile["fingerprints"]["tools"]
    assert "reg.exe" in profile["fingerprints"]["tools"]
    assert "wevtutil.exe" in profile["fingerprints"]["tools"]
    assert "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" in profile["fingerprints"]["registry_keys"]
    assert "T1021" in profile["fingerprints"]["techniques"]
    assert profile["c2_infrastructure"][0]["ip"] == "47.88.10.9"
    assert 10 in profile["c2_infrastructure"][0]["evidence_event_ids"]
    assert profile["apt_matches"][0]["name"] == "APT29 emulation profile"
    assert profile["apt_matches"][0]["final_score"] > 0.5


def test_attribution_profile_preserves_database_evidence_ids():
    events = [
        {
            "id": 501,
            "case_id": "case-a",
            "timestamp": "2026-09-08T13:00:00+08:00",
            "host": "pc-a",
            "source": "sysmon",
            "source_event_id": 1,
            "event_type": "process_start",
            "user": "alice",
            "process": "powershell.exe",
            "src_ip": None,
            "dst_ip": None,
            "dst_port": None,
            "protocol": None,
            "logon_type": None,
            "session_id": None,
            "cmdline": "powershell.exe -enc abc",
            "detail": {"file_path": "C:\\Users\\Public\\run.ps1"},
            "description": "PowerShell execution",
            "anomaly_flags": ["suspicious_process"],
            "severity": 3,
            "raw_log": "Sysmon EventID=1 powershell",
        }
    ]
    steps = correlate_events(events)

    profile = build_attribution_profile(events, steps)

    assert profile["evidence_event_ids"] == [501]
    assert 1 not in profile["evidence_event_ids"]
    assert "C:\\Users\\Public\\run.ps1" in profile["fingerprints"]["scripts"]


def test_attribution_profile_analyzes_cases_independently():
    sample = load_sample()
    other_event = dict(sample["events"][1], id=900, case_id="other_case")
    other_event["timestamp"] = "2026-09-08T15:00:00+08:00"
    other_event["cmdline"] = "cmd.exe /c whoami"
    events = sample["events"] + [other_event]
    steps = correlate_events(events, sample["host_map"])

    profile = build_attribution_profile(events, steps, sample["host_map"])

    assert profile["case_id"] is None
    assert {case["case_id"] for case in profile["profiles"]} == {"apt29_case_001", "other_case"}


def test_attribution_endpoint_returns_profile(monkeypatch):
    sample = load_sample()
    monkeypatch.setattr(attack_chain_module, "get_events", lambda case_id=None: sample["events"])
    monkeypatch.setattr(
        attack_chain_module,
        "get_hosts",
        lambda: [
            {"ip": ip, "hostname": hostname, "role": "host"}
            for ip, hostname in sample["host_map"].items()
        ],
    )

    app = FastAPI()
    app.include_router(attack_chain_router)
    client = TestClient(app)

    response = client.get("/api/attack-chain/attribution")

    assert response.status_code == 200
    data = response.json()
    assert data["case_id"] == "apt29_case_001"
    assert data["apt_matches"][0]["name"] == "APT29 emulation profile"
