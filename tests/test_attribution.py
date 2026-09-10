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
    assert profile["attribution_status"] == "ok"
    assert "bash" in profile["fingerprints"]["tools"]
    assert "reg.exe" in profile["fingerprints"]["tools"]
    assert "wevtutil.exe" in profile["fingerprints"]["tools"]
    assert "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" in profile["fingerprints"]["registry_keys"]
    assert "T1021" in profile["fingerprints"]["techniques"]
    assert profile["c2_infrastructure"][0]["ip"] == "47.88.10.9"
    assert profile["c2_infrastructure"][0]["registration"]["registered_org"] == "Course Lab VPS Provider"
    assert "apt29-c2.lab" in profile["c2_infrastructure"][0]["related_domains"]
    assert profile["c2_infrastructure"][0]["history"]
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


def test_attribution_fingerprints_ignore_low_value_system_artifacts():
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
            "cmdline": "powershell.exe -File C:\\CASE01\\jump.ps1",
            "detail": {"file_path": "C:\\CASE01\\jump.ps1"},
            "description": "PowerShell execution",
            "anomaly_flags": ["suspicious_process"],
            "severity": 3,
            "raw_log": "PowerShell C:\\CASE01\\jump.ps1",
        },
        {
            "id": 502,
            "case_id": "case-a",
            "timestamp": "2026-09-08T13:00:01+08:00",
            "host": "linux-a",
            "source": "linux_audit",
            "source_event_id": None,
            "event_type": "file_read",
            "user": "alice",
            "process": "gnome-shell",
            "src_ip": None,
            "dst_ip": None,
            "dst_port": None,
            "protocol": None,
            "logon_type": None,
            "session_id": None,
            "cmdline": None,
            "detail": {"file_path": "/usr/share/gnome-shell/extensions/ding@rastersoft.com/app/ding.js"},
            "description": "Desktop extension read ding.js from rastersoft.com path",
            "anomaly_flags": [],
            "severity": 0,
            "raw_log": "normal file read /usr/share/gnome-shell/extensions/ding@rastersoft.com/app/ding.js",
        },
    ]
    steps = [
        {
            "case_id": "case-a",
            "stage": "Execution",
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "timestamp": "2026-09-08T13:00:00+08:00",
            "source_host": "pc-a",
            "target_host": "pc-a",
            "source_ip": None,
            "target_ip": None,
            "description": "Suspicious script execution",
            "evidence_event_ids": [501, 502],
        }
    ]

    profile = build_attribution_profile(events, steps)

    assert "powershell.exe" in profile["fingerprints"]["tools"]
    assert "gnome-shell" not in profile["fingerprints"]["tools"]
    assert "C:\\CASE01\\jump.ps1" in profile["fingerprints"]["scripts"]
    assert not any("ding.js" in script for script in profile["fingerprints"]["scripts"])
    assert "rastersoft.com" not in profile["fingerprints"]["domains"]


def test_attribution_c2_infrastructure_excludes_weak_entry_source_callback():
    events = [
        {
            "id": 501,
            "case_id": "case-a",
            "timestamp": "2026-09-08T13:00:00+08:00",
            "host": "web-server",
            "source": "network_pcap",
            "source_event_id": None,
            "event_type": "network_connection",
            "user": None,
            "process": None,
            "src_ip": "10.10.20.10",
            "dst_ip": "10.10.10.10",
            "dst_port": 34382,
            "protocol": "tcp",
            "logon_type": None,
            "session_id": None,
            "cmdline": None,
            "detail": {},
            "description": "weak callback to original entry source",
            "anomaly_flags": [],
            "severity": 0,
            "raw_log": "flow",
        },
        {
            "id": 502,
            "case_id": "case-a",
            "timestamp": "2026-09-08T13:00:01+08:00",
            "host": "win10-jump",
            "source": "network_pcap",
            "source_event_id": None,
            "event_type": "http_request",
            "user": None,
            "process": None,
            "src_ip": "10.10.30.10",
            "dst_ip": "10.10.10.20",
            "dst_port": 8080,
            "protocol": "tcp",
            "logon_type": None,
            "session_id": None,
            "cmdline": None,
            "detail": {"uri": "/test-beacon"},
            "description": "C2 beacon",
            "anomaly_flags": ["c2_beacon"],
            "severity": 3,
            "raw_log": "C2 beacon",
        },
    ]
    steps = [
        {
            "case_id": "case-a",
            "stage": "Initial Access",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "timestamp": "2026-09-08T12:59:59+08:00",
            "source_host": None,
            "target_host": "web-server",
            "source_ip": "10.10.10.10",
            "target_ip": "10.10.20.10",
            "description": "entry source",
            "evidence_event_ids": [],
        },
        {
            "case_id": "case-a",
            "stage": "Command and Control",
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
            "timestamp": "2026-09-08T13:00:00+08:00",
            "source_host": "web-server",
            "target_host": None,
            "source_ip": "10.10.20.10",
            "target_ip": "10.10.10.10",
            "description": "weak callback",
            "evidence_event_ids": [501],
        },
        {
            "case_id": "case-a",
            "stage": "Command and Control",
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
            "timestamp": "2026-09-08T13:00:01+08:00",
            "source_host": "win10-jump",
            "target_host": "c2-server",
            "source_ip": "10.10.30.10",
            "target_ip": "10.10.10.20",
            "description": "strong c2",
            "evidence_event_ids": [502],
        },
    ]

    profile = build_attribution_profile(
        events,
        steps,
        internal_networks=["10.10.20.0/24", "10.10.30.0/24"],
    )

    assert [item["ip"] for item in profile["c2_infrastructure"]] == ["10.10.10.20"]


def test_attribution_c2_infrastructure_surfaces_intel_context():
    events = [
        {
            "id": 700,
            "case_id": "case-a",
            "timestamp": "2026-09-08T13:00:00+08:00",
            "host": "win10-jump",
            "source": "network_pcap",
            "source_event_id": None,
            "event_type": "http_request",
            "user": None,
            "process": None,
            "src_ip": "10.10.30.10",
            "dst_ip": "10.10.10.20",
            "dst_port": 8080,
            "protocol": "tcp",
            "logon_type": None,
            "session_id": None,
            "cmdline": None,
            "detail": {"method": "GET", "uri": "/beacon"},
            "description": "C2 beacon",
            "anomaly_flags": ["c2_beacon"],
            "severity": 3,
            "raw_log": "GET /beacon HTTP/1.1",
        }
    ]
    steps = [
        {
            "case_id": "case-a",
            "stage": "Command and Control",
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
            "timestamp": "2026-09-08T13:00:00+08:00",
            "source_host": "win10-jump",
            "target_host": "c2-server",
            "source_ip": "10.10.30.10",
            "target_ip": "10.10.10.20",
            "description": "C2 beacon",
            "evidence_event_ids": [700],
        }
    ]
    threat_intel = {
        "infrastructure": {
            "10.10.10.20": {
                "registration": {
                    "registered_org": "Case01 Lab C2 Server",
                    "registrar": "Local Course Threat Intel",
                    "asn": "AS-LAB-CASE01",
                    "country": "Lab",
                },
                "related_domains": ["case01-c2.lab", "apt29-c2.lab"],
                "history": ["Observed as Case01 HTTP C2."],
                "tags": ["lab-c2", "http-c2"],
            }
        }
    }

    profile = build_attribution_profile(
        events,
        steps,
        threat_intel=threat_intel,
        internal_networks=["10.10.20.0/24", "10.10.30.0/24"],
    )

    c2 = profile["c2_infrastructure"][0]
    assert c2["registration"]["registered_org"] == "Case01 Lab C2 Server"
    assert c2["registration"]["asn"] == "AS-LAB-CASE01"
    assert c2["history"] == ["Observed as Case01 HTTP C2."]
    assert c2["related_domains"] == ["apt29-c2.lab", "case01-c2.lab"]


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


def test_attribution_profile_returns_no_candidates_without_evidence():
    profile = build_attribution_profile([], [])

    assert profile["attribution_status"] == "insufficient_evidence"
    assert profile["apt_matches"] == []
    assert profile["evidence_event_ids"] == []


def test_attribution_endpoint_returns_no_candidates_for_absent_case(monkeypatch):
    sample = load_sample()

    def fake_get_events(case_id=None):
        if case_id == "absent":
            return []
        return sample["events"]

    monkeypatch.setattr(attack_chain_module, "get_events", fake_get_events)
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

    response = client.get("/api/attack-chain/attribution?case_id=absent")

    assert response.status_code == 200
    data = response.json()
    assert data["attribution_status"] == "insufficient_evidence"
    assert data["apt_matches"] == []
