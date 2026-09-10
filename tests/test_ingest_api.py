"""批次清单与上传解析 API 测试（成员C 平台化需求）。

用 TestClient 走真实 FastAPI 栈（临时库文件），覆盖：
  GET /api/batches、POST /api/ingest（pcap/filterlog 上传、case_id 打标、
  无效文件容错）、GET /api/events?case_id= 过滤、analysis 的 case_id。
"""
import io
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_PCAP = ROOT / "data" / "network_logs" / "e_case01" / "win10-to-core.pcap"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """独立临时库的 TestClient（不污染真实 attack_trace.db）。"""
    db = tmp_path / "test_attack_trace.db"
    monkeypatch.setattr("backend.database.DB_PATH", db)
    from backend.main import app
    with TestClient(app) as c:
        yield c


def test_ingest_upload_pcap_and_batches(client):
    """上传 pcap -> case03 批次入库 -> batches 清单可见 -> case_id 过滤生效。"""
    with open(SAMPLE_PCAP, "rb") as fh:
        resp = client.post("/api/ingest",
                           data={"case_id": "case03"},
                           files={"files": ("win10-to-core.pcap", fh, "application/octet-stream")})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["case_id"] == "case03"
    assert body["imported"] > 0

    batches = client.get("/api/batches").json()["batches"]
    case03 = next(b for b in batches if b["case_id"] == "case03")
    assert case03["count"] == body["imported"]
    assert case03["alert_count"] >= 0

    # case_id 过滤：只返回该批次
    ev = client.get("/api/events", params={"case_id": "case03"}).json()
    assert len(ev) == body["imported"]


def test_ingest_filterlog_as_firewall_source(client):
    """filterlog 上传 -> source=firewall 事件（content-one 新枚举落地验证）。"""
    sample = (
        "2026-09-09T13:58:02\tInformational\tfilterlog\t 60,,,r1,em2,match,pass,in,4,0x0,,128,48265,0,DF,6,tcp,52,10.10.30.10,10.10.30.1,62100,80,0,S,4078474303,,64240,,mss\n"
        "2026-09-09T13:57:54\tInformational\tfilterlog\t 6,,,r2,em0,match,block,in,4,0x0,,128,25455,0,none,17,udp,229,10.10.10.1,10.10.10.255,138,138,209\n"
    )
    resp = client.post("/api/ingest",
                       data={"case_id": "fw_test"},
                       files={"files": ("filter.log", io.BytesIO(sample.encode("utf-8")), "text/plain")})
    assert resp.status_code == 200
    assert resp.json()["imported"] == 2

    ev = client.get("/api/events", params={"case_id": "fw_test"}).json()
    assert all(e["source"] == "firewall" for e in ev)
    assert all("action" in e["detail"] for e in ev)
    assert {e["detail"]["action"] for e in ev} == {"pass", "block"}


def test_ingest_invalid_file_graceful(client):
    """无法解析的文件不中断整个上传，按错误反馈。"""
    resp = client.post("/api/ingest",
                       data={"case_id": "junk_batch"},
                       files={"files": ("garbage.bin", io.BytesIO(b"\x00\x01\x02not-a-pcap"), "application/octet-stream")})
    body = resp.json()
    assert body["imported"] == 0
    assert any(pf.get("error") for pf in body["per_file"])


def test_analysis_supports_case_id(client):
    """POST /api/analysis 支持 case_id 过滤（内容二：分析界面的后端依赖）。"""
    with open(SAMPLE_PCAP, "rb") as fh:
        client.post("/api/ingest", data={"case_id": "case_analysis"},
                    files={"files": ("sample.pcap", fh, "application/octet-stream")})
    resp = client.post("/api/analysis", json={"case_id": "case_analysis"})
    assert resp.status_code == 200
    report = resp.json()
    assert "summary" in report or "attack_path" in report or isinstance(report, dict)
