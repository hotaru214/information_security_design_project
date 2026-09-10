import sqlite3
from contextlib import closing

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend import database
from backend.routers.events import router as events_router
from backend.routers.attack_chain import router as chain_router
from backend.schemas.event import EventCreate


def event(**changes):
    result = dict(timestamp="2026-09-09T12:00:00+08:00", host="web",
                  source="sysmon", source_event_id=4688, event_type="process_start",
                  user=None, process="powershell", src_ip=None, dst_ip=None,
                  dst_port=None, protocol=None, logon_type=None, session_id=None,
                  cmdline=None, detail={}, description="process evidence",
                  anomaly_flags=[], severity=2, raw_log="original log")
    result.update(changes)
    return result


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "test.db")
    database.init_db()
    app = FastAPI()
    app.include_router(events_router)
    app.include_router(chain_router)
    with TestClient(app) as c:
        yield c


def test_new_schema_and_idempotent_migration(client):
    database.init_db()
    with closing(database.get_connection()) as con:
        columns = {r["name"]: r for r in con.execute("PRAGMA table_info(events)")}
        assert columns["case_id"]["type"] == "TEXT"
        assert columns["case_id"]["notnull"] == 0
        assert "idx_events_case_id" in {r["name"] for r in con.execute("PRAGMA index_list(events)")}


def test_old_database_additive_migration(tmp_path, monkeypatch):
    path = tmp_path / "old.db"
    monkeypatch.setattr(database, "DB_PATH", path)
    # Recreate the actual pre-case schema, independent of production init_db.
    with closing(sqlite3.connect(path)) as con:
        con.execute("""CREATE TABLE events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
            host TEXT NOT NULL, source TEXT NOT NULL, event_id INTEGER,
            event_type TEXT NOT NULL, user TEXT, process TEXT, src_ip TEXT,
            dst_ip TEXT, dst_port INTEGER, protocol TEXT, logon_type INTEGER,
            session_id TEXT, cmdline TEXT, detail TEXT NOT NULL,
            description TEXT NOT NULL, anomaly_flags TEXT NOT NULL,
            severity INTEGER NOT NULL, raw_log TEXT NOT NULL)""")
        con.execute("""INSERT INTO events(id,timestamp,host,source,event_id,event_type,
            detail,description,anomaly_flags,severity,raw_log)
            VALUES(73,'2026-09-09T12:00:00+08:00','web','sysmon',4688,
            'process_start','{}','old','[]',0,'preserve raw')""")
        con.execute("CREATE TABLE extra(value TEXT)")
        con.execute("INSERT INTO extra VALUES ('preserve')")
        con.commit()
        before = con.execute("SELECT * FROM events").fetchone()
    database.init_db()
    database.init_db()
    with closing(database.get_connection()) as con:
        row = tuple(con.execute("SELECT * FROM events").fetchone())
        assert row[:-1] == before and row[-1] is None
        assert con.execute("SELECT value FROM extra").fetchone()[0] == "preserve"
    new = database.insert_event(EventCreate.model_validate(event(case_id="case01")))
    assert new["id"] == 74
    assert database.get_event_by_id(73)["case_id"] is None


@pytest.mark.parametrize("path", ["/api/events", "/api/events/batch", "/api/events/import"])
def test_all_write_paths_roundtrip(client, path):
    payload = event(case_id="case01")
    response = client.post(path, json=payload if path == "/api/events" else [payload])
    assert response.status_code == 201
    saved = client.get("/api/events").json()[0]
    assert saved["case_id"] == "case01" and saved["source_event_id"] == 4688
    assert saved["id"] != 4688
    assert client.get(f"/api/events/{saved['id']}").json() == saved


def test_import_assigns_case_without_conflating_batch(client):
    response = client.post("/api/events/import?case_id=case01", json=[
        event(detail={"batch_id": "host-upload"}),
        event(source="network_pcap", source_event_id=None, detail={"batch_id": "pcap-upload"})])
    assert response.status_code == 201
    saved = client.get("/api/events?case_id=case01").json()
    assert len(saved) == 2
    assert {e["case_id"] for e in saved} == {"case01"}
    assert {e["detail"]["batch_id"] for e in saved} == {"host-upload", "pcap-upload"}
    assert client.post("/api/events/import?case_id=case01", json=[event(case_id="case02")]).status_code == 422
    assert len(database.get_events()) == 2


@pytest.mark.parametrize("canonical", [None, 1, 4688])
def test_legacy_alias_does_not_override_canonical_or_db_id(client, canonical):
    payload = event(source_event_id=canonical, event_id=4624, id=9999)
    result = client.post("/api/events", json=payload).json()
    assert result["source_event_id"] == canonical
    assert result["id"] == 1
    payload.pop("source_event_id")
    result = client.post("/api/events", json=payload).json()
    assert result["source_event_id"] == 4624 and result["id"] == 2


def test_case_isolation_propagation_filter_and_evidence(client):
    initial = event(case_id="case01", event_type="http_request", source="windows_evtx",
                    source_event_id=4688, src_ip="8.8.8.8", dst_ip="10.10.20.10",
                    detail={"uri": "/shell"}, process=None)
    execution = event(case_id="case02", timestamp="2026-09-09T12:01:00+08:00")
    assert client.post("/api/events/batch", json=[initial, execution]).status_code == 201
    rows = client.get("/api/events").json()
    assert len({e["id"] for e in rows}) == 2
    assert {e["source_event_id"] for e in rows} == {4688}
    by_id = {e["id"]: e for e in rows}
    chain = client.get("/api/attack-chain").json()
    assert {l["case_id"] for l in chain["links"]} == {"case01", "case02"}
    for link in chain["links"]:
        assert link["evidence_event_ids"]
        for eid in link["evidence_event_ids"]:
            assert by_id[eid]["case_id"] == link["case_id"]
            assert client.get(f"/api/events/{eid}").status_code == 200
    filtered = client.get("/api/attack-chain?case_id=case01").json()
    assert filtered["meta"]["event_count"] == 1
    assert filtered["links"] and all(l["case_id"] == "case01" for l in filtered["links"])
    assert len(client.get("/api/events?case_id=case01").json()) == 1
    assert client.get("/api/attack-chain?case_id=absent").json()["links"] == []


def test_legacy_case_filter_matches_d_precedence(client):
    for payload in [event(detail={"batch_id": "case01"}),
                    event(detail={"case_id": "case01", "batch_id": "other"}),
                    event(case_id="case02", detail={"case_id": "case01"}), event()]:
        assert client.post("/api/events", json=payload).status_code == 201
    rows = client.get("/api/events?case_id=case01").json()
    assert len(rows) == 2 and all(e["case_id"] is None for e in rows)
    assert all(l["case_id"] == "case01" for l in client.get("/api/attack-chain?case_id=case01").json()["links"])
