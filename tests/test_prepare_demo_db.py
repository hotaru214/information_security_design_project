import hashlib
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from backend import database
from scripts import prepare_demo_db as tool


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def old_db(tmp_path, monkeypatch):
    path = tmp_path / "attack_trace.db"
    monkeypatch.setattr(database, "DB_PATH", path)
    database.init_db()
    with closing(sqlite3.connect(path)) as con:
        con.execute("INSERT INTO hosts(hostname,ip,role) VALUES ('test','10.1.1.1','test')")
        con.execute("""INSERT INTO events(timestamp,host,source,event_type,detail,
                    description,anomaly_flags,severity,raw_log)
                    VALUES ('2026-09-08T12:00:00+08:00','test','sysmon',
                    'process_start','{}','test','[]',0,'raw')""")
        con.execute("CREATE TABLE extra_data(value TEXT)")
        con.execute("INSERT INTO extra_data VALUES ('preserve me')")
        con.commit()
    return path


def test_preview_is_read_only(old_db):
    before = digest(old_db)
    files = set(old_db.parent.iterdir())
    assert tool.main([]) == 0
    assert digest(old_db) == before
    assert set(old_db.parent.iterdir()) == files
    assert tool.read_state(old_db)["counts"]["events"] == 1


def test_execute_backups_all_tables_and_reuses_schema(old_db):
    result = tool.prepare_demo_db(True)
    backup = Path(result["backup"])
    state = tool.read_state(backup)
    assert state["counts"]["events"] == state["counts"]["hosts"] == 1
    assert state["counts"]["extra_data"] == 1
    with closing(sqlite3.connect(backup)) as con:
        assert con.execute("SELECT raw_log FROM events").fetchone() == ("raw",)
        assert con.execute("SELECT value FROM extra_data").fetchone() == ("preserve me",)
    assert result["after"]["counts"] == {"events": 0, "hosts": 0, "sqlite_sequence": 0}
    assert database.DB_PATH == old_db
    second = tool.prepare_demo_db(True)
    assert second["backup"] != result["backup"]
    assert backup.exists()


def test_backup_failure_keeps_original(old_db, monkeypatch):
    before = digest(old_db)
    def fail(*args):
        raise OSError("simulated backup failure")
    monkeypatch.setattr(tool, "create_backup", fail)
    assert tool.main(["--execute"]) == 1
    assert digest(old_db) == before


def test_init_failure_keeps_backup_and_original(old_db, monkeypatch):
    before = digest(old_db)
    def fail():
        raise RuntimeError("simulated initialization failure")
    monkeypatch.setattr(database, "init_db", fail)
    assert tool.main(["--execute"]) == 1
    assert digest(old_db) == before
    assert database.DB_PATH == old_db
    backup = next((old_db.parent / "backups").glob("*.db"))
    assert tool.read_state(backup)["counts"]["events"] == 1


def test_absent_db_requires_execute(tmp_path, monkeypatch):
    path = tmp_path / "data" / "attack_trace.db"
    monkeypatch.setattr(database, "DB_PATH", path)
    assert tool.main([]) == 0
    assert not path.parent.exists()
    assert tool.main(["--execute"]) == 0
    assert tool.read_state(path)["counts"]["events"] == 0
    assert not (path.parent / "backups").exists()


def test_verification_failure_preserves_original(old_db, monkeypatch):
    before = digest(old_db)
    def fail(path):
        raise RuntimeError("verification failure")
    monkeypatch.setattr(tool, "verify_new", fail)
    assert tool.main(["--execute"]) == 1
    assert digest(old_db) == before
    assert list((old_db.parent / "backups").glob("*.db"))


def test_replace_failure_keeps_backup(old_db, monkeypatch):
    before = digest(old_db)
    def fail(*args):
        raise PermissionError("database in use")
    monkeypatch.setattr(tool.os, "replace", fail)
    assert tool.main(["--execute"]) == 1
    assert digest(old_db) == before
    assert list((old_db.parent / "backups").glob("*.db"))


def test_wal_backup_includes_committed_rows(old_db):
    backup = old_db.parent / "wal_backup.db"
    with closing(sqlite3.connect(old_db)) as con:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("INSERT INTO extra_data VALUES ('in WAL')")
        con.commit()
        assert Path(str(old_db) + "-wal").exists()
        tool.create_backup(old_db, backup)
        assert tool.read_state(backup)["counts"]["extra_data"] == 2


def test_active_transaction_refused(old_db):
    with closing(sqlite3.connect(old_db)) as con:
        con.execute("BEGIN IMMEDIATE")
        assert tool.main(["--execute"]) == 1
        con.rollback()
    assert tool.read_state(old_db)["counts"]["events"] == 1
