import json
import sqlite3
from contextlib import closing
from pathlib import Path

from backend.analysis.correlation import get_case_id
from backend.schemas.event import EventCreate
from backend.schemas.host import HostCreate


DB_PATH = Path(__file__).resolve().parent.parent / "data" / "attack_trace.db"

INSERT_EVENT_SQL = """
    INSERT INTO events (
        case_id, timestamp, host, source, event_id, event_type, user, process,
        src_ip, dst_ip, dst_port, protocol, logon_type, session_id, cmdline,
        detail, description, anomaly_flags, severity, raw_log
    ) VALUES (
        :case_id, :timestamp, :host, :source, :event_id, :event_type, :user, :process,
        :src_ip, :dst_ip, :dst_port, :protocol, :logon_type, :session_id, :cmdline,
        :detail, :description, :anomaly_flags, :severity, :raw_log
    )
"""
INSERT_HOST_SQL = """
    INSERT INTO hosts (hostname, ip, role) VALUES (:hostname, :ip, :role)
"""


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(get_connection()) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT,
                    timestamp TEXT NOT NULL,
                    host TEXT NOT NULL,
                    source TEXT NOT NULL,
                    event_id INTEGER,
                    event_type TEXT NOT NULL,
                    user TEXT,
                    process TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    protocol TEXT,
                    logon_type INTEGER,
                    session_id TEXT,
                    cmdline TEXT,
                    detail TEXT NOT NULL,
                    description TEXT NOT NULL,
                    anomaly_flags TEXT NOT NULL,
                    severity INTEGER NOT NULL,
                    raw_log TEXT NOT NULL
                );
            """)
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(events)")}
            if "case_id" not in columns:
                connection.execute("ALTER TABLE events ADD COLUMN case_id TEXT")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_events_case_id ON events(case_id)")
            connection.execute("""
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT NOT NULL UNIQUE,
                    ip TEXT NOT NULL UNIQUE,
                    role TEXT
                );
            """)


def _event_data(event: EventCreate):
    data = event.model_dump()
    data["timestamp"] = event.timestamp.isoformat()
    data["detail"] = json.dumps(event.detail, ensure_ascii=False)
    data["anomaly_flags"] = json.dumps(event.anomaly_flags, ensure_ascii=False)
    # 契约字段名是 source_event_id，DB 列名保留 event_id（内部实现细节）
    data["event_id"] = data.pop("source_event_id", None)
    return data


def _event_from_row(row):
    data = dict(row)
    data["detail"] = json.loads(data["detail"])
    data["anomaly_flags"] = json.loads(data["anomaly_flags"])
    # DB 列 event_id -> 契约字段 source_event_id（EventOut 输出用契约名）
    if "event_id" in data:
        data["source_event_id"] = data.pop("event_id")
    return data


def insert_event(event: EventCreate):
    with closing(get_connection()) as connection:
        with connection:
            cursor = connection.execute(INSERT_EVENT_SQL, _event_data(event))
            row = connection.execute(
                "SELECT * FROM events WHERE id = ?", (cursor.lastrowid,)
            ).fetchone()
        return _event_from_row(row)


def insert_events(events: list[EventCreate]):
    with closing(get_connection()) as connection:
        with connection:
            connection.executemany(
                INSERT_EVENT_SQL, [_event_data(event) for event in events]
            )
    return len(events)


def get_events(case_id: str | None = None):
    with closing(get_connection()) as connection:
        if case_id is None:
            rows = connection.execute("SELECT * FROM events ORDER BY id ASC").fetchall()
        else:
            # Preserve legacy NULL rows; compatibility metadata is read, not backfilled.
            rows = connection.execute(
                "SELECT * FROM events WHERE case_id = ? OR case_id IS NULL ORDER BY id ASC",
                (case_id,),
            ).fetchall()
        events = [_event_from_row(row) for row in rows]
        return events if case_id is None else [e for e in events if get_case_id(e) == case_id]


def get_event_by_id(event_db_id: int):
    with closing(get_connection()) as connection:
        row = connection.execute(
            "SELECT * FROM events WHERE id = ?", (event_db_id,)
        ).fetchone()
        return _event_from_row(row) if row is not None else None


def insert_host(host: HostCreate):
    with closing(get_connection()) as connection:
        with connection:
            cursor = connection.execute(INSERT_HOST_SQL, host.model_dump())
            row = connection.execute(
                "SELECT * FROM hosts WHERE id = ?", (cursor.lastrowid,)
            ).fetchone()
        return dict(row)


def insert_hosts(hosts: list[HostCreate]):
    with closing(get_connection()) as connection:
        with connection:
            connection.executemany(INSERT_HOST_SQL, [host.model_dump() for host in hosts])
    return len(hosts)


def get_hosts():
    with closing(get_connection()) as connection:
        rows = connection.execute("SELECT * FROM hosts ORDER BY id ASC").fetchall()
        return [dict(row) for row in rows]


def delete_case_events(case_id: str) -> int:
    """删除某批次的全部事件（批次管理用）。

    同时按 case_id 列与 detail 里的 batch_id 匹配删除，
    兼容列缺失时代由 detail.batch_id 打标的旧数据。
    """
    with closing(get_connection()) as connection:
        with connection:
            cursor = connection.execute(
                "DELETE FROM events WHERE case_id = ? "
                "OR detail LIKE ?",
                (case_id, f'%"batch_id":"{case_id}"%'),
            )
            return cursor.rowcount


def get_host_by_ip(ip: str):
    with closing(get_connection()) as connection:
        row = connection.execute("SELECT * FROM hosts WHERE ip = ?", (ip,)).fetchone()
        return dict(row) if row is not None else None


def get_host_map():
    return {host["ip"]: host["hostname"] for host in get_hosts()}
