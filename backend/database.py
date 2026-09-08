import json
import sqlite3
from contextlib import closing
from pathlib import Path

from backend.schemas.event import EventCreate
from backend.schemas.host import HostCreate


DB_PATH = Path(__file__).resolve().parent.parent / "data" / "attack_trace.db"

INSERT_EVENT_SQL = """
    INSERT INTO events (
        timestamp, host, source, event_id, event_type, user, process,
        src_ip, dst_ip, dst_port, protocol, logon_type, session_id, cmdline,
        detail, description, anomaly_flags, severity, raw_log
    ) VALUES (
        :timestamp, :host, :source, :event_id, :event_type, :user, :process,
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
            connection.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    return data


def _event_from_row(row):
    data = dict(row)
    data["detail"] = json.loads(data["detail"])
    data["anomaly_flags"] = json.loads(data["anomaly_flags"])
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


def get_events():
    with closing(get_connection()) as connection:
        rows = connection.execute("SELECT * FROM events ORDER BY id ASC").fetchall()
        return [_event_from_row(row) for row in rows]


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


def get_host_by_ip(ip: str):
    with closing(get_connection()) as connection:
        row = connection.execute("SELECT * FROM hosts WHERE ip = ?", (ip,)).fetchone()
        return dict(row) if row is not None else None


def get_host_map():
    return {host["ip"]: host["hostname"] for host in get_hosts()}
