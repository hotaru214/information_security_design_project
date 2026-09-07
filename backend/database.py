import sqlite3
from contextlib import closing
from pathlib import Path

from backend.schemas.event import EventCreate


DB_PATH = Path(__file__).resolve().parent.parent / "data" / "attack_trace.db"

INSERT_EVENT_SQL = """
    INSERT INTO events (
        timestamp, host, event_type, src_ip, dst_ip, dst_port, protocol, description
    ) VALUES (
        :timestamp, :host, :event_type, :src_ip, :dst_ip, :dst_port, :protocol, :description
    )
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
                    event_type TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    dst_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    description TEXT NOT NULL
                );
            """)


def _event_data(event: EventCreate):
    data = event.model_dump()
    data["timestamp"] = event.timestamp.isoformat()
    return data


def insert_event(event: EventCreate):
    with closing(get_connection()) as connection:
        with connection:
            cursor = connection.execute(INSERT_EVENT_SQL, _event_data(event))
            row = connection.execute(
                "SELECT * FROM events WHERE id = ?", (cursor.lastrowid,)
            ).fetchone()
        return dict(row)


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
        return [dict(row) for row in rows]
