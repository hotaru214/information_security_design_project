"""Local demo DB preparation; default is read-only preview.

Stop FastAPI and all SQLite clients before --execute. This tool cannot reliably
identify an idle server. Never run it concurrently with the application.
Restore manually: stop all clients, preserve the current DB, remove its stale
WAL/SHM files, and copy the verified backup to the printed DB path.
"""
import argparse
from contextlib import closing
from datetime import datetime
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend import database


def read_state(path):
    path = Path(path)
    state = {"path": str(path), "exists": path.exists(), "size": 0,
             "tables": [], "counts": {}, "journal_mode": None}
    if not path.exists():
        return state
    state["size"] = path.stat().st_size
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1)) as con:
        tables = [row[0] for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        state["tables"] = tables
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            state["counts"][table] = con.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0]
        state["journal_mode"] = con.execute("PRAGMA journal_mode").fetchone()[0]
        if con.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise RuntimeError(f"Database integrity check failed: {path}")
    return state


def create_backup(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation: even an unlikely filename collision must not overwrite.
    with destination.open("xb"):
        pass
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True, timeout=1)) as src:
        with closing(sqlite3.connect(destination)) as dst:
            src.backup(dst)
    state = read_state(destination)
    if state["size"] <= 0:
        raise RuntimeError("Backup is empty")
    return state


def initialize_at(path):
    # Standalone process only; reuse the production schema without copying SQL.
    original = database.DB_PATH
    try:
        database.DB_PATH = path
        database.init_db()
    finally:
        database.DB_PATH = original


def verify_new(path):
    state = read_state(path)
    if not {"events", "hosts"}.issubset(state["tables"]):
        raise RuntimeError("Initialized database is missing required tables")
    if state["counts"]["events"] != 0 or state["counts"]["hosts"] != 0:
        raise RuntimeError("Initialized database is not empty")
    return state


def prepare_demo_db(execute=False):
    path = Path(database.DB_PATH).absolute()
    # Refuse redirected targets; file operations stay beside the actual DB path.
    if path.is_symlink() or path.parent.resolve() != path.parent:
        raise RuntimeError("Refusing a symlink or redirected database path")
    backup_dir = path.parent / "backups"
    if backup_dir.exists() and backup_dir.resolve() != backup_dir:
        raise RuntimeError("Refusing a redirected backup directory")
    backup = backup_dir / (f"{path.stem}_demo-reset_"
                          f"{datetime.now():%Y%m%d_%H%M%S_%f}_{uuid4().hex[:8]}.db")
    sidecars = [Path(str(path) + suffix) for suffix in ("-wal", "-shm", "-journal")]
    before = read_state(path)
    print("Stop the FastAPI server before resetting the demo database.")
    print("Server shutdown cannot be reliably detected; stop all SQLite clients manually.")
    print(json.dumps(before, ensure_ascii=False, indent=2))
    print(f"Planned backup: {backup}")
    print("Sidecars: " + str([str(p) for p in sidecars if p.exists()]))
    if not execute:
        print("Preview only. No reset performed. Use --execute after stopping the server.")
        return {"before": before, "backup": None, "planned_backup": str(backup)}
    if any(p.is_symlink() for p in sidecars):
        raise RuntimeError("Refusing redirected sidecars")
    if not path.exists() and any(p.exists() for p in sidecars):
        raise RuntimeError("Orphan SQLite sidecars found; preserve them for manual recovery")
    if sidecars[2].exists():
        raise RuntimeError("Rollback journal found; recover/close SQLite before reset")
    saved = None
    if path.exists():
        # A brief lock probe catches active transactions, not idle servers.
        with closing(sqlite3.connect(path, timeout=0)) as con:
            con.execute("BEGIN EXCLUSIVE")
            con.rollback()
        saved_state = create_backup(path, backup)
        if saved_state["tables"] != before["tables"] or saved_state["counts"] != before["counts"]:
            raise RuntimeError(f"Backup differs from preview; stop concurrent writers. Backup: {backup}")
        saved = str(backup)
        print(f"Verified backup: {backup}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.stem + "_new_", suffix=".db", dir=path.parent)
    os.close(fd)
    temporary = Path(temporary)
    # Keep the temporary file and backup on failure for diagnosis/recovery.
    print(f"Initializing temporary database: {temporary}")
    initialize_at(temporary)
    expected = verify_new(temporary)
    # Backup succeeded and new DB is ready. All clients must remain stopped.
    for sidecar in sidecars[:2]:
        if sidecar.exists():
            sidecar.unlink()
            print(f"Removed stale sidecar: {sidecar}")
    os.replace(temporary, path)
    after = verify_new(path)
    if after["tables"] != expected["tables"] or after["counts"] != expected["counts"]:
        raise RuntimeError(f"Post-replacement verification failed. Backup: {saved}")
    print("Demo database ready.")
    print(f"Backup: {saved or 'No previous database existed'}")
    print(json.dumps(after, ensure_ascii=False, indent=2))
    return {"before": before, "after": after, "backup": saved}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="Back up and rebuild; requires all DB clients stopped")
    args = parser.parse_args(argv)
    try:
        prepare_demo_db(args.execute)
    except Exception as exc:
        print(f"ERROR: {exc}. Preparation failed; preserve any backup/temporary files.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
