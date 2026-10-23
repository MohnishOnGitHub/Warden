"""Recreate data/warden.db from scratch and load data/seed_directory.json.

Run from the repo root:  python scripts/reset_db.py
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db import DB_PATH, create_schema, get_connection
from app.seed import SEED_PATH, TABLES, load_seed


def delete_old_db():
    for suffix in ("", "-wal", "-shm"):
        f = Path(str(DB_PATH) + suffix)
        try:
            f.unlink(missing_ok=True)
        except PermissionError:
            sys.exit(f"Cannot delete {f}: another process (dashboard, API, DB viewer) has it open. Close it and retry.")


def main():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    delete_old_db()
    seed = json.loads(SEED_PATH.read_text(encoding="utf-8"))
    conn = get_connection()
    try:
        create_schema(conn)
        with conn:  # one transaction: all or nothing
            load_seed(conn, seed)
        print(f"Created {DB_PATH}")
        for table in ["users"] + TABLES:
            n = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            print(f"  {table}: {n}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
