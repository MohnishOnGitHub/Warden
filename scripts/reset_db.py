"""Recreate data/warden.db from scratch and load data/seed_directory.json.

Run from the repo root:  python scripts/reset_db.py
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db import DB_PATH, ROOT, create_schema, get_connection

SEED_PATH = ROOT / "data" / "seed_directory.json"

# Insert order matters: foreign keys need parents first.
# users.manager_id points at other users, so users are inserted with manager_id
# set afterwards (see load_seed).
TABLES = ["groups", "group_members", "devices", "software_catalogue", "services"]


def delete_old_db():
    for suffix in ("", "-wal", "-shm"):
        f = Path(str(DB_PATH) + suffix)
        try:
            f.unlink(missing_ok=True)
        except PermissionError:
            sys.exit(f"Cannot delete {f}: another process (dashboard, API, DB viewer) has it open. Close it and retry.")


def insert_rows(conn, table, rows):
    for row in rows:
        cols = ", ".join(row)
        marks = ", ".join("?" for _ in row)
        conn.execute(f"INSERT INTO {table} ({cols}) VALUES ({marks})", list(row.values()))


def load_seed(conn, seed):
    users = seed["users"]
    # Pass 1: users without manager (a manager may appear later in the list).
    # Pass 2: set manager_id.
    for u in users:
        conn.execute(
            "INSERT INTO users (user_id, name, email, department, role, manager_id, locked) "
            "VALUES (?, ?, ?, ?, ?, NULL, ?)",
            (u["user_id"], u["name"], f"{u['user_id']}@corp.example.com",
             u["department"], u["role"], u["locked"]),
        )
    for u in users:
        if u["manager_id"]:
            conn.execute("UPDATE users SET manager_id = ? WHERE user_id = ?", (u["manager_id"], u["user_id"]))
    for table in TABLES:
        insert_rows(conn, table, seed[table])


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
