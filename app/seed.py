"""Load the simulated directory from data/seed_directory.json, and reset a live database in place."""
import json

from app.db import CORE_SCHEMA, EVAL_TABLES, ROOT, ensure_eval_tables

SEED_PATH = ROOT / "data" / "seed_directory.json"

# Insert order matters: foreign keys need parents first.
# users.manager_id points at other users, so users are inserted with manager_id
# set afterwards (see load_seed).
TABLES = ["groups", "group_members", "devices", "software_catalogue", "services"]


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


def reset_in_place(conn):
    """Drop the demo tables (audit_log included) and reload the seed, on an open connection.

    The eval tables are results, not demo state, so they are kept. Only the DEMO_MODE=1 reset
    endpoint and the evaluation runner call this. It exists because a running API cannot delete the
    database file on Windows. DROP TABLE is the one way the append-only audit_log is ever wiped.
    """
    seed = json.loads(SEED_PATH.read_text(encoding="utf-8"))
    conn.commit()
    conn.execute("PRAGMA foreign_keys = OFF")  # cannot be changed inside a transaction
    try:
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")]
        with conn:
            for name in tables:
                if name not in EVAL_TABLES:
                    conn.execute(f'DROP TABLE "{name}"')
            conn.executescript(CORE_SCHEMA)
            ensure_eval_tables(conn)
            load_seed(conn, seed)
    finally:
        conn.execute("PRAGMA foreign_keys = ON")
