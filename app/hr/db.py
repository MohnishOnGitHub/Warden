"""Simulated HR onboarding tables and their seed data. Same SQLite database as everything else; nothing real."""
import json

from app.db import ROOT, create_schema

SEED_PATH = ROOT / "data" / "seed_hr.json"

HR_SCHEMA = """
CREATE TABLE hr_candidates (
    candidate_id       TEXT PRIMARY KEY,
    name               TEXT NOT NULL,
    department         TEXT NOT NULL,
    hiring_manager_id  TEXT NOT NULL REFERENCES users(user_id),
    start_date         TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'pre_boarding' CHECK (status IN ('pre_boarding','active'))
);

CREATE TABLE hr_assets (
    asset_id     TEXT PRIMARY KEY,
    asset_class  TEXT NOT NULL CHECK (asset_class IN ('standard','high_spec')),
    status       TEXT NOT NULL DEFAULT 'available' CHECK (status IN ('available','assigned'))
);

CREATE TABLE hr_apps (
    app          TEXT PRIMARY KEY,
    sensitivity  TEXT NOT NULL CHECK (sensitivity IN ('standard','sensitive','restricted'))
);

CREATE TABLE hr_accounts (
    candidate_id  TEXT PRIMARY KEY REFERENCES hr_candidates(candidate_id),
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL UNIQUE,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE hr_asset_assignments (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id  TEXT NOT NULL REFERENCES hr_candidates(candidate_id),
    asset_id      TEXT NOT NULL REFERENCES hr_assets(asset_id),
    assigned_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE hr_app_access (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id  TEXT NOT NULL REFERENCES hr_candidates(candidate_id),
    app           TEXT NOT NULL REFERENCES hr_apps(app),
    granted_at    TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (candidate_id, app)
);

CREATE TABLE hr_orientations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id  TEXT NOT NULL REFERENCES hr_candidates(candidate_id),
    session_date  TEXT NOT NULL,
    scheduled_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

HR_TABLES = ("hr_candidates", "hr_assets", "hr_apps", "hr_accounts", "hr_asset_assignments", "hr_app_access",
             "hr_orientations")


def create_hr_schema(conn):
    conn.executescript(HR_SCHEMA)


def load_hr_seed(conn, seed=None):
    seed = seed or json.loads(SEED_PATH.read_text(encoding="utf-8"))
    with conn:
        for c in seed["candidates"]:
            conn.execute(
                "INSERT INTO hr_candidates (candidate_id, name, department, hiring_manager_id, start_date, status) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (c["candidate_id"], c["name"], c["department"], c["hiring_manager_id"], c["start_date"], c["status"]))
        for a in seed["assets"]:
            conn.execute("INSERT INTO hr_assets (asset_id, asset_class, status) VALUES (?, ?, ?)",
                         (a["asset_id"], a["asset_class"], a["status"]))
        for a in seed["apps"]:
            conn.execute("INSERT INTO hr_apps (app, sensitivity) VALUES (?, ?)", (a["app"], a["sensitivity"]))


def reset_hr_demo(conn):
    """Drop everything in this database and rebuild the core tables, the IT directory (the requesters live in
    `users`) and the HR tables. For a throwaway demo database only."""
    from app.seed import SEED_PATH as IT_SEED_PATH, load_seed

    conn.commit()
    conn.execute("PRAGMA foreign_keys = OFF")
    try:
        for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                                    ).fetchall():
            conn.execute(f'DROP TABLE "{name}"')
        conn.commit()
    finally:
        conn.execute("PRAGMA foreign_keys = ON")
    create_schema(conn)
    create_hr_schema(conn)
    with conn:
        load_seed(conn, json.loads(IT_SEED_PATH.read_text(encoding="utf-8")))
    load_hr_seed(conn)
