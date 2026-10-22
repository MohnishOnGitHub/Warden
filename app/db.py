"""SQLite connection helper and schema for the simulated directory and Warden records."""
import os
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("WARDEN_DB", ROOT / "data" / "warden.db"))

SCHEMA = """
-- Simulated environment ------------------------------------------------------

CREATE TABLE users (
    user_id     TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    email       TEXT NOT NULL UNIQUE,
    department  TEXT NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('employee','manager','executive','it_staff','it_admin')),
    manager_id  TEXT REFERENCES users(user_id),
    locked      INTEGER NOT NULL DEFAULT 0 CHECK (locked IN (0,1))
);

CREATE TABLE groups (
    group_name  TEXT PRIMARY KEY,
    owner_id    TEXT NOT NULL REFERENCES users(user_id),
    privileged  INTEGER NOT NULL DEFAULT 0 CHECK (privileged IN (0,1))
);

CREATE TABLE group_members (
    group_name  TEXT NOT NULL REFERENCES groups(group_name),
    user_id     TEXT NOT NULL REFERENCES users(user_id),
    PRIMARY KEY (group_name, user_id)
);

CREATE TABLE devices (
    device_id   TEXT PRIMARY KEY,
    owner_id    TEXT NOT NULL REFERENCES users(user_id)
);

CREATE TABLE software_catalogue (
    package     TEXT PRIMARY KEY,
    status      TEXT NOT NULL CHECK (status IN ('approved','needs_approval','denied'))
);

CREATE TABLE installs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id    TEXT NOT NULL REFERENCES devices(device_id),
    package      TEXT NOT NULL,
    installed_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE services (
    host          TEXT NOT NULL,
    service_name  TEXT NOT NULL,
    environment   TEXT NOT NULL CHECK (environment IN ('prod','nonprod')),
    restartable   INTEGER NOT NULL CHECK (restartable IN (0,1)),
    PRIMARY KEY (host, service_name)
);

-- Simulated email. Holds secrets (temporary passwords): never displayed, never logged.
CREATE TABLE outbox (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    to_email    TEXT NOT NULL,
    subject     TEXT NOT NULL,
    body        TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Records --------------------------------------------------------------------

CREATE TABLE tickets (
    ticket_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    requester_id     TEXT NOT NULL REFERENCES users(user_id),
    subject          TEXT NOT NULL,
    body             TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'NEW'
                     CHECK (status IN ('NEW','IN_PROGRESS','PENDING_APPROVAL','RESOLVED','ESCALATED')),
    security_flag    INTEGER NOT NULL DEFAULT 0 CHECK (security_flag IN (0,1)),
    resolution_note  TEXT,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE actions (
    action_id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id               INTEGER NOT NULL REFERENCES tickets(ticket_id),
    tool                    TEXT NOT NULL,
    args_json               TEXT NOT NULL,
    policy_verdict          TEXT CHECK (policy_verdict IN ('ALLOW','REQUIRE_APPROVAL','BLOCK')),
    policy_rule_ids         TEXT,
    policy_reason           TEXT,
    judge_verdict           TEXT CHECK (judge_verdict IN ('ALLOW','REQUIRE_APPROVAL','BLOCK')),
    judge_risk_score        INTEGER CHECK (judge_risk_score BETWEEN 0 AND 100),
    judge_reason            TEXT,
    judge_indicators_json   TEXT,
    final_verdict           TEXT CHECK (final_verdict IN ('ALLOW','REQUIRE_APPROVAL','BLOCK')),
    status                  TEXT NOT NULL DEFAULT 'PROPOSED',
    latency_ms              INTEGER,
    warden_mode             TEXT NOT NULL DEFAULT 'on' CHECK (warden_mode IN ('on','off')),
    created_at              TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE approvals (
    approval_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id    INTEGER NOT NULL REFERENCES actions(action_id),
    ticket_id    INTEGER NOT NULL REFERENCES tickets(ticket_id),
    status       TEXT NOT NULL DEFAULT 'PENDING'
                 CHECK (status IN ('PENDING','APPROVED','DENIED','EXPIRED')),
    approver_id  TEXT REFERENCES users(user_id),
    expires_at   TEXT NOT NULL,
    decided_at   TEXT,
    comment      TEXT
);

CREATE TABLE audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL DEFAULT (datetime('now')),
    event_type    TEXT NOT NULL,
    actor         TEXT NOT NULL,
    ticket_id     INTEGER,
    payload_json  TEXT NOT NULL
);

-- Invariant 7: audit_log is append only.
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append only');
END;

CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append only');
END;

-- Eval -----------------------------------------------------------------------

CREATE TABLE eval_cases (
    case_id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    label                   TEXT NOT NULL CHECK (label IN ('benign','attack')),
    category                TEXT NOT NULL,
    requester_id            TEXT NOT NULL REFERENCES users(user_id),
    subject                 TEXT NOT NULL,
    body                    TEXT NOT NULL,
    expected_status         TEXT NOT NULL,
    forbidden_actions_json  TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE eval_results (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id             INTEGER NOT NULL REFERENCES eval_cases(case_id),
    warden_mode         TEXT NOT NULL CHECK (warden_mode IN ('on','off')),
    final_status        TEXT NOT NULL,
    forbidden_executed  INTEGER NOT NULL CHECK (forbidden_executed IN (0,1)),
    run_at              TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def get_connection(path=None):
    conn = sqlite3.connect(str(path or DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def create_schema(conn):
    conn.executescript(SCHEMA)
