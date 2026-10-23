import re
import sqlite3
from pathlib import Path

import pytest

from app import audit
from app.approvals import approve
from app.audit import log_event
from app.ingestion import create_ticket
from app.warden import handle
from tests.conftest import judge_reply


def insert_action(conn, **cols):
    base = {"ticket_id": "T1001", "tool": "unlock_account", "args_json": "{}"}
    base.update(cols)
    with conn:
        conn.execute(f"INSERT INTO actions ({', '.join(base)}) VALUES ({', '.join('?' for _ in base)})",
                     list(base.values()))


def test_empty_database_metrics(conn):
    conn.execute("DELETE FROM tickets")
    m = audit.dashboard_metrics(conn)
    assert m["auto_resolution_rate"] is None and m["attacks_blocked"] == 0 and m["security_flags"] == 0
    assert m["judge_latency"] == {"count": 0, "median_ms": None, "p95_ms": None}
    assert all(n == 0 for n in m["tickets_by_status"].values())
    assert all(n == 0 for n in m["verdicts"].values())


def test_judge_latency_median_and_p95(conn):
    for ms in (400, 100, 1000, 300, 200):
        insert_action(conn, judge_latency_ms=ms)
    insert_action(conn)  # no judge: ignored
    stats = audit.judge_latency_stats(conn)
    assert stats == {"count": 5, "median_ms": 300, "p95_ms": 1000}


def test_p95_nearest_rank_with_many_values(conn):
    for ms in range(1, 101):
        insert_action(conn, judge_latency_ms=ms)
    stats = audit.judge_latency_stats(conn)
    assert stats["median_ms"] == 50.5 and stats["p95_ms"] == 95


def test_metrics_from_a_realistic_mix(conn, fake_judge):
    # T1001 (priya): auto-resolved with an allowed unlock + resolve
    handle(conn, "T1001", "priya.s", "unlock_account", {"user_id": "priya.s"})
    handle(conn, "T1001", "priya.s", "resolve_ticket", {"ticket_id": "T1001", "message": "done"})
    # attack 1: stopped by policy
    t2 = create_ticket(conn, "rahul.k", "a", "b")
    handle(conn, t2, "rahul.k", "grant_group_membership",
           {"user_id": "rahul.k", "group_name": "DomainAdmins", "justification": "x"})
    # attack 2: policy allows, the judge blocks
    t3 = create_ticket(conn, "arjun.m", "a", "b")
    fake_judge.reply = judge_reply("BLOCK", 85, "exfil", ["secret_exfiltration"])
    handle(conn, t3, "arjun.m", "reset_password", {"user_id": "arjun.m"})
    # judge down: approval
    t4 = create_ticket(conn, "priya.s", "a", "b")
    from app import llm
    fake_judge.reply = llm.LLMError("503")
    handle(conn, t4, "priya.s", "unlock_account", {"user_id": "priya.s"})
    # policy approval, then approved
    fake_judge.reply = judge_reply()
    t5 = create_ticket(conn, "neha.i", "a", "b")
    handle(conn, t5, "neha.i", "reset_password", {"user_id": "rahul.k"})
    approve(conn, conn.execute("SELECT approval_id FROM approvals WHERE ticket_id = ?", (t5,)).fetchone()[0], "sam.t")

    m = audit.dashboard_metrics(conn)
    assert m["tickets_by_status"]["RESOLVED"] == 2          # T1001 (resolve_ticket) and t5 (approved)
    assert m["tickets_by_status"]["PENDING_APPROVAL"] == 1  # t4
    assert m["attacks_blocked"] == 2 and m["security_flags"] == 2
    assert m["verdicts"] == {"ALLOW": 2, "REQUIRE_APPROVAL": 2, "BLOCK": 2}
    assert m["auto_resolution_rate"] == pytest.approx(1 / 5)  # only T1001 resolved without an approval
    split = m["catch_split"]
    assert split["policy"] == {"BLOCK": 1, "REQUIRE_APPROVAL": 1}
    assert split["judge"] == {"BLOCK": 1, "REQUIRE_APPROVAL": 0}
    assert split["judge_unavailable"] == {"BLOCK": 0, "REQUIRE_APPROVAL": 1}
    assert split["judge_invalid"] == {"BLOCK": 0, "REQUIRE_APPROVAL": 0}
    assert m["judge_latency"]["count"] == 4  # unlock, 2 resets and the judge-down unlock; closing tools skip it


def test_warden_off_actions_are_not_counted_as_blocks(conn):
    insert_action(conn, status="BLOCKED", warden_mode="off", final_verdict="BLOCK")
    assert audit.attacks_blocked(conn) == 0 and audit.verdict_counts(conn)["BLOCK"] == 0
    assert audit.verdict_counts(conn, mode="off")["BLOCK"] == 1


# Invariant 7 ------------------------------------------------------------------

def test_audit_log_stays_append_only_at_the_database(conn):
    log_event(conn, "x", "test", "T1001", {"a": 1})
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("UPDATE audit_log SET actor = 'evil'")
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("DELETE FROM audit_log")


def test_no_code_updates_or_deletes_audit_log():
    pattern = re.compile(r"\b(UPDATE|DELETE\s+FROM|INSERT\s+OR\s+REPLACE\s+INTO|REPLACE\s+INTO)\s+audit_log\b", re.I)
    root = Path(__file__).resolve().parent.parent
    offenders = [str(p.relative_to(root)) for folder in ("app", "scripts")
                 for p in (root / folder).rglob("*.py") if pattern.search(p.read_text(encoding="utf-8"))]
    assert offenders == []


def test_secret_keys_are_dropped_from_audit_payloads(conn):
    log_event(conn, "x", "test", "T1001", {"temp_password": "hunter2", "ok": 1})
    payload = conn.execute("SELECT payload_json FROM audit_log").fetchone()[0]
    assert "hunter2" not in payload and '"ok": 1' in payload
