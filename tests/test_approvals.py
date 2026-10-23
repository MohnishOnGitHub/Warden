import json
import threading
from datetime import datetime, timedelta, timezone

import pytest

from app import approvals
from app.agent import run_ticket
from app.approvals import approve, create_approval, deny, expire_overdue
from app.db import get_connection
from app.ingestion import create_ticket
from app.warden import handle
from tests.test_agent import ScriptedLLM

FINANCE = {"user_id": "arjun.m", "group_name": "FinanceReports", "justification": "Need the monthly reports."}


def request_finance_access(conn):
    """arjun.m asks for FinanceReports: policy REQUIRE_APPROVAL by anita.d. Returns (ticket_id, decision)."""
    tid = create_ticket(conn, "arjun.m", "Finance access", "Please add me to FinanceReports.")
    return tid, handle(conn, tid, "arjun.m", "grant_group_membership", FINANCE)


def is_member(conn, user="arjun.m", group="FinanceReports"):
    return conn.execute("SELECT COUNT(*) FROM group_members WHERE user_id = ? AND group_name = ?",
                        (user, group)).fetchone()[0] == 1


def row(conn, table, key, value):
    return conn.execute(f"SELECT * FROM {table} WHERE {key} = ?", (value,)).fetchone()


def approval_for(conn, ticket):
    return row(conn, "approvals", "ticket_id", ticket)


def event_types(conn):
    return [r[0] for r in conn.execute("SELECT event_type FROM audit_log ORDER BY id")]


def parse(ts):
    return datetime.strptime(ts, approvals.TS_FORMAT).replace(tzinfo=timezone.utc)


# Creation ----------------------------------------------------------------------

def test_require_approval_creates_row_and_holding_note(conn):
    tid, d = request_finance_access(conn)
    assert d.status == "pending_approval" and d.approver_id == "anita.d"
    a = approval_for(conn, tid)
    assert (a["status"], a["approver_id"]) == ("PENDING", "anita.d")
    assert a["action_id"] == d.action_id
    ticket = row(conn, "tickets", "ticket_id", tid)
    assert ticket["status"] == "PENDING_APPROVAL"
    assert ticket["resolution_note"] == "Your request needs approval from Anita D; we'll update you."
    assert not is_member(conn)  # nothing ran
    act = row(conn, "actions", "action_id", d.action_id)
    assert act["status"] == "PENDING_APPROVAL" and json.loads(act["obligations_json"]) == {}
    assert "approval_created" in event_types(conn) and event_types(conn)[-1] == "approval_requested"


def test_ttl_is_ten_minutes_by_default_and_two_in_demo_mode(conn, monkeypatch):
    monkeypatch.delenv("DEMO_MODE", raising=False)
    tid, _ = request_finance_access(conn)
    created = datetime.now(timezone.utc)
    assert timedelta(minutes=9, seconds=50) < parse(approval_for(conn, tid)["expires_at"]) - created < timedelta(minutes=10, seconds=5)

    monkeypatch.setenv("DEMO_MODE", "1")
    tid2, _ = request_finance_access(conn)
    delta = parse(approval_for(conn, tid2)["expires_at"]) - datetime.now(timezone.utc)
    assert timedelta(minutes=1, seconds=50) < delta < timedelta(minutes=2, seconds=5)


def test_requester_would_be_approver_uses_fallback(conn):
    tid = create_ticket(conn, "anita.d", "Add Arjun", "Please add arjun.m to FinanceReports.")
    d = handle(conn, tid, "anita.d", "grant_group_membership", FINANCE)  # P043 names the owner: anita.d herself
    assert d.status == "pending_approval" and d.approver_id == "sam.t"
    created = json.loads(row(conn, "audit_log", "event_type", "approval_created")["payload_json"])
    assert created["requested_approver"] == "anita.d" and created["approver_id"] == "sam.t"


def test_no_eligible_approver_denies_and_escalates_without_security_flag(conn):
    tid = create_ticket(conn, "sam.t", "Restart payments", "Please restart payments_api.")
    d = handle(conn, tid, "sam.t", "restart_service", {"host": "app01", "service_name": "payments_api"})
    assert d.status == "blocked" and d.decided_by == "no_eligible_approver"
    assert "passed to a human" in d.for_agent()["reason"]
    act = row(conn, "actions", "action_id", d.action_id)
    assert (act["status"], act["decided_by"]) == ("DENIED", "no_eligible_approver")
    ticket = row(conn, "tickets", "ticket_id", tid)
    assert ticket["status"] == "ESCALATED" and ticket["security_flag"] == 0
    assert ticket["resolution_note"] == approvals.NO_APPROVER_NOTE
    assert approval_for(conn, tid) is None
    assert "approval_unavailable" in event_types(conn) and "security_flag_set" not in event_types(conn)
    assert conn.execute("SELECT last_restart_at FROM services WHERE host = 'app01'").fetchone()[0] is None


def test_agent_loop_stops_on_no_eligible_approver(conn):
    tid = create_ticket(conn, "sam.t", "Restart payments", "Please restart payments_api.")
    fake = ScriptedLLM([[("restart_service", {"host": "app01", "service_name": "payments_api"})], "unused"])
    result = run_ticket(conn, tid, llm_fn=fake)
    assert len(fake.seen) == 1 and result.final_status == "ESCALATED"


# Approve ------------------------------------------------------------------------

def test_approve_runs_stored_call_once_and_resolves(conn):
    tid, d = request_finance_access(conn)
    a = approval_for(conn, tid)
    r = approve(conn, a["approval_id"], "anita.d", "looks fine")
    assert r.ok and r.status == "executed"
    assert is_member(conn)
    assert row(conn, "approvals", "approval_id", a["approval_id"])["status"] == "APPROVED"
    assert row(conn, "actions", "action_id", d.action_id)["status"] == "APPROVED_EXECUTED"
    ticket = row(conn, "tickets", "ticket_id", tid)
    assert ticket["status"] == "RESOLVED"
    assert ticket["resolution_note"] == "Approved by Anita D. arjun.m has been added to FinanceReports."
    assert {"approval_approved", "action_executed"} <= set(event_types(conn))


def test_double_approve_executes_only_once(conn):
    tid = create_ticket(conn, "neha.i", "Reset Rahul", "Rahul is locked out.")
    d = handle(conn, tid, "neha.i", "reset_password", {"user_id": "rahul.k"})  # IT on another user: sam.t approves
    assert d.status == "pending_approval" and d.approver_id == "sam.t"
    approval_id = approval_for(conn, tid)["approval_id"]
    first = approve(conn, approval_id, "sam.t")
    second = approve(conn, approval_id, "sam.t")
    assert first.ok and not second.ok and second.status == "not_pending"
    assert conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == 1  # one email, not two
    assert "email address on file" in row(conn, "tickets", "ticket_id", tid)["resolution_note"]


def test_concurrent_approvals_execute_exactly_once(conn):
    tid = create_ticket(conn, "neha.i", "Reset Rahul", "Rahul is locked out.")
    handle(conn, tid, "neha.i", "reset_password", {"user_id": "rahul.k"})
    approval_id = approval_for(conn, tid)["approval_id"]
    db_path = conn.execute("PRAGMA database_list").fetchone()["file"]
    results, barrier = [], threading.Barrier(6)

    def worker():
        c = get_connection(db_path)
        try:
            barrier.wait()
            results.append(approve(c, approval_id, "sam.t").ok)
        finally:
            c.close()

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1
    assert conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == 1


def test_wrong_approver_is_rejected(conn):
    tid, d = request_finance_access(conn)
    approval_id = approval_for(conn, tid)["approval_id"]
    for who in ("sam.t", "vikram.r", "rahul.k", "nobody"):
        r = approve(conn, approval_id, who)
        assert not r.ok and r.status == "not_the_approver"
    assert approval_for(conn, tid)["status"] == "PENDING" and not is_member(conn)
    rejected = [json.loads(r[0]) for r in conn.execute(
        "SELECT payload_json FROM audit_log WHERE event_type = 'approval_rejected'")]
    assert len(rejected) == 4 and all(p["reason"] == "not_the_approver" for p in rejected)
    assert conn.execute("SELECT actor FROM audit_log WHERE event_type = 'approval_rejected' ORDER BY id").fetchone()[0] == "sam.t"


def test_requester_can_never_approve_their_own_request(conn):
    tid, d = request_finance_access(conn)
    approval_id = approval_for(conn, tid)["approval_id"]
    r = approve(conn, approval_id, "arjun.m")
    assert not r.ok and r.status == "self_approval" and not is_member(conn)
    assert deny(conn, approval_id, "arjun.m").status == "self_approval"

    # Even a hand-edited row naming the requester as approver cannot be approved by them.
    with conn:
        conn.execute("UPDATE approvals SET approver_id = 'arjun.m' WHERE approval_id = ?", (approval_id,))
    r = approve(conn, approval_id, "arjun.m")
    assert not r.ok and r.status == "self_approval" and not is_member(conn)
    assert approval_for(conn, tid)["status"] == "PENDING"


def test_database_gate_refuses_requester_even_if_python_checks_are_bypassed(conn):
    tid, d = request_finance_access(conn)
    approval_id = approval_for(conn, tid)["approval_id"]
    with conn:
        conn.execute("UPDATE approvals SET approver_id = 'arjun.m' WHERE approval_id = ?", (approval_id,))
    changed = conn.execute(
        "UPDATE approvals SET status = 'APPROVED' WHERE approval_id = ? AND status = 'PENDING' AND approver_id = ? "
        "AND approver_id != (SELECT requester_id FROM tickets WHERE ticket_id = approvals.ticket_id)",
        (approval_id, "arjun.m")).rowcount
    assert changed == 0


def test_approve_unknown_id(conn):
    r = approve(conn, 999, "sam.t")
    assert not r.ok and r.status == "not_found"


def test_stored_call_and_obligations_are_what_runs(conn, monkeypatch):
    tid, d = request_finance_access(conn)
    with conn:
        conn.execute("UPDATE actions SET obligations_json = ? WHERE action_id = ?", ('{"redact": true}', d.action_id))
    seen = []
    monkeypatch.setattr(approvals, "execute_tool", lambda c, tool, args, **ob: seen.append((tool, args, ob)) or {"ok": 1})
    approve(conn, approval_for(conn, tid)["approval_id"], "anita.d")
    assert seen == [("grant_group_membership", FINANCE, {"redact": True})]


def test_tool_failure_on_approve_marks_failed_and_escalates(conn):
    tid = create_ticket(conn, "priya.s", "Restart", "Restart payments_api please.")
    d = handle(conn, tid, "priya.s", "restart_service", {"host": "app01", "service_name": "payments_api"})
    with conn:
        conn.execute("UPDATE services SET restartable = 0 WHERE host = 'app01'")  # the world changed meanwhile
    r = approve(conn, approval_for(conn, tid)["approval_id"], "sam.t")
    assert not r.ok and r.status == "failed"
    assert row(conn, "actions", "action_id", d.action_id)["status"] == "FAILED"
    ticket = row(conn, "tickets", "ticket_id", tid)
    assert ticket["status"] == "ESCALATED" and ticket["resolution_note"] == approvals.APPROVED_FAILED_NOTE
    assert "action_failed" in event_types(conn)


# Deny ---------------------------------------------------------------------------

def test_deny_escalates_and_nothing_runs(conn):
    tid, d = request_finance_access(conn)
    approval_id = approval_for(conn, tid)["approval_id"]
    r = deny(conn, approval_id, "anita.d", "not needed")
    assert r.ok and r.status == "denied"
    assert approval_for(conn, tid)["status"] == "DENIED" and approval_for(conn, tid)["comment"] == "not needed"
    assert row(conn, "actions", "action_id", d.action_id)["status"] == "DENIED"
    ticket = row(conn, "tickets", "ticket_id", tid)
    assert ticket["status"] == "ESCALATED" and ticket["security_flag"] == 0
    assert ticket["resolution_note"] == "Your request was denied by Anita D. A human will follow up."
    assert not is_member(conn) and "approval_denied" in event_types(conn)
    # a denied approval cannot be approved afterwards
    assert approve(conn, approval_id, "anita.d").status == "not_pending" and not is_member(conn)


def test_wrong_person_cannot_deny(conn):
    tid, _ = request_finance_access(conn)
    r = deny(conn, approval_for(conn, tid)["approval_id"], "sam.t")
    assert not r.ok and r.status == "not_the_approver" and approval_for(conn, tid)["status"] == "PENDING"


# Expiry -------------------------------------------------------------------------

def test_expire_overdue_escalates_and_nothing_runs(conn):
    tid, d = request_finance_access(conn)
    approval_id = approval_for(conn, tid)["approval_id"]
    assert expire_overdue(conn) == []  # not due yet
    later = datetime.now(timezone.utc) + timedelta(minutes=11)
    assert expire_overdue(conn, now=later) == [approval_id]
    assert approval_for(conn, tid)["status"] == "EXPIRED"
    assert row(conn, "actions", "action_id", d.action_id)["status"] == "EXPIRED"
    ticket = row(conn, "tickets", "ticket_id", tid)
    assert (ticket["status"], ticket["security_flag"], ticket["resolution_note"]) == ("ESCALATED", 0, approvals.EXPIRED_NOTE)
    assert expire_overdue(conn, now=later) == []  # only once
    assert not is_member(conn) and "approval_expired" in event_types(conn)


def test_approving_an_overdue_approval_expires_it_instead(conn):
    tid, d = request_finance_access(conn)
    approval_id = approval_for(conn, tid)["approval_id"]
    with conn:
        conn.execute("UPDATE approvals SET expires_at = '2000-01-01 00:00:00' WHERE approval_id = ?", (approval_id,))
    r = approve(conn, approval_id, "anita.d")
    assert not r.ok and r.status == "expired" and not is_member(conn)
    assert approval_for(conn, tid)["status"] == "EXPIRED"
    assert row(conn, "tickets", "ticket_id", tid)["status"] == "ESCALATED"


def test_approve_just_before_expiry_still_works(conn):
    tid, _ = request_finance_access(conn)
    soon = datetime.now(timezone.utc) + timedelta(minutes=9)
    assert approve(conn, approval_for(conn, tid)["approval_id"], "anita.d", now=soon).ok


# End to end through the agent ----------------------------------------------------

def test_agent_ends_on_pending_then_approval_resolves_ticket(conn):
    tid = create_ticket(conn, "arjun.m", "Finance access", "Please add me to FinanceReports.")
    fake = ScriptedLLM([[("grant_group_membership", FINANCE)], "unused"])
    result = run_ticket(conn, tid, llm_fn=fake)
    assert result.final_status == "PENDING_APPROVAL" and len(fake.seen) == 1
    assert result.steps[0]["approver_id"] == "anita.d"
    assert approve(conn, approval_for(conn, tid)["approval_id"], "anita.d").ok
    assert row(conn, "tickets", "ticket_id", tid)["status"] == "RESOLVED" and is_member(conn)


def test_create_approval_directly_validates_approver_exists(conn):
    tid = create_ticket(conn, "arjun.m", "x", "y")
    d = handle(conn, tid, "arjun.m", "unlock_account", {"user_id": "arjun.m"})
    # a ghost approver is not eligible, so the fallback is used
    created = create_approval(conn, d.action_id, tid, "arjun.m", "ghost.user")
    assert created is not None and created.approver_id == "sam.t"
