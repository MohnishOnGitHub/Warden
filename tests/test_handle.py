import json
import re

import pytest

from app.warden import coerce_args, handle, warden_mode


def h(conn, tool, args, requester="priya.s", ticket="T1001"):
    return handle(conn, ticket, requester, tool, args)


def action(conn, action_id):
    return conn.execute("SELECT * FROM actions WHERE action_id = ?", (action_id,)).fetchone()


def audit_types(conn):
    return [r["event_type"] for r in conn.execute("SELECT event_type FROM audit_log ORDER BY id")]


def test_allow_executes_and_records(conn):
    d = h(conn, "unlock_account", {"user_id": "priya.s"})
    assert d.status == "executed" and d.verdict == "ALLOW" and d.rule_id == "P020"
    assert conn.execute("SELECT locked FROM users WHERE user_id = 'priya.s'").fetchone()[0] == 0
    a = action(conn, d.action_id)
    assert (a["status"], a["policy_verdict"], a["final_verdict"], a["warden_mode"]) == ("EXECUTED", "ALLOW", "ALLOW", "on")
    assert a["policy_rule_ids"] == "P020" and a["latency_ms"] is not None
    assert audit_types(conn) == ["action_proposed", "policy_decision", "judge_decision", "action_executed"]


def test_block_does_not_execute_and_agent_sees_reason_not_rule_id(conn):
    args = {"user_id": "rahul.k", "group_name": "DomainAdmins", "justification": "x"}
    d = h(conn, "grant_group_membership", args, requester="rahul.k")
    assert (d.status, d.rule_id) == ("blocked", "P040")
    assert conn.execute("SELECT COUNT(*) FROM group_members WHERE user_id = 'rahul.k' AND group_name = 'DomainAdmins'"
                        ).fetchone()[0] == 0
    seen = d.for_agent()
    assert seen == {"status": "blocked", "reason": "Privileged groups cannot be granted by the service desk."}
    assert not re.search(r"P\d{3}", json.dumps(seen))
    assert action(conn, d.action_id)["status"] == "BLOCKED"
    assert audit_types(conn)[-2:] == ["action_blocked", "security_flag_set"]


def test_require_approval_queues_and_does_not_execute(conn):
    d = h(conn, "restart_service", {"host": "app01", "service_name": "payments_api"})
    assert d.status == "pending_approval" and d.approver_id == "sam.t"
    assert d.for_agent() == {"status": "pending_approval"}
    assert conn.execute("SELECT last_restart_at FROM services WHERE host = 'app01'").fetchone()[0] is None
    assert action(conn, d.action_id)["status"] == "PENDING_APPROVAL"
    assert conn.execute("SELECT status FROM tickets WHERE ticket_id = 'T1001'").fetchone()[0] == "PENDING_APPROVAL"
    assert audit_types(conn)[-1] == "approval_requested"


def test_redact_obligation_is_applied(conn):
    d = h(conn, "get_user_profile", {"user_id": "priya.s"}, requester="rahul.k")
    assert d.status == "executed" and d.result == {"name": "Priya S", "department": "Engineering"}


def test_invalid_args_blocked(conn):
    d = h(conn, "reset_password", {"user_id": "priya.s", "send_to": "evil@x.com"})
    assert d.status == "blocked" and d.rule_id == "P002"
    assert conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == 0


def test_temp_password_never_in_decision_actions_or_audit(conn):
    d = h(conn, "reset_password", {"user_id": "priya.s"})
    assert d.status == "executed"
    body = conn.execute("SELECT body FROM outbox").fetchone()[0]
    secret = body.split("password is ")[1].split(". ")[0]
    everything = json.dumps(d.for_agent())
    for table in ("actions", "audit_log"):
        everything += json.dumps([dict(r) for r in conn.execute(f"SELECT * FROM {table}")], default=str)
    assert secret not in everything


def test_fail_closed_when_database_breaks(conn):
    conn.close()
    d = h(conn, "unlock_account", {"user_id": "priya.s"})  # must not raise
    assert d.status == "blocked"


def test_unknown_tool_blocked_and_recorded(conn):
    d = h(conn, "format_disk", {})
    assert (d.status, d.rule_id) == ("blocked", "P001")
    assert action(conn, d.action_id)["tool"] == "format_disk"


def test_coerce_args():
    assert coerce_args({"a": 3.0, "b": 1.5, "c": True, "d": "x", "e": 2}) == {"a": 3, "b": 1.5, "c": True, "d": "x", "e": 2}
    assert coerce_args(None) is None


def test_mode_off_runs_without_policy(conn, monkeypatch):
    monkeypatch.setenv("WARDEN_MODE", "off")
    assert warden_mode() == "off"
    args = {"user_id": "rahul.k", "group_name": "DomainAdmins", "justification": "x"}
    d = h(conn, "grant_group_membership", args, requester="rahul.k")
    assert d.status == "executed"
    assert conn.execute("SELECT COUNT(*) FROM group_members WHERE user_id = 'rahul.k' AND group_name = 'DomainAdmins'"
                        ).fetchone()[0] == 1
    a = action(conn, d.action_id)
    assert (a["warden_mode"], a["status"], a["policy_verdict"]) == ("off", "EXECUTED", None)


@pytest.mark.parametrize("value", ["on", "", "banana", "OFF "])
def test_mode_defaults_to_on_unless_exactly_off(monkeypatch, value):
    monkeypatch.setenv("WARDEN_MODE", value)
    assert warden_mode() == ("off" if value.strip().lower() == "off" else "on")


def test_tool_failure_is_recorded_as_failed(conn, monkeypatch):
    monkeypatch.setenv("WARDEN_MODE", "off")  # policy would have blocked a missing user first
    d = h(conn, "reset_password", {"user_id": "nobody"})
    assert d.status == "blocked" and d.reason == "The action could not be completed."
    assert action(conn, d.action_id)["status"] == "FAILED"
    assert audit_types(conn)[-1] == "action_failed"
