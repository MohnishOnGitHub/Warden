"""Warden: the guardian layer between the agent and the tools.

handle() is the only path from a proposed tool call to a tool function (invariant 1).
Milestone 4 runs policy only. The judge and combiner join in milestone 5.
"""
import json
import os
import time
from dataclasses import replace

from app.audit import log_event
from app.models import ActionStatus, Decision
from app.tools import execute_tool, redact
from app.warden.policy import ALLOW, BLOCK, REQUIRE_APPROVAL, evaluate_policy

BLOCKED_REASON = "This action is not permitted."
FAILED_REASON = "The action could not be completed."

# Columns _set_action may write. Fixed list, so no SQL text ever comes from outside.
ACTION_COLUMNS = {
    "policy_verdict", "policy_rule_ids", "policy_reason", "final_verdict", "status", "latency_ms",
}


def warden_mode():
    """'off' only when WARDEN_MODE is exactly 'off' (the baseline). Anything else is 'on'."""
    return "off" if os.environ.get("WARDEN_MODE", "on").strip().lower() == "off" else "on"


def coerce_args(raw_args):
    """Gemini returns whole numbers as floats (3.0). Turn those into ints before validation."""
    if not isinstance(raw_args, dict):
        return raw_args
    return {
        k: int(v) if isinstance(v, float) and v.is_integer() else v
        for k, v in raw_args.items()
    }


def _set_action(conn, action_id, **cols):
    assert set(cols) <= ACTION_COLUMNS
    sets = ", ".join(f"{c} = ?" for c in cols)
    with conn:
        conn.execute(f"UPDATE actions SET {sets} WHERE action_id = ?", (*cols.values(), action_id))


def _elapsed_ms(started):
    return int((time.perf_counter() - started) * 1000)


def _run_tool(conn, ticket_id, action_id, tool_name, args, obligations, started):
    """Run the tool and record the outcome. Only called after an ALLOW verdict (or mode off)."""
    try:
        result = execute_tool(conn, tool_name, args, **obligations)
    except Exception as e:
        _set_action(conn, action_id, status=ActionStatus.FAILED.value, latency_ms=_elapsed_ms(started))
        log_event(conn, "action_failed", "warden", ticket_id,
                  {"action_id": action_id, "tool": tool_name, "error": type(e).__name__})
        return Decision("blocked", tool_name, action_id, reason=FAILED_REASON)
    _set_action(conn, action_id, status=ActionStatus.EXECUTED.value, latency_ms=_elapsed_ms(started))
    log_event(conn, "action_executed", "warden", ticket_id,
              {"action_id": action_id, "tool": tool_name, "result": result})
    return Decision("executed", tool_name, action_id, result=result, verdict=ALLOW)


def _handle(conn, ticket_id, requester_id, tool_name, raw_args, started):
    mode = warden_mode()
    args = coerce_args(raw_args)

    with conn:
        action_id = conn.execute(
            "INSERT INTO actions (ticket_id, tool, args_json, warden_mode) VALUES (?, ?, ?, ?)",
            (ticket_id, tool_name, json.dumps(redact(args), default=str), mode),
        ).lastrowid
    log_event(conn, "action_proposed", "agent", ticket_id,
              {"action_id": action_id, "tool": tool_name, "args": args, "warden_mode": mode})

    if mode == "off":
        # Baseline for the Warden on/off comparison: no policy, everything runs.
        _set_action(conn, action_id, final_verdict=ALLOW)
        return _run_tool(conn, ticket_id, action_id, tool_name, args, {}, started)

    policy = evaluate_policy(tool_name, args, requester_id, ticket_id, conn)
    _set_action(
        conn, action_id,
        policy_verdict=policy.verdict, policy_rule_ids=",".join(policy.rule_ids),
        policy_reason=policy.reason, final_verdict=policy.verdict,
    )
    log_event(conn, "policy_decision", "warden", ticket_id, {
        "action_id": action_id, "verdict": policy.verdict, "rule_id": policy.rule_id,
        "rule_ids": list(policy.rule_ids), "reason": policy.reason, "approver_id": policy.approver_id,
    })

    internal = dict(action_id=action_id, verdict=policy.verdict, rule_id=policy.rule_id,
                    approver_id=policy.approver_id)

    if policy.verdict == BLOCK:
        _set_action(conn, action_id, status=ActionStatus.BLOCKED.value, latency_ms=_elapsed_ms(started))
        log_event(conn, "action_blocked", "warden", ticket_id,
                  {"action_id": action_id, "tool": tool_name, "rule_id": policy.rule_id})
        return Decision("blocked", tool_name, reason=policy.reason, **internal)

    if policy.verdict == REQUIRE_APPROVAL:
        _set_action(conn, action_id, status=ActionStatus.PENDING_APPROVAL.value, latency_ms=_elapsed_ms(started))
        with conn:
            conn.execute(
                "UPDATE tickets SET status = 'PENDING_APPROVAL', updated_at = datetime('now') WHERE ticket_id = ?",
                (ticket_id,))
        # The approvals row (with expiry) is created in milestone 6 from this event and the actions row.
        log_event(conn, "approval_requested", "warden", ticket_id,
                  {"action_id": action_id, "tool": tool_name, "approver_id": policy.approver_id})
        return Decision("pending_approval", tool_name, **internal)

    if policy.verdict == ALLOW:
        decision = _run_tool(conn, ticket_id, action_id, tool_name, args, policy.obligations, started)
        return replace(decision, rule_id=policy.rule_id, verdict=policy.verdict)

    raise ValueError(f"Unknown verdict: {policy.verdict}")  # caught by handle(): fail closed


def handle(conn, ticket_id, requester_id, tool_name, raw_args):
    """Decide and act on one proposed tool call. Never raises: any error means blocked (invariant 4)."""
    started = time.perf_counter()
    try:
        return _handle(conn, ticket_id, requester_id, tool_name, raw_args, started)
    except Exception as e:
        try:
            log_event(conn, "warden_error", "warden", ticket_id, {"tool": tool_name, "error": type(e).__name__})
        except Exception:
            pass
        return Decision("blocked", tool_name, reason=BLOCKED_REASON, verdict=BLOCK, rule_id="P999")
