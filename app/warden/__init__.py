"""Warden: the guardian layer between the agent and the tools.

handle() is the only path from a proposed tool call to a tool function (invariant 1).
Flow: validate, policy, judge (write tools that policy did not block), combine, then
execute, queue for approval, or block.
"""
import json
import os
import time
from dataclasses import replace

from app import llm
from app.actions import set_action as _set_action
from app.approvals import create_approval
from app.audit import log_event
from app.models import ActionStatus, Decision
from app.tools import execute_tool, redact
from app.warden.combiner import combine
from app.warden.judge import JudgeInvalid, JudgeUnavailable, judge_action
from app.warden.policy import ALLOW, BLOCK, REQUIRE_APPROVAL, evaluate_policy

BLOCKED_REASON = "This action is not permitted."
FAILED_REASON = "The action could not be completed."
# Judge reasons can echo ticket text, so the agent only ever gets this generic line.
JUDGE_BLOCKED_REASON = "This action was flagged as risky and was not run."
NO_APPROVER_REASON = "No approver is available for this request. It has been passed to a human."

def warden_mode():
    """'off' (baseline) or 'rules_only' (policy without the judge) when WARDEN_MODE says so. Anything else is 'on'."""
    value = os.environ.get("WARDEN_MODE", "on").strip().lower()
    return value if value in ("off", "rules_only") else "on"


def coerce_args(raw_args):
    """Gemini returns whole numbers as floats (3.0). Turn those into ints before validation."""
    if not isinstance(raw_args, dict):
        return raw_args
    return {
        k: int(v) if isinstance(v, float) and v.is_integer() else v
        for k, v in raw_args.items()
    }


def _flag_ticket(conn, ticket_id):
    """Warden owns the security flag: any blocked action raises it, whatever the agent says later."""
    with conn:
        changed = conn.execute(
            "UPDATE tickets SET security_flag = 1, updated_at = datetime('now') "
            "WHERE ticket_id = ? AND security_flag = 0", (ticket_id,)).rowcount
    if changed:
        log_event(conn, "security_flag_set", "warden", ticket_id, {"reason": "action blocked"})


class _Clock:
    """Elapsed time since it was created, minus any free-tier spacing delay (llm.waited_seconds).

    The evaluation spaces real Gemini calls out to respect rate limits. That wait is not Warden's
    latency, so it must not show up in the latencies recorded on the actions row.
    """

    def __init__(self):
        self.t0 = time.perf_counter()
        self.waited0 = llm.waited_seconds()

    def ms(self):
        waited = llm.waited_seconds() - self.waited0
        return max(0, int((time.perf_counter() - self.t0 - waited) * 1000))


def _elapsed_ms(clock):
    return clock.ms()


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


def _run_judge(conn, ticket_id, action_id, tool_name, args, policy):
    """Ask the judge and record what happened. Returns (JudgeOutput or None, judge_state)."""
    judge_started = _Clock()
    try:
        out = judge_action(conn, ticket_id, tool_name, args, policy)
    except JudgeUnavailable as e:
        _set_action(conn, action_id, judge_reason="Judge unavailable", judge_latency_ms=_elapsed_ms(judge_started))
        log_event(conn, "judge_unavailable", "judge", ticket_id, {"action_id": action_id, "error": str(e)})
        return None, "unavailable"
    except JudgeInvalid as e:
        _set_action(conn, action_id, judge_reason=f"Judge output invalid ({e.kind})",
                    judge_latency_ms=_elapsed_ms(judge_started))
        log_event(conn, "judge_invalid", "judge", ticket_id, {"action_id": action_id, "kind": e.kind})
        return None, "invalid"
    _set_action(
        conn, action_id,
        judge_verdict=out.verdict, judge_risk_score=out.risk_score, judge_reason=out.reason,
        judge_indicators_json=json.dumps(out.indicators), judge_latency_ms=_elapsed_ms(judge_started),
    )
    log_event(conn, "judge_decision", "judge", ticket_id, {
        "action_id": action_id, "verdict": out.verdict, "risk_score": out.risk_score,
        "indicators": out.indicators, "reason": out.reason,
    })
    return out, "ok"


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
        # Baseline for the Warden on/off comparison: no policy, no judge, everything runs.
        _set_action(conn, action_id, final_verdict=ALLOW)
        return _run_tool(conn, ticket_id, action_id, tool_name, args, {}, started)

    policy = evaluate_policy(tool_name, args, requester_id, ticket_id, conn)
    _set_action(
        conn, action_id,
        policy_verdict=policy.verdict, policy_rule_ids=",".join(policy.rule_ids), policy_reason=policy.reason,
        obligations_json=json.dumps(policy.obligations),
    )
    log_event(conn, "policy_decision", "warden", ticket_id, {
        "action_id": action_id, "verdict": policy.verdict, "rule_id": policy.rule_id,
        "rule_ids": list(policy.rule_ids), "reason": policy.reason, "approver_id": policy.approver_id,
    })

    judge_out, judge_state = None, "skipped"
    if policy.needs_judge and mode == "rules_only":
        # Experiment mode: the final verdict is the policy verdict. Everything else (approvals, blocks, flags) is unchanged.
        _set_action(conn, action_id, judge_reason="Skipped (rules_only)")
    elif policy.needs_judge:
        judge_out, judge_state = _run_judge(conn, ticket_id, action_id, tool_name, args, policy)
    final = combine(policy, judge_out, judge_state)
    _set_action(conn, action_id, final_verdict=final.verdict, decided_by=final.decided_by)

    judge_info = None if judge_out is None else {
        "verdict": judge_out.verdict, "risk_score": judge_out.risk_score,
        "reason": judge_out.reason, "indicators": list(judge_out.indicators),
    }
    internal = dict(action_id=action_id, verdict=final.verdict, rule_id=policy.rule_id,
                    approver_id=final.approver_id, decided_by=final.decided_by, judge=judge_info)

    if final.verdict == BLOCK:
        _set_action(conn, action_id, status=ActionStatus.BLOCKED.value, latency_ms=_elapsed_ms(started))
        log_event(conn, "action_blocked", "warden", ticket_id, {
            "action_id": action_id, "tool": tool_name, "rule_id": policy.rule_id, "decided_by": final.decided_by})
        _flag_ticket(conn, ticket_id)
        reason = {"policy": policy.reason, "judge": JUDGE_BLOCKED_REASON}.get(final.decided_by, BLOCKED_REASON)
        return Decision("blocked", tool_name, reason=reason, **internal)

    if final.verdict == REQUIRE_APPROVAL:
        created = create_approval(conn, action_id, ticket_id, requester_id, final.approver_id)
        if created is None:
            # Nobody eligible to approve: recorded as DENIED and escalated by create_approval. An org gap, not an attack.
            _set_action(conn, action_id, latency_ms=_elapsed_ms(started))
            return Decision("blocked", tool_name, reason=NO_APPROVER_REASON,
                            **{**internal, "decided_by": "no_eligible_approver", "approver_id": None})
        _set_action(conn, action_id, status=ActionStatus.PENDING_APPROVAL.value, latency_ms=_elapsed_ms(started))
        log_event(conn, "approval_requested", "warden", ticket_id, {
            "action_id": action_id, "tool": tool_name, "approval_id": created.approval_id,
            "approver_id": created.approver_id, "decided_by": final.decided_by})
        return Decision("pending_approval", tool_name, **{**internal, "approver_id": created.approver_id})

    if final.verdict == ALLOW:
        decision = _run_tool(conn, ticket_id, action_id, tool_name, args, policy.obligations, started)
        return replace(decision, rule_id=policy.rule_id, verdict=final.verdict,
                       decided_by=final.decided_by, judge=judge_info)

    raise ValueError(f"Unknown verdict: {final.verdict}")  # caught by handle(): fail closed


def handle(conn, ticket_id, requester_id, tool_name, raw_args):
    """Decide and act on one proposed tool call. Never raises: any error means blocked (invariant 4)."""
    started = _Clock()
    try:
        return _handle(conn, ticket_id, requester_id, tool_name, raw_args, started)
    except Exception as e:
        try:
            log_event(conn, "warden_error", "warden", ticket_id, {"tool": tool_name, "error": type(e).__name__})
            _flag_ticket(conn, ticket_id)
        except Exception:
            pass
        return Decision("blocked", tool_name, reason=BLOCKED_REASON, verdict=BLOCK, rule_id="P999")
