"""Read side of the API: shapes database rows into what the dashboard shows.

Nothing here writes. The outbox table (it holds temporary passwords) is never read (invariant 6).
Fields that can echo ticket text (subject, body, judge reason) are plain strings: the dashboard
must display them as text, never as markup.
"""
import json

from app.warden.policy import SEVERITY

TERMINAL = ("RESOLVED", "ESCALATED")
EXECUTED_STATUSES = ("EXECUTED", "APPROVED_EXECUTED")

DESCRIPTIONS = {
    "get_user_profile": "Look up the profile of {user_id}",
    "reset_password": "Reset the password of {user_id}",
    "unlock_account": "Unlock the account of {user_id}",
    "install_software": "Install {package} on {device_id}",
    "grant_group_membership": "Add {user_id} to {group_name}",
    "restart_service": "Restart {service_name} on {host}",
    "resolve_ticket": "Close ticket {ticket_id} as resolved",
    "escalate_to_human": "Escalate ticket {ticket_id} to a human",
}


class _Missing(dict):
    def __missing__(self, key):
        return "?"


def describe_action(tool, args):
    """The action in plain words, e.g. 'Add arjun.m to FinanceReports'."""
    template = DESCRIPTIONS.get(tool)
    if template is None:
        return f"Call {tool}"
    return template.format_map(_Missing(args if isinstance(args, dict) else {}))


def _loads(text, default):
    try:
        return json.loads(text) if text else default
    except ValueError:
        return default


def _worst_verdict(verdicts):
    verdicts = [v for v in verdicts if v]
    return max(verdicts, key=lambda v: SEVERITY[v]) if verdicts else None


def _action_reason(a):
    """The one-line reason for the final verdict. Judge reasons are untrusted text."""
    by = a["decided_by"]
    if a["warden_mode"] == "off":
        return "Warden was off: no checks ran."
    if by == "policy":
        return a["policy_reason"]
    if by == "judge":
        return a["judge_reason"]
    return {
        "judge_unavailable": "The judge was unavailable, so a human has to approve.",
        "judge_invalid": "The judge returned invalid output, so the action was blocked.",
        "no_eligible_approver": "No eligible approver exists. A human will follow up.",
    }.get(by, a["policy_reason"])


# Tickets -----------------------------------------------------------------------

def list_tickets(conn, limit=200):
    rows = conn.execute(
        "SELECT ticket_id, requester_id, subject, status, security_flag, created_at, updated_at "
        "FROM tickets ORDER BY created_at DESC, ticket_id DESC LIMIT ?", (limit,)).fetchall()
    actions = {}
    for a in conn.execute("SELECT ticket_id, final_verdict, warden_mode FROM actions"):
        actions.setdefault(a["ticket_id"], []).append(a)
    pending = {r["ticket_id"]: r["approval_id"] for r in conn.execute(
        "SELECT ticket_id, approval_id FROM approvals WHERE status = 'PENDING'")}
    out = []
    for t in rows:
        acts = actions.get(t["ticket_id"], [])
        out.append({
            **dict(t),
            "security_flag": bool(t["security_flag"]),
            "verdict": _worst_verdict(a["final_verdict"] for a in acts),
            "action_count": len(acts),
            "warden_mode": acts[-1]["warden_mode"] if acts else None,
            "pending_approval_id": pending.get(t["ticket_id"]),
        })
    return out


def _stages(ticket, actions, events):
    """Ingested, Decided, Executed, Reported. state: done | waiting | skipped | pending."""
    event_types = {e["event_type"] for e in events}
    statuses = [a["status"] for a in actions]
    ingested = "done" if "ticket_ingested" in event_types else "pending"
    if any(a["final_verdict"] for a in actions):
        decided = "done"
    else:
        decided = "pending"
    if any(s in EXECUTED_STATUSES for s in statuses):
        executed = "done"
    elif "PENDING_APPROVAL" in statuses:
        executed = "waiting"
    elif actions and all(s in ("BLOCKED", "DENIED", "EXPIRED", "FAILED") for s in statuses):
        executed = "skipped"
    else:
        executed = "pending"
    if ticket["status"] in TERMINAL:
        reported = "done"
    elif ticket["status"] == "PENDING_APPROVAL":
        reported = "waiting"
    else:
        reported = "pending"
    detail = {
        "Ingested": f"{len(next((e['payload'].get('markers', []) for e in events if e['event_type'] == 'ticket_ingested'), []))}"
                    " scanner markers",
        "Decided": f"{len(actions)} action(s) checked",
        "Executed": {"done": "ran", "waiting": "waiting for approval", "skipped": "nothing ran", "pending": "-"}[executed],
        "Reported": ticket["status"].replace("_", " ").lower(),
    }
    return [{"name": n, "state": s, "detail": detail[n]} for n, s in
            (("Ingested", ingested), ("Decided", decided), ("Executed", executed), ("Reported", reported))]


def ticket_detail(conn, ticket_id):
    t = conn.execute("SELECT * FROM tickets WHERE ticket_id = ?", (ticket_id,)).fetchone()
    if t is None:
        return None
    requester = conn.execute("SELECT user_id, name, role, department FROM users WHERE user_id = ?",
                             (t["requester_id"],)).fetchone()
    actions = []
    for a in conn.execute("SELECT * FROM actions WHERE ticket_id = ? ORDER BY action_id", (ticket_id,)):
        args = _loads(a["args_json"], {})
        actions.append({
            "action_id": a["action_id"], "tool": a["tool"], "args": args,
            "description": describe_action(a["tool"], args),
            "status": a["status"], "warden_mode": a["warden_mode"], "decided_by": a["decided_by"],
            "policy_verdict": a["policy_verdict"], "policy_rule_ids": (a["policy_rule_ids"] or "").split(",") if a["policy_rule_ids"] else [],
            "policy_reason": a["policy_reason"],
            "judge_verdict": a["judge_verdict"], "judge_risk_score": a["judge_risk_score"],
            "judge_reason": a["judge_reason"], "judge_indicators": _loads(a["judge_indicators_json"], []),
            "judge_latency_ms": a["judge_latency_ms"],
            "final_verdict": a["final_verdict"], "reason": _action_reason(a),
            "latency_ms": a["latency_ms"], "created_at": a["created_at"],
        })
    events = [{"id": e["id"], "ts": e["ts"], "event_type": e["event_type"], "actor": e["actor"],
               "payload": _loads(e["payload_json"], {})}
              for e in conn.execute("SELECT * FROM audit_log WHERE ticket_id = ? ORDER BY id", (ticket_id,))]
    ticket = {**dict(t), "security_flag": bool(t["security_flag"]), "requester": dict(requester) if requester else None}
    return {
        "ticket": ticket,
        "actions": actions,
        "approvals": list_approvals(conn, ticket_id=ticket_id),
        "audit_events": events,
        "stages": _stages(ticket, actions, events),
    }


# Approvals ---------------------------------------------------------------------

def list_approvals(conn, status=None, ticket_id=None):
    where, params = [], []
    if status:
        where.append("ap.status = ?")
        params.append(status)
    if ticket_id:
        where.append("ap.ticket_id = ?")
        params.append(ticket_id)
    sql = (
        "SELECT ap.approval_id, ap.ticket_id, ap.status, ap.approver_id, ap.expires_at, ap.decided_at, ap.comment, "
        "ac.action_id, ac.tool, ac.args_json, ac.policy_reason, ac.policy_rule_ids, ac.judge_verdict, "
        "ac.judge_risk_score, ac.judge_reason, ac.judge_indicators_json, ac.decided_by, "
        "t.requester_id, ru.name AS requester_name, au.name AS approver_name "
        "FROM approvals ap JOIN actions ac ON ac.action_id = ap.action_id "
        "JOIN tickets t ON t.ticket_id = ap.ticket_id "
        "LEFT JOIN users ru ON ru.user_id = t.requester_id LEFT JOIN users au ON au.user_id = ap.approver_id "
        + (f"WHERE {' AND '.join(where)} " if where else "") + "ORDER BY ap.approval_id DESC")
    out = []
    for r in conn.execute(sql, params):
        args = _loads(r["args_json"], {})
        out.append({
            "approval_id": r["approval_id"], "ticket_id": r["ticket_id"], "status": r["status"],
            "approver_id": r["approver_id"], "approver_name": r["approver_name"],
            "requester_id": r["requester_id"], "requester_name": r["requester_name"],
            "expires_at": r["expires_at"], "decided_at": r["decided_at"], "comment": r["comment"],
            "action_id": r["action_id"], "tool": r["tool"], "args": args,
            "description": describe_action(r["tool"], args),
            "policy_reason": r["policy_reason"], "decided_by": r["decided_by"],
            "judge_verdict": r["judge_verdict"], "judge_risk_score": r["judge_risk_score"],
            "judge_reason": r["judge_reason"], "judge_indicators": _loads(r["judge_indicators_json"], []),
        })
    return out


# Directory ---------------------------------------------------------------------

def directory(conn):
    users = [dict(r, locked=bool(r["locked"])) for r in conn.execute(
        "SELECT user_id, name, email, department, role, manager_id, locked FROM users ORDER BY user_id")]
    members = {}
    for r in conn.execute("SELECT group_name, user_id FROM group_members ORDER BY user_id"):
        members.setdefault(r["group_name"], []).append(r["user_id"])
    groups = [{"group_name": g["group_name"], "owner_id": g["owner_id"], "privileged": bool(g["privileged"]),
               "members": members.get(g["group_name"], [])}
              for g in conn.execute("SELECT * FROM groups ORDER BY privileged DESC, group_name")]
    return {
        "users": users,
        "groups": groups,
        "devices": [dict(r) for r in conn.execute("SELECT device_id, owner_id FROM devices ORDER BY device_id")],
        "software_catalogue": [dict(r) for r in conn.execute(
            "SELECT package, status FROM software_catalogue ORDER BY status, package")],
        "installs": [dict(r) for r in conn.execute(
            "SELECT device_id, package, installed_at FROM installs ORDER BY id DESC")],
        "services": [dict(r, restartable=bool(r["restartable"])) for r in conn.execute(
            "SELECT host, service_name, environment, restartable, last_restart_at FROM services ORDER BY host")],
    }
