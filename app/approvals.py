"""Human approvals for REQUIRE_APPROVAL actions: create, approve, deny, expire.

The stored tool call (tool, args, obligations on the actions row) runs at most once, and
only after the named approver says yes. Nothing is re-evaluated at approval time.
"""
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.actions import set_action
from app.audit import log_event
from app.models import ActionStatus
from app.settings import SETTINGS
from app.tools import execute_tool

TS_FORMAT = "%Y-%m-%d %H:%M:%S"  # UTC, sorts as text

NO_APPROVER_NOTE = "No approver is available for this request. A human will follow up."
APPROVED_FAILED_NOTE = "The approved action could not be completed. A human will follow up."
EXPIRED_NOTE = "The approval request expired without a decision. A human will follow up."

# Resolution notes for approved actions. Only trusted values go in: approver name and validated tool args.
APPROVED_NOTES = {
    "reset_password": "Approved by {approver}. A temporary password has been sent to the email address on file "
                      "for {user_id}.",
    "unlock_account": "Approved by {approver}. The account {user_id} has been unlocked.",
    "install_software": "Approved by {approver}. {package} has been installed on {device_id}.",
    "grant_group_membership": "Approved by {approver}. {user_id} has been added to {group_name}.",
    "restart_service": "Approved by {approver}. {service_name} on {host} has been restarted.",
}
DEFAULT_APPROVED_NOTE = "Approved by {approver}. The requested action was completed."


@dataclass(frozen=True)
class Created:
    approval_id: int
    approver_id: str


@dataclass(frozen=True)
class ApprovalResult:
    ok: bool
    status: str   # executed, denied, expired, failed, or a rejection: not_found, not_pending, self_approval, not_the_approver
    message: str
    result: dict | None = None


class _SafeDict(dict):
    def __missing__(self, key):
        return "?"


def _now(now):
    return now or datetime.now(timezone.utc)


def _ts(dt):
    return dt.strftime(TS_FORMAT)


def approval_ttl():
    minutes = SETTINGS.approval_ttl_minutes_demo if os.environ.get("DEMO_MODE") == "1" else SETTINGS.approval_ttl_minutes
    return timedelta(minutes=minutes)


def _user_name(conn, user_id):
    row = conn.execute("SELECT name FROM users WHERE user_id = ?", (user_id,)).fetchone()
    return row["name"] if row else user_id


def _pick_approver(conn, requester_id, wanted):
    """The wanted approver, unless that is the requester; then the fallback. None if nobody is eligible."""
    for candidate in (wanted, SETTINGS.fallback_approver):
        if not candidate or candidate == requester_id:
            continue
        if conn.execute("SELECT 1 FROM users WHERE user_id = ?", (candidate,)).fetchone():
            return candidate
    return None


def _set_ticket(conn, ticket_id, status, note):
    with conn:
        conn.execute(
            "UPDATE tickets SET status = ?, resolution_note = ?, updated_at = datetime('now') WHERE ticket_id = ?",
            (status, note, ticket_id))


def _move_action(conn, action_id, new_status):
    """Only an action still waiting for approval can move on: this is what keeps decisions single use."""
    with conn:
        conn.execute("UPDATE actions SET status = ? WHERE action_id = ? AND status = ?",
                     (new_status.value, action_id, ActionStatus.PENDING_APPROVAL.value))


def create_approval(conn, action_id, ticket_id, requester_id, wanted_approver, now=None):
    """Queue an approval and write the holding note. Returns Created, or None if nobody can approve.

    The requester never approves their own action: if they would be the approver, the fallback
    approver is used. With no eligible approver the action is recorded DENIED and the ticket is
    escalated (an org gap, not an attack, so no security flag).
    """
    approver_id = _pick_approver(conn, requester_id, wanted_approver)
    if approver_id is None:
        set_action(conn, action_id, status=ActionStatus.DENIED.value, decided_by="no_eligible_approver")
        _set_ticket(conn, ticket_id, "ESCALATED", NO_APPROVER_NOTE)
        log_event(conn, "approval_unavailable", "warden", ticket_id,
                  {"action_id": action_id, "requested_approver": wanted_approver, "requester_id": requester_id})
        return None

    expires_at = _ts(_now(now) + approval_ttl())
    with conn:
        approval_id = conn.execute(
            "INSERT INTO approvals (action_id, ticket_id, approver_id, expires_at) VALUES (?, ?, ?, ?)",
            (action_id, ticket_id, approver_id, expires_at)).lastrowid
    _set_ticket(conn, ticket_id, "PENDING_APPROVAL",
                f"Your request needs approval from {_user_name(conn, approver_id)}; we'll update you.")
    log_event(conn, "approval_created", "warden", ticket_id, {
        "approval_id": approval_id, "action_id": action_id, "approver_id": approver_id,
        "requested_approver": wanted_approver, "expires_at": expires_at})
    return Created(approval_id, approver_id)


def _load(conn, approval_id):
    return conn.execute(
        "SELECT ap.approval_id, ap.action_id, ap.ticket_id, ap.status, ap.approver_id, ap.expires_at, "
        "ac.tool, ac.args_json, ac.obligations_json, t.requester_id "
        "FROM approvals ap JOIN actions ac ON ac.action_id = ap.action_id "
        "JOIN tickets t ON t.ticket_id = ap.ticket_id WHERE ap.approval_id = ?", (approval_id,)).fetchone()


def _reject(conn, row, actor, code, message):
    log_event(conn, "approval_rejected", actor, row["ticket_id"],
              {"approval_id": row["approval_id"], "reason": code})
    return ApprovalResult(False, code, message)


def _expire_row(conn, row):
    """Expire one still-pending approval. Returns True if this call did it."""
    with conn:
        changed = conn.execute(
            "UPDATE approvals SET status = 'EXPIRED', decided_at = datetime('now') "
            "WHERE approval_id = ? AND status = 'PENDING'", (row["approval_id"],)).rowcount
    if not changed:
        return False
    _move_action(conn, row["action_id"], ActionStatus.EXPIRED)
    _set_ticket(conn, row["ticket_id"], "ESCALATED", EXPIRED_NOTE)
    log_event(conn, "approval_expired", "warden", row["ticket_id"],
              {"approval_id": row["approval_id"], "action_id": row["action_id"]})
    return True


def _precheck(conn, row, approver_id, now):
    """Common checks for approve and deny. Returns an ApprovalResult if the attempt must be refused."""
    if row["status"] != "PENDING":
        return _reject(conn, row, approver_id, "not_pending", f"This approval is already {row['status'].lower()}.")
    if approver_id == row["requester_id"]:
        return _reject(conn, row, approver_id, "self_approval", "You cannot decide on your own request.")
    if approver_id != row["approver_id"]:
        return _reject(conn, row, approver_id, "not_the_approver",
                       f"Only {row['approver_id']} can decide on this approval.")
    if row["expires_at"] <= _ts(now):
        _expire_row(conn, row)
        return ApprovalResult(False, "expired", "This approval has expired.")
    return None


def approve(conn, approval_id, approver_id, comment=None, now=None):
    """Run the stored tool call, once, if approver_id is the named approver (and not the requester)."""
    now = _now(now)
    row = _load(conn, approval_id)
    if row is None:
        return ApprovalResult(False, "not_found", f"No approval {approval_id}.")
    refused = _precheck(conn, row, approver_id, now)
    if refused:
        return refused

    # The conditional UPDATE is the gate: whoever changes PENDING to APPROVED first runs the tool.
    with conn:
        changed = conn.execute(
            "UPDATE approvals SET status = 'APPROVED', decided_at = ?, comment = ? "
            "WHERE approval_id = ? AND status = 'PENDING' AND approver_id = ? AND expires_at > ? "
            "AND approver_id != (SELECT requester_id FROM tickets WHERE ticket_id = approvals.ticket_id)",
            (_ts(now), comment, approval_id, approver_id, _ts(now))).rowcount
    if changed != 1:
        return _reject(conn, row, approver_id, "not_pending", "This approval was already decided.")
    log_event(conn, "approval_approved", approver_id, row["ticket_id"],
              {"approval_id": approval_id, "action_id": row["action_id"], "comment": comment})

    try:
        args = json.loads(row["args_json"])
        obligations = json.loads(row["obligations_json"] or "{}")
        result = execute_tool(conn, row["tool"], args, **obligations)
    except Exception as e:
        _move_action(conn, row["action_id"], ActionStatus.FAILED)
        _set_ticket(conn, row["ticket_id"], "ESCALATED", APPROVED_FAILED_NOTE)
        log_event(conn, "action_failed", "warden", row["ticket_id"], {
            "action_id": row["action_id"], "tool": row["tool"], "error": type(e).__name__, "approved": True})
        return ApprovalResult(False, "failed", "The approved action failed and the ticket was escalated.")

    _move_action(conn, row["action_id"], ActionStatus.APPROVED_EXECUTED)
    note = APPROVED_NOTES.get(row["tool"], DEFAULT_APPROVED_NOTE).format_map(
        _SafeDict(args, approver=_user_name(conn, approver_id)))
    _set_ticket(conn, row["ticket_id"], "RESOLVED", note)
    log_event(conn, "action_executed", "warden", row["ticket_id"], {
        "action_id": row["action_id"], "tool": row["tool"], "result": result, "approved_by": approver_id})
    return ApprovalResult(True, "executed", note, result)


def deny(conn, approval_id, approver_id, comment=None, now=None):
    """The named approver says no: nothing runs and the ticket is escalated."""
    now = _now(now)
    row = _load(conn, approval_id)
    if row is None:
        return ApprovalResult(False, "not_found", f"No approval {approval_id}.")
    refused = _precheck(conn, row, approver_id, now)
    if refused:
        return refused

    with conn:
        changed = conn.execute(
            "UPDATE approvals SET status = 'DENIED', decided_at = ?, comment = ? "
            "WHERE approval_id = ? AND status = 'PENDING' AND approver_id = ?",
            (_ts(now), comment, approval_id, approver_id)).rowcount
    if changed != 1:
        return _reject(conn, row, approver_id, "not_pending", "This approval was already decided.")
    _move_action(conn, row["action_id"], ActionStatus.DENIED)
    note = f"Your request was denied by {_user_name(conn, approver_id)}. A human will follow up."
    _set_ticket(conn, row["ticket_id"], "ESCALATED", note)
    log_event(conn, "approval_denied", approver_id, row["ticket_id"],
              {"approval_id": approval_id, "action_id": row["action_id"], "comment": comment})
    return ApprovalResult(True, "denied", note)


def expire_overdue(conn, now=None):
    """Expire every pending approval past its expires_at. Returns the list of expired approval ids."""
    cutoff = _ts(_now(now))
    rows = conn.execute(
        "SELECT ap.approval_id, ap.action_id, ap.ticket_id FROM approvals ap "
        "WHERE ap.status = 'PENDING' AND ap.expires_at <= ?", (cutoff,)).fetchall()
    return [r["approval_id"] for r in rows if _expire_row(conn, r)]
