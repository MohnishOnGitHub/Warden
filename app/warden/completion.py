"""Completion check: before resolve_ticket runs, is the work it reports actually done?

Rule based, no LLM, and it never reads ticket text (invariant 2). It compares two things:
  * the ticket's executed actions against the real state of the simulated directory, and
  * the closing message (written by the agent) against those actions: a message that claims a change
    ("I've unlocked your account") needs a matching executed action.
A ticket with no executed write action may still be resolved, as long as the message claims no change
(an information answer). check_completion() returns a list of fixed-text problems; empty means fine.
The problems never contain ticket text, message text or secrets: they end up in the resolution note.
"""
import json
import re

from app.models import ActionStatus
from app.warden.policy import CLOSING_TOOLS

DONE_STATUSES = (ActionStatus.EXECUTED, ActionStatus.APPROVED_EXECUTED)

# Tools of a domain that has no state rules here (the HR domain registers its tools): a ticket that executed one of
# them is not checked, since the IT claim words and state rules do not describe its work.
SKIPPED_TOOLS = set()

# Words in a closing message that claim a change, and the tool that would back the claim.
CLAIMS = {
    "unlock_account": ("unlock", re.compile(r"\bunlock(?:ed|s|ing)?\b", re.I)),
    "install_software": ("install", re.compile(r"\binstall(?:ed|s|ing|ation)?\b", re.I)),
    "reset_password": ("password reset", re.compile(r"\breset(?:s|ting)?\b", re.I)),
    "grant_group_membership": ("group change", re.compile(r"\b(?:grant(?:ed|s|ing)?|add(?:ed|s|ing)?)\b", re.I)),
    "restart_service": ("restart", re.compile(r"\b(?:restart(?:ed|s|ing)?|reboot(?:ed|s|ing)?)\b", re.I)),
}


def _row(conn, sql, *params):
    return conn.execute(sql, params).fetchone()


def _unlocked(conn, a):
    r = _row(conn, "SELECT locked FROM users WHERE user_id = ?", a.get("user_id"))
    return r is not None and r["locked"] == 0


def _installed(conn, a):
    return _row(conn, "SELECT 1 FROM installs WHERE device_id = ? AND package = ?",
                a.get("device_id"), a.get("package")) is not None


def _granted(conn, a):
    return _row(conn, "SELECT 1 FROM group_members WHERE group_name = ? AND user_id = ?",
                a.get("group_name"), a.get("user_id")) is not None


def _restarted(conn, a):
    r = _row(conn, "SELECT last_restart_at FROM services WHERE host = ? AND service_name = ?",
             a.get("host"), a.get("service_name"))
    return r is not None and r["last_restart_at"] is not None


def _password_mailed(conn, a):
    # Existence only: the outbox body holds the temporary password and is never read.
    return _row(conn, "SELECT 1 FROM outbox WHERE subject = 'Your temporary password' AND to_email = "
                      "(SELECT email FROM users WHERE user_id = ?)", a.get("user_id")) is not None


# tool -> (state test, problem text if the state does not hold)
STATE_RULES = {
    "unlock_account": (_unlocked, "the account is still locked"),
    "install_software": (_installed, "the package is not installed on the device"),
    "grant_group_membership": (_granted, "the group membership is missing"),
    "restart_service": (_restarted, "no restart is recorded for the service"),
    "reset_password": (_password_mailed, "no password email was sent"),
}


def executed_work(conn, ticket_id):
    """The ticket's executed write actions that have a state rule: [(tool, args)]."""
    rows = conn.execute(
        f"SELECT tool, args_json FROM actions WHERE ticket_id = ? AND status IN ({','.join('?' for _ in DONE_STATUSES)}) "
        "ORDER BY action_id", (ticket_id, *DONE_STATUSES)).fetchall()
    return [(r["tool"], json.loads(r["args_json"] or "{}")) for r in rows
            if r["tool"] in STATE_RULES and r["tool"] not in CLOSING_TOOLS]


# A verb after these is an instruction to the requester or an inability, not a claim:
# "Please restart Slack", "you can reset it at the portal", "unable to unlock".
NOT_A_CLAIM = re.compile(
    r"(?:please|kindly|you\s+(?:can|could|should|may|might|need\s+to|must|have\s+to|will\s+need\s+to)|try\s+to|"
    r"remember\s+to|make\s+sure\s+to|be\s+sure\s+to|to)\s+(?:\w+\s+)?$", re.I)


def _claims(pattern, text):
    return any(not NOT_A_CLAIM.search(text[max(0, m.start() - 40):m.start()]) for m in pattern.finditer(text))


def claimed_tools(message):
    """Tools whose change the message claims to have made."""
    text = message if isinstance(message, str) else ""
    return [tool for tool, (_, pattern) in CLAIMS.items() if _claims(pattern, text)]


def check_completion(conn, ticket_id, message):
    """Return the list of problems that stop this ticket from being resolved (empty = fine)."""
    if SKIPPED_TOOLS and conn.execute(
            f"SELECT 1 FROM actions WHERE ticket_id = ? AND tool IN ({','.join('?' for _ in SKIPPED_TOOLS)}) "
            f"AND status IN ({','.join('?' for _ in DONE_STATUSES)}) LIMIT 1",
            (ticket_id, *SKIPPED_TOOLS, *DONE_STATUSES)).fetchone():
        return []
    problems = []
    work = executed_work(conn, ticket_id)

    for tool, args in work:
        holds, problem = STATE_RULES[tool]
        if not holds(conn, args) and problem not in problems:
            problems.append(problem)

    done = {tool for tool, _ in work}
    for tool in claimed_tools(message):
        if tool not in done:
            label = CLAIMS[tool][0]
            problems.append(f"the closing message claims a {label} that was not carried out")
    return problems


def downgrade_note(problems):
    return "Escalated for human review: the request could not be confirmed as done (" + "; ".join(problems) + ")."
