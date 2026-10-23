"""Ticket intake: trusted identity from the users table, untrusted text wrapped and scanned.

Ticket subject and body are data, never instructions (invariant 2). They only ever
appear inside the <untrusted_ticket> block built here.
"""
import re
from dataclasses import dataclass

# Scanner hints for the judge (milestone 5). Advisory only: they never decide anything on their own.
MARKER_PATTERNS = {
    "html_comment": r"<!--",
    "system_keyword": r"(?i)\b(system|assistant|developer)\s*:",
    "ignore_instructions": r"(?i)\b(ignore|disregard|override|forget)\b.{0,30}\b(instructions|rules|policy|prompt)\b",
    "role_override": r"(?i)\byou are now\b",
    # Lines addressed to the agent: "ACTION REQUIRED: ...", "support agent must ...".
    "imperative_directive": r"(?i)\b(action|attention|response) required\b|\b(agent|assistant|bot|ai)\s+(must|should|needs to|has to|is required to)\b",
    "tag_spoof": r"(?i)</?\s*untrusted_ticket",
    "zero_width_chars": r"[​-‏⁠﻿]",
    "base64_blob": r"[A-Za-z0-9+/]{40,}={0,2}",
    "privileged_group_mention": r"(?i)\b(DomainAdmins|GlobalAdmins|SecurityAdmins)\b",
}
_COMPILED = {name: re.compile(p) for name, p in MARKER_PATTERNS.items()}


def scan_markers(text):
    """Names of the injection markers found in RAW ticket text. Run this before wrap_untrusted."""
    return [name for name, pattern in _COMPILED.items() if pattern.search(text)]


def escape_text(text):
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def wrap_untrusted(subject, body):
    """Wrap ticket text in the <untrusted_ticket> block.

    < > & are escaped, so the text cannot close the block or open a fake one.
    """
    return f"<untrusted_ticket>\nSubject: {escape_text(subject)}\nBody: {escape_text(body)}\n</untrusted_ticket>"


@dataclass(frozen=True)
class Envelope:
    ticket_id: str
    requester: dict      # from the users table
    markers: list        # from scan_markers on the raw text
    untrusted: str       # the wrapped ticket text

    def prompt(self):
        """The user turn for the agent: trusted facts first, then the untrusted block."""
        r = self.requester
        return (
            "Trusted context from the company directory (not from the ticket):\n"
            f"ticket_id: {self.ticket_id}\n"
            f"requester: {r['user_id']} ({r['name']}), role {r['role']}, department {r['department']}, "
            f"manager {r['manager_id'] or 'none'}\n\n"
            f"{self.untrusted}"
        )


def build_envelope(conn, ticket_id):
    """Identity comes from the users table via tickets.requester_id, never from ticket text."""
    t = conn.execute(
        "SELECT requester_id, subject, body FROM tickets WHERE ticket_id = ?", (ticket_id,)
    ).fetchone()
    if t is None:
        raise ValueError(f"Unknown ticket: {ticket_id}")
    u = conn.execute(
        "SELECT user_id, name, department, role, manager_id FROM users WHERE user_id = ?",
        (t["requester_id"],),
    ).fetchone()
    if u is None:
        raise ValueError(f"Unknown requester: {t['requester_id']}")
    markers = scan_markers(f"{t['subject']}\n{t['body']}")  # raw text, before escaping
    return Envelope(ticket_id, dict(u), markers, wrap_untrusted(t["subject"], t["body"]))


def create_ticket(conn, requester_id, subject, body):
    """Insert a NEW ticket with the next T#### id (starting at T1001) and return the id."""
    if conn.execute("SELECT 1 FROM users WHERE user_id = ?", (requester_id,)).fetchone() is None:
        raise ValueError(f"Unknown requester: {requester_id}")
    with conn:
        last = conn.execute("SELECT MAX(CAST(SUBSTR(ticket_id, 2) AS INTEGER)) FROM tickets").fetchone()[0]
        ticket_id = f"T{(last or 1000) + 1}"
        conn.execute(
            "INSERT INTO tickets (ticket_id, requester_id, subject, body) VALUES (?, ?, ?, ?)",
            (ticket_id, requester_id, subject, body),
        )
    return ticket_id
