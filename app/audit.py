"""Append only audit writer. The only SQL here is INSERT (invariant 7).

Milestone 6 adds the metric queries to this module.
"""
import json

from app.tools import redact


def log_event(conn, event_type, actor, ticket_id, payload):
    """Append one audit row. Keys containing password, token or secret are dropped first."""
    with conn:
        conn.execute(
            "INSERT INTO audit_log (event_type, actor, ticket_id, payload_json) VALUES (?, ?, ?, ?)",
            (event_type, actor, ticket_id, json.dumps(redact(payload), default=str)),
        )
