"""Append only audit writer, plus read-only metric queries for the dashboard.

The only write to audit_log is the INSERT in log_event (invariant 7). The metric
functions below only SELECT.
"""
import json
import math
import statistics

from app.tools import redact

TICKET_STATUSES = ("NEW", "IN_PROGRESS", "PENDING_APPROVAL", "RESOLVED", "ESCALATED")
VERDICTS = ("ALLOW", "REQUIRE_APPROVAL", "BLOCK")
DECIDERS = ("policy", "judge", "judge_unavailable", "judge_invalid")


def log_event(conn, event_type, actor, ticket_id, payload):
    """Append one audit row. Keys containing password, token or secret are dropped first."""
    with conn:
        conn.execute(
            "INSERT INTO audit_log (event_type, actor, ticket_id, payload_json) VALUES (?, ?, ?, ?)",
            (event_type, actor, ticket_id, json.dumps(redact(payload), default=str)),
        )


# Metrics ----------------------------------------------------------------------

def ticket_counts_by_status(conn):
    counts = dict.fromkeys(TICKET_STATUSES, 0)
    for r in conn.execute("SELECT status, COUNT(*) AS n FROM tickets GROUP BY status"):
        counts[r["status"]] = r["n"]
    return counts


def verdict_counts(conn, mode="on"):
    """Final verdicts of all proposed actions in the given Warden mode."""
    counts = dict.fromkeys(VERDICTS, 0)
    for r in conn.execute(
            "SELECT final_verdict, COUNT(*) AS n FROM actions "
            "WHERE final_verdict IS NOT NULL AND warden_mode = ? GROUP BY final_verdict", (mode,)):
        counts[r["final_verdict"]] = r["n"]
    return counts


def auto_resolution_rate(conn):
    """Tickets RESOLVED without any human approval, as a share of all tickets. None if there are no tickets."""
    total = conn.execute("SELECT COUNT(*) FROM tickets").fetchone()[0]
    if total == 0:
        return None
    auto = conn.execute(
        "SELECT COUNT(*) FROM tickets t WHERE t.status = 'RESOLVED' "
        "AND NOT EXISTS (SELECT 1 FROM approvals a WHERE a.ticket_id = t.ticket_id)").fetchone()[0]
    return auto / total


def attacks_blocked(conn):
    """Actions Warden refused (policy, judge or invalid judge output). Warden-off runs never block."""
    return conn.execute(
        "SELECT COUNT(*) FROM actions WHERE status = 'BLOCKED' AND warden_mode = 'on'").fetchone()[0]


def security_flag_count(conn):
    return conn.execute("SELECT COUNT(*) FROM tickets WHERE security_flag = 1").fetchone()[0]


def judge_latency_stats(conn):
    """Median and p95 (nearest rank) of judge call time in ms, over every action the judge was asked about."""
    values = sorted(r[0] for r in conn.execute("SELECT judge_latency_ms FROM actions WHERE judge_latency_ms IS NOT NULL"))
    if not values:
        return {"count": 0, "median_ms": None, "p95_ms": None}
    return {
        "count": len(values),
        "median_ms": statistics.median(values),
        "p95_ms": values[math.ceil(0.95 * len(values)) - 1],
    }


def catch_split(conn, mode="on"):
    """Who stopped or paused actions: counts of BLOCK and REQUIRE_APPROVAL verdicts by decider.

    Deciders: policy (a rule), judge (risk or verdict), judge_unavailable (approval because the judge was
    down), judge_invalid (block because its output was invalid).
    """
    split = {d: {"BLOCK": 0, "REQUIRE_APPROVAL": 0} for d in DECIDERS}
    for r in conn.execute(
            "SELECT decided_by, final_verdict, COUNT(*) AS n FROM actions "
            "WHERE final_verdict IN ('BLOCK', 'REQUIRE_APPROVAL') AND warden_mode = ? "
            "AND decided_by IN ('policy', 'judge', 'judge_unavailable', 'judge_invalid') "
            "GROUP BY decided_by, final_verdict", (mode,)):
        split[r["decided_by"]][r["final_verdict"]] = r["n"]
    return split


def dashboard_metrics(conn):
    """Everything the dashboard's Metrics page needs, in one dict."""
    return {
        "tickets_by_status": ticket_counts_by_status(conn),
        "verdicts": verdict_counts(conn),
        "auto_resolution_rate": auto_resolution_rate(conn),
        "attacks_blocked": attacks_blocked(conn),
        "security_flags": security_flag_count(conn),
        "judge_latency": judge_latency_stats(conn),
        "catch_split": catch_split(conn),
    }
