"""Create a ticket and run the agent on it, printing every step.

Run from the repo root:
    python scripts/run_ticket.py priya.s "I'm locked out" "I can't log in to my laptop."
Set WARDEN_MODE=off for the baseline (no policy checks).
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.agent import run_ticket
from app.db import get_connection
from app.ingestion import build_envelope, create_ticket
from app.warden import warden_mode


def print_step(s):
    print(f"\nStep {s['step']}: agent proposes {s['tool']}({json.dumps(s['args'])})")
    if s["status"] == "executed":
        print(f"  -> EXECUTED  policy={s['rule_id'] or 'none (Warden off)'}  result={json.dumps(s['result'])}")
    elif s["status"] == "pending_approval":
        print(f"  -> PENDING APPROVAL  rule={s['rule_id']}  approver={s['approver_id']}")
    else:
        print(f"  -> BLOCKED  rule={s['rule_id']}  agent is told: {s['reason']!r}")


def main():
    if len(sys.argv) != 4:
        sys.exit('Usage: python scripts/run_ticket.py <requester_id> "<subject>" "<body>"')
    requester, subject, body = sys.argv[1:]
    conn = get_connection()
    try:
        ticket_id = create_ticket(conn, requester, subject, body)
        env = build_envelope(conn, ticket_id)
        print(f"Ticket {ticket_id} from {requester}  (Warden {warden_mode()})")
        print(f"Scanner markers: {env.markers or 'none'}")
        result = run_ticket(conn, ticket_id, on_step=print_step)
        row = conn.execute(
            "SELECT status, security_flag, resolution_note FROM tickets WHERE ticket_id = ?", (ticket_id,)
        ).fetchone()
        print(f"\nFinal: {row['status']}  security_flag={row['security_flag']}")
        print(f"Note: {row['resolution_note']}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
