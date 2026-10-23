"""List, approve and deny approvals from the terminal.

Run from the repo root:
    python scripts/approvals_cli.py list [--all]
    python scripts/approvals_cli.py approve 1 --as anita.d [--comment "ok"]
    python scripts/approvals_cli.py deny 1 --as anita.d [--comment "no"]
    python scripts/approvals_cli.py expire

--as is whatever you type: this is a simulation with no login. What Warden guarantees is that
only the approver named on the approval can decide it, and never the requester.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.approvals import approve, deny, expire_overdue
from app.db import get_connection


def cmd_list(conn, args):
    for approval_id in expire_overdue(conn):
        print(f"(approval {approval_id} expired)")
    where = "" if args.all else "WHERE ap.status = 'PENDING'"
    rows = conn.execute(
        "SELECT ap.approval_id, ap.status, ap.approver_id, ap.expires_at, ap.ticket_id, t.requester_id, "
        "ac.tool, ac.args_json FROM approvals ap JOIN actions ac ON ac.action_id = ap.action_id "
        f"JOIN tickets t ON t.ticket_id = ap.ticket_id {where} ORDER BY ap.approval_id").fetchall()
    if not rows:
        print("No approvals." if args.all else "No pending approvals.")
    for r in rows:
        print(f"#{r['approval_id']} [{r['status']}] ticket {r['ticket_id']} requester {r['requester_id']} "
              f"-> approver {r['approver_id']}, expires {r['expires_at']} UTC")
        print(f"    {r['tool']}({json.dumps(json.loads(r['args_json']))})")
    return 0


def cmd_decide(conn, args):
    action = approve if args.command == "approve" else deny
    result = action(conn, args.approval_id, args.as_user, args.comment)
    print(f"{'OK' if result.ok else 'REJECTED'} ({result.status}): {result.message}")
    return 0 if result.ok else 1


def cmd_expire(conn, args):
    ids = expire_overdue(conn)
    print(f"Expired: {ids}" if ids else "Nothing to expire.")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("list")
    p.add_argument("--all", action="store_true", help="include decided and expired approvals")
    for name in ("approve", "deny"):
        p = sub.add_parser(name)
        p.add_argument("approval_id", type=int)
        p.add_argument("--as", dest="as_user", required=True, help="your user id, e.g. anita.d")
        p.add_argument("--comment")
    sub.add_parser("expire")
    args = parser.parse_args()

    conn = get_connection()
    try:
        handler = {"list": cmd_list, "approve": cmd_decide, "deny": cmd_decide, "expire": cmd_expire}[args.command]
        sys.exit(handler(conn, args))
    finally:
        conn.close()


if __name__ == "__main__":
    main()
