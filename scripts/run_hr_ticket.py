"""Run one benign and one attack HR onboarding ticket through the same Warden pipeline as the IT desk.

Run from the repo root:
    python scripts/run_hr_ticket.py                 live: Gemini is the agent and the judge (about 10 calls)
    python scripts/run_hr_ticket.py --scripted      canned agent steps instead of Gemini; the judge still runs
                                                    if a GEMINI_API_KEY is set, otherwise policy only
    python scripts/run_hr_ticket.py --rules-only    skip the judge (policy only)
    python scripts/run_hr_ticket.py --only attack   run just one of the two tickets

It uses a throwaway database (data/hr_demo.db) that is rebuilt every time. Nothing else is touched.
"""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import hr, llm  # noqa: E402  (llm loads .env)
from app.agent import run_ticket  # noqa: E402
from app.db import ROOT, get_connection  # noqa: E402
from app.hr.db import HR_TABLES, reset_hr_demo  # noqa: E402
from app.hr.demo import ATTACK, BENIGN, SCRIPTS, ScriptedAgent  # noqa: E402
from app.hr.prompt import HR_SYSTEM_PROMPT  # noqa: E402
from app.hr.tools import HR_TOOL_DECLARATIONS  # noqa: E402
from app.ingestion import build_envelope, create_ticket  # noqa: E402
from app.warden import warden_mode  # noqa: E402

DB_PATH = ROOT / "data" / "hr_demo.db"


def print_step(s):
    print(f"\n  Step {s['step']}: agent proposes {s['tool']}({json.dumps(s['args'])})")
    if s["status"] == "executed":
        print(f"    -> EXECUTED  policy={s['rule_id'] or 'none'}  result={json.dumps(s['result'])}")
    elif s["status"] == "pending_approval":
        print(f"    -> PENDING APPROVAL  decided_by={s['decided_by']}  policy rule={s['rule_id']}  "
              f"approver={s['approver_id']}")
    else:
        print(f"    -> BLOCKED  decided_by={s['decided_by']}  policy rule={s['rule_id']}  "
              f"agent is told: {s['reason']!r}")
    j = s["judge"]
    if j:
        print(f"       judge: {j['verdict']} risk={j['risk_score']} indicators={j['indicators']}")
        print(f"              reason: {j['reason']}")
    elif s["decided_by"] is not None and s["tool"] in ("create_account", "assign_laptop", "grant_app_access",
                                                       "schedule_orientation"):
        print("       judge: not run")


def hr_state(conn):
    parts = []
    for table in HR_TABLES[3:]:
        n = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        parts.append(f"{table.removeprefix('hr_')}={n}")
    return ", ".join(parts)


def run_one(conn, case, scripted):
    tid = create_ticket(conn, case["requester"], case["subject"], case["body"])
    env = build_envelope(conn, tid)
    print("=" * 78)
    print(f"{case['label'].upper()} ticket {tid} from {case['requester']}  (Warden {warden_mode()})")
    print(f"Subject: {case['subject']}")
    print(f"Scanner markers: {env.markers or 'none'}")
    agent = ScriptedAgent(SCRIPTS[case["label"]](tid)) if scripted else None
    result = run_ticket(conn, tid, llm_fn=agent, on_step=print_step,
                        tools=HR_TOOL_DECLARATIONS, system_prompt=HR_SYSTEM_PROMPT)
    t = conn.execute("SELECT status, security_flag, resolution_note FROM tickets WHERE ticket_id = ?", (tid,)).fetchone()
    print(f"\n  Final: {t['status']}  security_flag={t['security_flag']}")
    print(f"  Note: {t['resolution_note']}")
    print(f"  HR directory now: {hr_state(conn)}")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scripted", action="store_true", help="canned agent steps instead of Gemini")
    parser.add_argument("--rules-only", action="store_true", help="skip the judge (policy only)")
    parser.add_argument("--only", choices=("benign", "attack"))
    args = parser.parse_args()

    have_key = bool(os.environ.get("GEMINI_API_KEY"))
    if args.rules_only or (args.scripted and not have_key):
        os.environ["WARDEN_MODE"] = "rules_only"
        print("Judge skipped (policy only)." if args.rules_only else "No GEMINI_API_KEY: judge skipped (policy only).")
    elif not args.scripted and not have_key:
        sys.exit("GEMINI_API_KEY is not set (put it in .env), or use --scripted --rules-only.")
    if not args.scripted:
        try:
            llm.check_models()
        except llm.LLMConfigError as e:
            sys.exit(f"CONFIGURATION ERROR: {e}")

    hr.register()
    conn = get_connection(DB_PATH)
    try:
        reset_hr_demo(conn)
        print(f"HR onboarding domain on the Warden pipeline. Database: {DB_PATH.name} (rebuilt)")
        for case in (BENIGN, ATTACK):
            if args.only in (None, case["label"]):
                run_one(conn, case, args.scripted)
        print("\nAudit trail for the run:")
        for kind, n in conn.execute("SELECT event_type, COUNT(*) FROM audit_log GROUP BY event_type ORDER BY 1"):
            print(f"  {kind:<26}{n}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
