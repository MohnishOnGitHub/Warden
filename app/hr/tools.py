"""The HR onboarding tools: arg models, mock implementations on the simulated HR tables, Gemini declarations.

Same shape as app/tools.py: every implementation takes (conn, args_model) and returns a plain dict.
"""
from datetime import datetime

from pydantic import Field

from app.tools import TOOL_DECLARATIONS, ArgsBase, ToolError, ToolSpec, _declaration


class CreateAccountArgs(ArgsBase):
    candidate_id: str = Field(min_length=1, description="Candidate ID, e.g. C-101")


class AssignLaptopArgs(ArgsBase):
    candidate_id: str = Field(min_length=1, description="Candidate ID, e.g. C-101")
    asset_id: str = Field(min_length=1, description="Laptop asset ID, e.g. LT-HR-01")


class GrantAppAccessArgs(ArgsBase):
    candidate_id: str = Field(min_length=1, description="Candidate ID, e.g. C-101")
    app: str = Field(min_length=1, description="Application name, e.g. email")


class ScheduleOrientationArgs(ArgsBase):
    candidate_id: str = Field(min_length=1, description="Candidate ID, e.g. C-101")
    date: str = Field(min_length=1, description="Orientation date as YYYY-MM-DD")


def _candidate(conn, candidate_id):
    row = conn.execute("SELECT * FROM hr_candidates WHERE candidate_id = ?", (candidate_id,)).fetchone()
    if row is None:
        raise ToolError(f"Unknown candidate: {candidate_id}")
    return row


def create_account(conn, args: CreateAccountArgs):
    c = _candidate(conn, args.candidate_id)
    if conn.execute("SELECT 1 FROM hr_accounts WHERE candidate_id = ?", (args.candidate_id,)).fetchone():
        raise ToolError(f"Account already exists for {args.candidate_id}")
    username = ".".join(c["name"].lower().split())
    with conn:
        conn.execute("INSERT INTO hr_accounts (candidate_id, username, email) VALUES (?, ?, ?)",
                     (args.candidate_id, username, f"{username}@corp.example.com"))
    return {"status": "account_created", "candidate_id": args.candidate_id, "username": username}


def assign_laptop(conn, args: AssignLaptopArgs):
    _candidate(conn, args.candidate_id)
    asset = conn.execute("SELECT * FROM hr_assets WHERE asset_id = ?", (args.asset_id,)).fetchone()
    if asset is None:
        raise ToolError(f"Unknown asset: {args.asset_id}")
    if asset["status"] != "available":
        raise ToolError(f"Asset is not available: {args.asset_id}")
    with conn:
        conn.execute("INSERT INTO hr_asset_assignments (candidate_id, asset_id) VALUES (?, ?)",
                     (args.candidate_id, args.asset_id))
        conn.execute("UPDATE hr_assets SET status = 'assigned' WHERE asset_id = ?", (args.asset_id,))
    return {"status": "laptop_assigned", "candidate_id": args.candidate_id, "asset_id": args.asset_id}


def grant_app_access(conn, args: GrantAppAccessArgs):
    _candidate(conn, args.candidate_id)
    if conn.execute("SELECT 1 FROM hr_apps WHERE app = ?", (args.app,)).fetchone() is None:
        raise ToolError(f"Unknown application: {args.app}")
    with conn:
        conn.execute("INSERT OR IGNORE INTO hr_app_access (candidate_id, app) VALUES (?, ?)",
                     (args.candidate_id, args.app))
    return {"status": "access_granted", "candidate_id": args.candidate_id, "app": args.app}


def schedule_orientation(conn, args: ScheduleOrientationArgs):
    _candidate(conn, args.candidate_id)
    try:
        datetime.strptime(args.date, "%Y-%m-%d")
    except ValueError:
        raise ToolError(f"Not a valid date (use YYYY-MM-DD): {args.date}") from None
    with conn:
        conn.execute("INSERT INTO hr_orientations (candidate_id, session_date) VALUES (?, ?)",
                     (args.candidate_id, args.date))
    return {"status": "orientation_scheduled", "candidate_id": args.candidate_id, "date": args.date}


HR_TOOLS = {
    "create_account": ToolSpec("Create the corporate account for a new hire.", CreateAccountArgs, create_account, True),
    "assign_laptop": ToolSpec("Assign an available laptop to a new hire.", AssignLaptopArgs, assign_laptop, True),
    "grant_app_access": ToolSpec("Give a new hire access to an application.", GrantAppAccessArgs, grant_app_access, True),
    "schedule_orientation": ToolSpec("Book a new hire's orientation session.", ScheduleOrientationArgs,
                                     schedule_orientation, True),
}

# What the HR agent is offered: the four HR tools plus the two closing tools, which are shared with the IT desk.
CLOSING = ("resolve_ticket", "escalate_to_human")
HR_TOOL_DECLARATIONS = (
    [_declaration(name, spec) for name, spec in HR_TOOLS.items()]
    + [d for d in TOOL_DECLARATIONS if d["name"] in CLOSING]
)
