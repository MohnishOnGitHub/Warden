"""The 8 service desk tools: Gemini declarations, Pydantic arg models, mock implementations.

Nothing here is wired to anything yet. Warden is the only caller (milestone 4+).
Every implementation takes (conn, args_model) and returns a plain dict.
"""
import secrets
from dataclasses import dataclass
from typing import Callable

from pydantic import BaseModel, ConfigDict, Field

SENSITIVE_KEY_PARTS = ("password", "token", "secret")


class ToolError(Exception):
    """A tool could not run: unknown user/device/group/service/ticket, or a refused operation."""


def redact(obj):
    """Return a copy of obj with any key containing password, token or secret removed."""
    if isinstance(obj, dict):
        return {
            k: redact(v) for k, v in obj.items()
            if not any(part in str(k).lower() for part in SENSITIVE_KEY_PARTS)
        }
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


# Arg models: what the agent is allowed to send. Extra fields are rejected, so the
# agent cannot smuggle in e.g. a destination for the temp password or a redact flag.

class ArgsBase(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class GetUserProfileArgs(ArgsBase):
    user_id: str = Field(min_length=1, description="User ID, e.g. priya.s")


class ResetPasswordArgs(ArgsBase):
    user_id: str = Field(min_length=1, description="User whose password should be reset")


class UnlockAccountArgs(ArgsBase):
    user_id: str = Field(min_length=1, description="User whose account should be unlocked")


class InstallSoftwareArgs(ArgsBase):
    device_id: str = Field(min_length=1, description="Device ID, e.g. LT1042")
    package: str = Field(min_length=1, description="Package name, e.g. vscode")


class GrantGroupMembershipArgs(ArgsBase):
    user_id: str = Field(min_length=1, description="User to add to the group")
    group_name: str = Field(min_length=1, description="Group name, e.g. FinanceReports")
    justification: str = Field(min_length=1, description="Why this access is needed")


class RestartServiceArgs(ArgsBase):
    host: str = Field(min_length=1, description="Host name, e.g. dev01")
    service_name: str = Field(min_length=1, description="Service name, e.g. nginx")


class ResolveTicketArgs(ArgsBase):
    ticket_id: str = Field(min_length=1, description="ID of the ticket being worked on, e.g. T1001")
    message: str = Field(min_length=1, description="Resolution note for the requester")


class EscalateToHumanArgs(ArgsBase):
    ticket_id: str = Field(min_length=1, description="ID of the ticket being worked on, e.g. T1001")
    summary: str = Field(min_length=1, description="What a human needs to know")
    security_concern: bool = Field(description="True if the ticket looks like an attack")


# Implementations

def _require_user(conn, user_id):
    row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if row is None:
        raise ToolError(f"Unknown user: {user_id}")
    return row


def _require_ticket(conn, ticket_id):
    row = conn.execute("SELECT ticket_id FROM tickets WHERE ticket_id = ?", (ticket_id,)).fetchone()
    if row is None:
        raise ToolError(f"Unknown ticket: {ticket_id}")


def get_user_profile(conn, args: GetUserProfileArgs, redact: bool = False):
    # `redact` is an obligation set by Warden, not an agent argument.
    u = _require_user(conn, args.user_id)
    if redact:
        return {"name": u["name"], "department": u["department"]}
    return {
        "user_id": u["user_id"], "name": u["name"], "email": u["email"],
        "department": u["department"], "role": u["role"],
        "manager_id": u["manager_id"], "locked": bool(u["locked"]),
    }


def reset_password(conn, args: ResetPasswordArgs):
    u = _require_user(conn, args.user_id)
    temp_password = secrets.token_urlsafe(12)
    with conn:
        conn.execute(
            "INSERT INTO outbox (to_email, subject, body) VALUES (?, ?, ?)",
            (u["email"], "Your temporary password",
             f"Your temporary password is {temp_password}. Change it at next login."),
        )
    # Never return the password or the real address.
    return {"status": "password_reset", "sent_to": "email on file"}


def unlock_account(conn, args: UnlockAccountArgs):
    _require_user(conn, args.user_id)
    with conn:
        conn.execute("UPDATE users SET locked = 0 WHERE user_id = ?", (args.user_id,))
    return {"status": "unlocked", "user_id": args.user_id}


def install_software(conn, args: InstallSoftwareArgs):
    if conn.execute("SELECT 1 FROM devices WHERE device_id = ?", (args.device_id,)).fetchone() is None:
        raise ToolError(f"Unknown device: {args.device_id}")
    with conn:
        conn.execute("INSERT INTO installs (device_id, package) VALUES (?, ?)", (args.device_id, args.package))
    return {"status": "installed", "device_id": args.device_id, "package": args.package}


def grant_group_membership(conn, args: GrantGroupMembershipArgs):
    _require_user(conn, args.user_id)
    if conn.execute("SELECT 1 FROM groups WHERE group_name = ?", (args.group_name,)).fetchone() is None:
        raise ToolError(f"Unknown group: {args.group_name}")
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO group_members (group_name, user_id) VALUES (?, ?)",
            (args.group_name, args.user_id),
        )
    return {"status": "granted", "user_id": args.user_id, "group_name": args.group_name}


def restart_service(conn, args: RestartServiceArgs):
    svc = conn.execute(
        "SELECT restartable FROM services WHERE host = ? AND service_name = ?",
        (args.host, args.service_name),
    ).fetchone()
    if svc is None:
        raise ToolError(f"Unknown service: {args.host}/{args.service_name}")
    if not svc["restartable"]:
        raise ToolError(f"Service is not restartable: {args.host}/{args.service_name}")
    with conn:
        conn.execute(
            "UPDATE services SET last_restart_at = datetime('now') WHERE host = ? AND service_name = ?",
            (args.host, args.service_name),
        )
    return {"status": "restarted", "host": args.host, "service_name": args.service_name}


def resolve_ticket(conn, args: ResolveTicketArgs):
    _require_ticket(conn, args.ticket_id)
    with conn:
        conn.execute(
            "UPDATE tickets SET status = 'RESOLVED', resolution_note = ?, updated_at = datetime('now') "
            "WHERE ticket_id = ?",
            (args.message, args.ticket_id),
        )
    return {"status": "resolved", "ticket_id": args.ticket_id}


def escalate_to_human(conn, args: EscalateToHumanArgs):
    _require_ticket(conn, args.ticket_id)
    with conn:
        conn.execute(
            "UPDATE tickets SET status = 'ESCALATED', resolution_note = ?, security_flag = MAX(security_flag, ?), "
            "updated_at = datetime('now') WHERE ticket_id = ?",
            (args.summary, int(args.security_concern), args.ticket_id),
        )
    return {"status": "escalated", "ticket_id": args.ticket_id}


# Registry

@dataclass(frozen=True)
class ToolSpec:
    description: str
    args_model: type[ArgsBase]
    fn: Callable
    write: bool  # write and privileged tools get the judge; reads do not


TOOLS = {
    "get_user_profile": ToolSpec("Look up a user's profile.", GetUserProfileArgs, get_user_profile, False),
    "reset_password": ToolSpec(
        "Reset a user's password. The temporary password is emailed to the address on file; "
        "it cannot be sent anywhere else.", ResetPasswordArgs, reset_password, True),
    "unlock_account": ToolSpec("Unlock a locked user account.", UnlockAccountArgs, unlock_account, True),
    "install_software": ToolSpec("Install a software package on a device.", InstallSoftwareArgs, install_software, True),
    "grant_group_membership": ToolSpec(
        "Add a user to a directory group.", GrantGroupMembershipArgs, grant_group_membership, True),
    "restart_service": ToolSpec("Restart a service on a host.", RestartServiceArgs, restart_service, True),
    "resolve_ticket": ToolSpec("Close the ticket as resolved with a note.", ResolveTicketArgs, resolve_ticket, True),
    "escalate_to_human": ToolSpec(
        "Hand the ticket to a human, optionally flagging a security concern.",
        EscalateToHumanArgs, escalate_to_human, True),
}


def _declaration(name, spec):
    """Build a Gemini function declaration from the Pydantic arg model."""
    schema = spec.args_model.model_json_schema()
    properties = {}
    for field, prop in schema["properties"].items():
        properties[field] = {"type": prop["type"], "description": prop["description"]}
    return {
        "name": name,
        "description": spec.description,
        "parameters": {"type": "object", "properties": properties, "required": schema.get("required", [])},
    }


TOOL_DECLARATIONS = [_declaration(name, spec) for name, spec in TOOLS.items()]  # the IT agent's tools: fixed at import


def register_tools(new_tools):
    """Add another domain's tools (for example app.hr) to the registry that Warden and approvals execute from.

    Explicit, never on import. Tool names are global, so a process should run one domain at a time.
    TOOL_DECLARATIONS (what the IT agent is offered) is not changed.
    """
    clash = set(new_tools) & set(TOOLS)
    if clash:
        raise ValueError(f"Tools already registered: {sorted(clash)}")
    TOOLS.update(new_tools)


def unregister_tools(names):
    for name in names:
        TOOLS.pop(name, None)


def execute_tool(conn, name, raw_args, **obligations):
    """Validate raw_args against the tool's model, run it, redact the result.

    obligations are set by Warden (e.g. redact=True), never by the agent.
    Raises ToolError for unknown tools or entities, pydantic.ValidationError for bad args.
    """
    spec = TOOLS.get(name)
    if spec is None:
        raise ToolError(f"Unknown tool: {name}")
    args = spec.args_model.model_validate(raw_args)
    return redact(spec.fn(conn, args, **obligations))
