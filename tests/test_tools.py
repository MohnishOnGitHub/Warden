import pytest
from google.genai import types
from pydantic import ValidationError

from app.tools import TOOL_DECLARATIONS, TOOLS, ToolError, execute_tool, redact


def test_reset_password_returns_no_secret_and_writes_outbox(conn):
    result = execute_tool(conn, "reset_password", {"user_id": "priya.s"})

    assert result == {"status": "password_reset", "sent_to": "email on file"}
    rows = conn.execute("SELECT to_email, body FROM outbox").fetchall()
    assert len(rows) == 1
    assert rows[0]["to_email"] == "priya.s@corp.example.com"
    temp_password = rows[0]["body"].split("password is ")[1].split(". ")[0]
    assert temp_password and temp_password not in str(result)
    assert "priya.s@corp.example.com" not in str(result)


def test_reset_password_has_no_destination_argument(conn):
    with pytest.raises(ValidationError):
        execute_tool(conn, "reset_password", {"user_id": "priya.s", "send_to": "evil@x.com"})
    assert conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == 0


def test_extra_missing_and_wrong_type_args_are_rejected(conn):
    with pytest.raises(ValidationError):
        execute_tool(conn, "install_software", {"device_id": "LT1042", "package": "git", "force": True})
    with pytest.raises(ValidationError):
        execute_tool(conn, "install_software", {"device_id": "LT1042"})
    with pytest.raises(ValidationError):
        execute_tool(conn, "resolve_ticket", {"ticket_id": 1001, "message": "done"})  # ids are text, numbers rejected


def test_unknown_entities_raise_tool_error(conn):
    with pytest.raises(ToolError):
        execute_tool(conn, "get_user_profile", {"user_id": "nobody"})
    with pytest.raises(ToolError):
        execute_tool(conn, "install_software", {"device_id": "LT9999", "package": "git"})
    with pytest.raises(ToolError):
        execute_tool(conn, "no_such_tool", {})


def test_get_user_profile_declaration_has_no_redact_parameter():
    decl = next(d for d in TOOL_DECLARATIONS if d["name"] == "get_user_profile")
    assert list(decl["parameters"]["properties"]) == ["user_id"]


def test_agent_cannot_send_redact_flag(conn):
    with pytest.raises(ValidationError):
        execute_tool(conn, "get_user_profile", {"user_id": "priya.s", "redact": False})


def test_redact_obligation_is_passed_by_warden_only(conn):
    full = execute_tool(conn, "get_user_profile", {"user_id": "priya.s"})
    assert "email" in full and "role" in full
    assert execute_tool(conn, "get_user_profile", {"user_id": "priya.s"}, redact=True) == {
        "name": "Priya S", "department": "Engineering"}


def test_redact_helper_strips_sensitive_keys_recursively():
    data = {"name": "x", "Password": "p", "api_token": "t", "nested": [{"client_secret": "s", "ok": 1}]}
    assert redact(data) == {"name": "x", "nested": [{"ok": 1}]}


def test_declarations_cover_all_tools_and_are_valid_for_gemini_sdk():
    assert {d["name"] for d in TOOL_DECLARATIONS} == set(TOOLS)
    for decl in TOOL_DECLARATIONS:
        types.FunctionDeclaration(**decl)  # raises if the SDK rejects the shape


def test_resolve_and_escalate_update_ticket(conn):
    execute_tool(conn, "escalate_to_human", {"ticket_id": "T1001", "summary": "odd", "security_concern": True})
    t = conn.execute("SELECT status, security_flag FROM tickets WHERE ticket_id = 'T1001'").fetchone()
    assert (t["status"], t["security_flag"]) == ("ESCALATED", 1)
    execute_tool(conn, "resolve_ticket", {"ticket_id": "T1001", "message": "done"})
    assert conn.execute("SELECT status FROM tickets WHERE ticket_id = 'T1001'").fetchone()[0] == "RESOLVED"


def test_restart_service_sets_last_restart_at_and_refuses_non_restartable(conn):
    q = "SELECT last_restart_at FROM services WHERE host = ? AND service_name = ?"
    assert conn.execute(q, ("dev01", "nginx")).fetchone()[0] is None
    execute_tool(conn, "restart_service", {"host": "dev01", "service_name": "nginx"})
    assert conn.execute(q, ("dev01", "nginx")).fetchone()[0] is not None
    with pytest.raises(ToolError):
        execute_tool(conn, "restart_service", {"host": "dc01", "service_name": "ntds"})
    assert conn.execute(q, ("dc01", "ntds")).fetchone()[0] is None
