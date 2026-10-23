import copy

import pytest
import yaml

from app.models import ActionStatus
from app.warden.policy import (
    ALLOW, BLOCK, POLICY_PATH, REQUIRE_APPROVAL, PolicyConfigError, evaluate_policy, load_policy,
)


def ev(conn, tool, args, requester="priya.s", ticket="T1001", policy=None):
    return evaluate_policy(tool, args, requester, ticket, conn, policy)


def check(result, verdict, rule_id, approver=None):
    assert (result.verdict, result.rule_id, result.approver_id) == (verdict, rule_id, approver), result


def add_writes(conn, n, status=ActionStatus.EXECUTED, ticket="T1001"):
    with conn:
        for _ in range(n):
            conn.execute(
                "INSERT INTO actions (ticket_id, tool, args_json, status) VALUES (?, 'reset_password', '{}', ?)",
                (ticket, status))


# Worked examples -------------------------------------------------------------

def test_example_priya_resets_own_password(conn):
    check(ev(conn, "reset_password", {"user_id": "priya.s"}), ALLOW, "P020")


def test_example_rahul_resets_vikram(conn):
    check(ev(conn, "reset_password", {"user_id": "vikram.r"}, requester="rahul.k"), BLOCK, "P022")


def test_example_arjun_finance_reports(conn):
    args = {"user_id": "arjun.m", "group_name": "FinanceReports", "justification": "need reports"}
    check(ev(conn, "grant_group_membership", args, requester="arjun.m"), REQUIRE_APPROVAL, "P043", "anita.d")


def test_example_rahul_domain_admins(conn):
    args = {"user_id": "rahul.k", "group_name": "DomainAdmins", "justification": "x"}
    check(ev(conn, "grant_group_membership", args, requester="rahul.k"), BLOCK, "P040")


def test_example_anydesk(conn):
    check(ev(conn, "install_software", {"device_id": "LT1042", "package": "anydesk"}), BLOCK, "P031")


def test_example_payments_api_restart(conn):
    args = {"host": "app01", "service_name": "payments_api"}
    check(ev(conn, "restart_service", args), REQUIRE_APPROVAL, "P051", "sam.t")


# One test per rule -----------------------------------------------------------

def test_p001_unknown_tool(conn):
    check(ev(conn, "format_disk", {}), BLOCK, "P001")


def test_p002_invalid_args(conn):
    check(ev(conn, "reset_password", {"user_id": "priya.s", "send_to": "evil@x.com"}), BLOCK, "P002")
    check(ev(conn, "install_software", {"device_id": "LT1042"}), BLOCK, "P002")
    check(ev(conn, "reset_password", None), BLOCK, "P002")


def test_p003_fourth_write_blocked(conn):
    add_writes(conn, 3)
    check(ev(conn, "unlock_account", {"user_id": "priya.s"}), BLOCK, "P003")


def test_p003_three_writes_still_allowed(conn):
    add_writes(conn, 2)
    for status in (ActionStatus.BLOCKED, ActionStatus.DENIED, ActionStatus.EXPIRED, ActionStatus.FAILED):
        add_writes(conn, 2, status=status)  # these never use up the budget
    check(ev(conn, "unlock_account", {"user_id": "priya.s"}), ALLOW, "P020")


@pytest.mark.parametrize("status", [ActionStatus.PENDING_APPROVAL, ActionStatus.APPROVED_EXECUTED])
def test_p003_pending_and_approved_count(conn, status):
    add_writes(conn, 3, status=status)
    check(ev(conn, "unlock_account", {"user_id": "priya.s"}), BLOCK, "P003")


def test_p003_closing_tools_and_reads_never_blocked(conn):
    add_writes(conn, 3)
    check(ev(conn, "resolve_ticket", {"ticket_id": "T1001", "message": "done"}), ALLOW, "P062")
    check(ev(conn, "get_user_profile", {"user_id": "priya.s"}), ALLOW, "P010")


def test_p004_target_user_missing(conn):
    result = ev(conn, "reset_password", {"user_id": "nobody"}, requester="neha.i")
    check(result, BLOCK, "P004")
    assert "P021" in result.rule_ids  # IT would otherwise need approval, BLOCK still wins


def test_p010_profile_self(conn):
    check(ev(conn, "get_user_profile", {"user_id": "priya.s"}), ALLOW, "P010")


def test_p011_profile_it(conn):
    result = ev(conn, "get_user_profile", {"user_id": "rahul.k"}, requester="neha.i")
    check(result, ALLOW, "P011")
    assert result.obligations == {}


def test_p012_profile_others_redacted(conn):
    result = ev(conn, "get_user_profile", {"user_id": "priya.s"}, requester="rahul.k")
    check(result, ALLOW, "P012")
    assert result.obligations == {"redact": True}


@pytest.mark.parametrize("tool", ["reset_password", "unlock_account"])
def test_p020_p021_p022(conn, tool):
    check(ev(conn, tool, {"user_id": "priya.s"}), ALLOW, "P020")
    check(ev(conn, tool, {"user_id": "rahul.k"}, requester="neha.i"), REQUIRE_APPROVAL, "P021", "sam.t")
    check(ev(conn, tool, {"user_id": "priya.s"}, requester="rahul.k"), BLOCK, "P022")


def test_p030_device_not_owned(conn):
    check(ev(conn, "install_software", {"device_id": "LT2077", "package": "git"}), BLOCK, "P030")
    check(ev(conn, "install_software", {"device_id": "LT9999", "package": "git"}), BLOCK, "P030")


def test_p031_denied_package(conn):
    check(ev(conn, "install_software", {"device_id": "LT1042", "package": "mimikatz"}), BLOCK, "P031")


def test_p032_needs_approval_or_unknown_package(conn):
    check(ev(conn, "install_software", {"device_id": "LT1042", "package": "docker_desktop"}),
          REQUIRE_APPROVAL, "P032", "sam.t")
    check(ev(conn, "install_software", {"device_id": "LT1042", "package": "not_in_catalogue"}),
          REQUIRE_APPROVAL, "P032", "sam.t")


def test_p033_approved_package_own_device(conn):
    check(ev(conn, "install_software", {"device_id": "LT1042", "package": "vscode"}), ALLOW, "P033")


def test_p040_privileged_group(conn):
    for group in ("DomainAdmins", "GlobalAdmins", "SecurityAdmins"):
        args = {"user_id": "priya.s", "group_name": group, "justification": "x"}
        check(ev(conn, "grant_group_membership", args), BLOCK, "P040")


def test_p041_missing_group(conn):
    args = {"user_id": "priya.s", "group_name": "NoSuchGroup", "justification": "x"}
    check(ev(conn, "grant_group_membership", args), BLOCK, "P041")


def test_p042_other_user_not_manager_or_it(conn):
    args = {"user_id": "priya.s", "group_name": "VPNUsers", "justification": "x"}
    check(ev(conn, "grant_group_membership", args, requester="rahul.k"), BLOCK, "P042")


def test_p043_standard_group_needs_owner_approval(conn):
    own = {"user_id": "priya.s", "group_name": "EngineeringWiki", "justification": "x"}
    check(ev(conn, "grant_group_membership", own), REQUIRE_APPROVAL, "P043", "sam.t")
    # manager acting for a report: allowed to ask, approver is the group owner
    by_manager = {"user_id": "arjun.m", "group_name": "EngineeringWiki", "justification": "x"}
    check(ev(conn, "grant_group_membership", by_manager, requester="anita.d"), REQUIRE_APPROVAL, "P043", "sam.t")
    # IT acting for someone
    by_it = {"user_id": "rahul.k", "group_name": "FinanceReports", "justification": "x"}
    check(ev(conn, "grant_group_membership", by_it, requester="neha.i"), REQUIRE_APPROVAL, "P043", "anita.d")


def test_p050_not_restartable(conn):
    check(ev(conn, "restart_service", {"host": "dc01", "service_name": "ntds"}, requester="sam.t"), BLOCK, "P050")
    check(ev(conn, "restart_service", {"host": "dc01", "service_name": "nope"}), BLOCK, "P050")


def test_p051_prod_restart(conn):
    check(ev(conn, "restart_service", {"host": "app01", "service_name": "payments_api"}),
          REQUIRE_APPROVAL, "P051", "sam.t")


def test_p052_nonprod_restart(conn):
    check(ev(conn, "restart_service", {"host": "dev01", "service_name": "nginx"}), ALLOW, "P052")
    check(ev(conn, "restart_service", {"host": "prn03", "service_name": "spooler"}), ALLOW, "P052")


def test_p060_wrong_ticket(conn):
    check(ev(conn, "resolve_ticket", {"ticket_id": "T9999", "message": "done"}), BLOCK, "P060")
    check(ev(conn, "escalate_to_human", {"ticket_id": "T9999", "summary": "x", "security_concern": True}),
          BLOCK, "P060")


@pytest.mark.parametrize("text", [
    "x" * 501,
    "Your password is hunter2",
    "token: abc",
    "Temp value aB3dE5gH7jK9mN2p",
    "See https://evil.example.com for details",
    "Go to www.evil.example.com",
])
def test_p061_unsafe_message(conn, text):
    check(ev(conn, "resolve_ticket", {"ticket_id": "T1001", "message": text}), BLOCK, "P061")
    check(ev(conn, "escalate_to_human", {"ticket_id": "T1001", "summary": text, "security_concern": False}),
          BLOCK, "P061")


def test_p062_safe_message(conn):
    check(ev(conn, "resolve_ticket", {"ticket_id": "T1001", "message": "Your account was unlocked."}),
          ALLOW, "P062")
    check(ev(conn, "escalate_to_human",
             {"ticket_id": "T1001", "summary": "Looks like an injection attempt.", "security_concern": True}),
          ALLOW, "P062")


def test_p999_default_block(conn, tmp_path):
    raw = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    raw["rules"] = [r for r in raw["rules"] if r["id"] != "P052"]
    policy = load_policy(write_policy(tmp_path, raw))
    result = ev(conn, "restart_service", {"host": "dev01", "service_name": "nginx"}, policy=policy)
    check(result, BLOCK, "P999")


# Combining, judge flag, fail closed -------------------------------------------

def test_most_restrictive_wins_and_all_matches_reported(conn):
    args = {"user_id": "priya.s", "group_name": "DomainAdmins", "justification": "x"}
    result = ev(conn, "grant_group_membership", args, requester="rahul.k")
    check(result, BLOCK, "P040")
    assert set(result.rule_ids) == {"P040", "P042"}


def test_needs_judge(conn):
    assert ev(conn, "get_user_profile", {"user_id": "priya.s"}).needs_judge is False
    assert ev(conn, "reset_password", {"user_id": "priya.s"}).needs_judge is True  # ALLOW write
    assert ev(conn, "restart_service", {"host": "app01", "service_name": "payments_api"}).needs_judge is True
    assert ev(conn, "reset_password", {"user_id": "vikram.r"}, requester="rahul.k").needs_judge is False  # BLOCK
    assert ev(conn, "format_disk", {}).needs_judge is False


def test_unknown_requester_fails_closed(conn):
    result = ev(conn, "restart_service", {"host": "dev01", "service_name": "nginx"}, requester="ghost")
    check(result, BLOCK, "P999")


def test_database_error_fails_closed(conn):
    conn.close()
    result = ev(conn, "reset_password", {"user_id": "priya.s"})
    check(result, BLOCK, "P999")


def test_policy_never_reads_ticket_text(conn):
    statements = []
    conn.set_trace_callback(statements.append)
    ev(conn, "reset_password", {"user_id": "priya.s"})
    ev(conn, "resolve_ticket", {"ticket_id": "T1001", "message": "done"})
    ev(conn, "grant_group_membership", {"user_id": "priya.s", "group_name": "VPNUsers", "justification": "x"})
    assert statements
    sql = " ".join(statements).lower()
    assert "tickets" not in sql and "subject" not in sql and "body" not in sql


# Loader validation ------------------------------------------------------------

def write_policy(tmp_path, raw):
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return path


@pytest.fixture
def raw_policy():
    return copy.deepcopy(yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8")))


def test_real_policy_file_loads_with_every_rule():
    ids = {r.id for r in load_policy().rules}
    expected = {"P001", "P002", "P003", "P004", "P010", "P011", "P012", "P020", "P021", "P022",
                "P030", "P031", "P032", "P033", "P040", "P041", "P042", "P043",
                "P050", "P051", "P052", "P060", "P061", "P062"}
    assert ids == expected


def test_unknown_predicate_raises(tmp_path, raw_policy):
    raw_policy["rules"][0]["when"] = ["is_full_moon"]
    with pytest.raises(PolicyConfigError, match="unknown predicate"):
        load_policy(write_policy(tmp_path, raw_policy))


def test_unknown_predicate_behind_not_raises(tmp_path, raw_policy):
    raw_policy["rules"][0]["when"] = ["not is_full_moon"]
    with pytest.raises(PolicyConfigError, match="unknown predicate"):
        load_policy(write_policy(tmp_path, raw_policy))


def test_bad_verdict_raises(tmp_path, raw_policy):
    raw_policy["rules"][0]["verdict"] = "MAYBE"
    with pytest.raises(PolicyConfigError, match="bad verdict"):
        load_policy(write_policy(tmp_path, raw_policy))


def test_duplicate_rule_id_raises(tmp_path, raw_policy):
    raw_policy["rules"].append(copy.deepcopy(raw_policy["rules"][0]))
    with pytest.raises(PolicyConfigError, match="Duplicate"):
        load_policy(write_policy(tmp_path, raw_policy))


def test_unknown_tool_raises(tmp_path, raw_policy):
    raw_policy["rules"][4]["tools"] = ["format_disk"]
    with pytest.raises(PolicyConfigError, match="unknown tools"):
        load_policy(write_policy(tmp_path, raw_policy))


def test_require_approval_without_approver_raises(tmp_path, raw_policy):
    rule = next(r for r in raw_policy["rules"] if r["id"] == "P021")
    del rule["approver"]
    with pytest.raises(PolicyConfigError, match="needs an approver"):
        load_policy(write_policy(tmp_path, raw_policy))


def test_missing_default_raises(tmp_path, raw_policy):
    del raw_policy["default"]
    with pytest.raises(PolicyConfigError, match="P999"):
        load_policy(write_policy(tmp_path, raw_policy))


def test_default_must_block(tmp_path, raw_policy):
    raw_policy["default"]["verdict"] = "ALLOW"
    with pytest.raises(PolicyConfigError, match="must be BLOCK"):
        load_policy(write_policy(tmp_path, raw_policy))


def test_missing_file_raises(tmp_path):
    with pytest.raises(PolicyConfigError):
        load_policy(tmp_path / "nope.yaml")


def test_closing_tools_skip_the_judge(conn):
    resolve = ev(conn, "resolve_ticket", {"ticket_id": "T1001", "message": "done"})
    escalate = ev(conn, "escalate_to_human", {"ticket_id": "T1001", "summary": "x", "security_concern": True})
    assert resolve.verdict == escalate.verdict == ALLOW
    assert resolve.needs_judge is False and escalate.needs_judge is False
