"""HR onboarding: a second domain on the same Warden pipeline.

Only configuration, tool definitions and seed data are new. warden.handle(), the judge, the combiner, approvals
and the audit log are the IT desk's, unchanged. register() plugs the HR tools and config/policy_hr.yaml in:
evaluate_policy picks a policy by tool name, so approvals (which recheck policy at approval time) work for HR too.

Limits: tool names are global, so run one domain per process (the demo script and the tests do). Closing tools are
shared and keep using the IT rules P060 to P062. The completion check does not cover HR tools (see completion.py).
"""
from app.db import ROOT
from app.hr import predicates  # noqa: F401  (registers the HR predicates)
from app.hr.tools import HR_TOOL_DECLARATIONS, HR_TOOLS
from app.tools import register_tools, unregister_tools
from app.warden import completion
from app.warden.policy import load_policy, register_policy, unregister_policy

HR_POLICY_PATH = ROOT / "config" / "policy_hr.yaml"
_registered = False


def register():
    """Make the HR tools executable and route them to the HR policy. Safe to call twice."""
    global _registered
    if _registered:
        return
    register_tools(HR_TOOLS)
    try:
        policy = load_policy(HR_POLICY_PATH)  # after the tools exist: it checks that its rules name real tools
    except Exception:
        unregister_tools(HR_TOOLS)
        raise
    register_policy(HR_TOOLS, policy)
    completion.SKIPPED_TOOLS.update(HR_TOOLS)
    _registered = True


def unregister():
    global _registered
    unregister_policy(HR_TOOLS)
    unregister_tools(HR_TOOLS)
    completion.SKIPPED_TOOLS.difference_update(HR_TOOLS)
    _registered = False
