"""Combine the policy verdict and the judge outcome into one final verdict.

Rules: the most restrictive verdict wins (BLOCK > REQUIRE_APPROVAL > ALLOW), the judge's
risk score has floors, and the judge can only make a verdict stricter, never relax it.
"""
from dataclasses import dataclass

from app.settings import SETTINGS
from app.warden.policy import ALLOW, BLOCK, REQUIRE_APPROVAL, SEVERITY

# Judge states: skipped (judge not needed), ok (valid answer), unavailable (could not be reached),
# invalid (answered with bad output).
JUDGE_STATES = ("skipped", "ok", "unavailable", "invalid")


@dataclass(frozen=True)
class Combined:
    verdict: str
    approver_id: str | None
    decided_by: str  # policy | judge | judge_unavailable | judge_invalid


def score_floor(risk_score, settings=SETTINGS):
    """The least restrictive verdict a risk score allows."""
    if risk_score >= settings.judge_block_score:
        return BLOCK
    if risk_score >= settings.judge_approval_score:
        return REQUIRE_APPROVAL
    return ALLOW


def combine(policy, judge=None, judge_state="skipped", settings=SETTINGS):
    """policy is a PolicyResult, judge a JudgeOutput (only for judge_state 'ok')."""
    if judge_state not in JUDGE_STATES:
        raise ValueError(f"Unknown judge state: {judge_state}")
    if judge_state == "ok" and judge is None:
        raise ValueError("judge_state 'ok' needs a judge output")

    verdict, decided_by = policy.verdict, "policy"

    def tighten(candidate, source):
        nonlocal verdict, decided_by
        if SEVERITY[candidate] > SEVERITY[verdict]:
            verdict, decided_by = candidate, source

    if judge_state == "ok":
        tighten(judge.verdict, "judge")
        tighten(score_floor(judge.risk_score, settings), "judge")
    elif judge_state == "unavailable":
        tighten(REQUIRE_APPROVAL, "judge_unavailable")  # a human decides; nothing runs unattended
    elif judge_state == "invalid":
        tighten(BLOCK, "judge_invalid")

    approver = None
    if verdict == REQUIRE_APPROVAL:
        approver = policy.approver_id or settings.fallback_approver
    return Combined(verdict, approver, decided_by)
