import pytest

from app.settings import SETTINGS
from app.warden.combiner import combine, score_floor
from app.warden.judge import JudgeOutput
from app.warden.policy import ALLOW, BLOCK, REQUIRE_APPROVAL, PolicyResult


def pol(verdict, approver=None):
    return PolicyResult(verdict, "P0XX", ("P0XX",), "r", approver_id=approver)


def jud(verdict="ALLOW", risk=0):
    return JudgeOutput(verdict=verdict, risk_score=risk, reason="r", indicators=[])


def test_score_floors():
    assert [score_floor(s) for s in (0, 39, 40, 69, 70, 100)] == [
        ALLOW, ALLOW, REQUIRE_APPROVAL, REQUIRE_APPROVAL, BLOCK, BLOCK]


def test_skipped_judge_keeps_policy_verdict():
    assert combine(pol(ALLOW)).verdict == ALLOW
    assert combine(pol(BLOCK)).verdict == BLOCK
    c = combine(pol(REQUIRE_APPROVAL, "anita.d"))
    assert (c.verdict, c.approver_id, c.decided_by) == (REQUIRE_APPROVAL, "anita.d", "policy")


@pytest.mark.parametrize("policy_v", [ALLOW, REQUIRE_APPROVAL, BLOCK])
@pytest.mark.parametrize("judge_v", [ALLOW, REQUIRE_APPROVAL, BLOCK])
def test_verdict_is_never_less_strict_than_either_input(policy_v, judge_v):
    order = {ALLOW: 0, REQUIRE_APPROVAL: 1, BLOCK: 2}
    c = combine(pol(policy_v, "sam.t" if policy_v == REQUIRE_APPROVAL else None), jud(judge_v), "ok")
    assert order[c.verdict] == max(order[policy_v], order[judge_v])


@pytest.mark.parametrize("policy_v", [ALLOW, REQUIRE_APPROVAL, BLOCK])
def test_judge_allow_with_zero_risk_never_relaxes(policy_v):
    c = combine(pol(policy_v, "sam.t"), jud(ALLOW, 0), "ok")
    assert c.verdict == policy_v and c.decided_by == "policy"


@pytest.mark.parametrize("risk,expected", [(0, ALLOW), (39, ALLOW), (40, REQUIRE_APPROVAL), (69, REQUIRE_APPROVAL),
                                           (70, BLOCK), (100, BLOCK)])
def test_risk_floor_overrides_a_lenient_judge_verdict(risk, expected):
    c = combine(pol(ALLOW), jud(ALLOW, risk), "ok")
    assert c.verdict == expected
    assert c.decided_by == ("policy" if expected == ALLOW else "judge")


def test_floor_never_relaxes_a_stricter_judge_verdict():
    assert combine(pol(ALLOW), jud(BLOCK, 10), "ok").verdict == BLOCK
    assert combine(pol(ALLOW), jud(REQUIRE_APPROVAL, 10), "ok").verdict == REQUIRE_APPROVAL


def test_judge_tightening_uses_fallback_approver_when_policy_named_none():
    c = combine(pol(ALLOW), jud(REQUIRE_APPROVAL, 50), "ok")
    assert (c.verdict, c.approver_id, c.decided_by) == (REQUIRE_APPROVAL, SETTINGS.fallback_approver, "judge")


def test_policy_approver_is_kept_when_judge_agrees_or_is_lenient():
    assert combine(pol(REQUIRE_APPROVAL, "anita.d"), jud(REQUIRE_APPROVAL, 50), "ok").approver_id == "anita.d"
    assert combine(pol(REQUIRE_APPROVAL, "anita.d"), jud(ALLOW, 0), "ok").approver_id == "anita.d"


def test_no_approver_unless_require_approval():
    assert combine(pol(ALLOW), jud(ALLOW, 0), "ok").approver_id is None
    assert combine(pol(ALLOW), jud(BLOCK, 90), "ok").approver_id is None


def test_judge_unavailable_means_approval_not_execution():
    c = combine(pol(ALLOW), None, "unavailable")
    assert (c.verdict, c.approver_id, c.decided_by) == (REQUIRE_APPROVAL, SETTINGS.fallback_approver,
                                                        "judge_unavailable")
    kept = combine(pol(REQUIRE_APPROVAL, "anita.d"), None, "unavailable")
    assert (kept.verdict, kept.approver_id, kept.decided_by) == (REQUIRE_APPROVAL, "anita.d", "policy")
    assert combine(pol(BLOCK), None, "unavailable").verdict == BLOCK


def test_judge_invalid_means_block():
    for policy_v in (ALLOW, REQUIRE_APPROVAL):
        c = combine(pol(policy_v, "sam.t"), None, "invalid")
        assert (c.verdict, c.approver_id, c.decided_by) == (BLOCK, None, "judge_invalid")


def test_bad_states_raise():
    with pytest.raises(ValueError):
        combine(pol(ALLOW), None, "ok")
    with pytest.raises(ValueError):
        combine(pol(ALLOW), None, "maybe")
