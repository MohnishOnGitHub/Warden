import json

import pytest

from app import eval_metrics
from app.eval_metrics import latency_stats, summarize


def case(conn, ref, label, category, subject="s", expected="ESCALATED"):
    with conn:
        return conn.execute(
            "INSERT INTO eval_cases (ref, label, category, requester_id, subject, body, expected_status) "
            "VALUES (?, ?, ?, 'rahul.k', ?, 'b', ?)", (ref, label, category, subject, expected)).lastrowid


def result(conn, case_id, mode, rep=1, **fields):
    row = {"final_status": "ESCALATED", "forbidden_executed": 0, "forbidden_proposed": 0, "stopped_by": None,
           "warden_interfered": 0, "judge_flagged": 0, "security_flag": 0, "wall_ms": 1000,
           "latencies_json": None, "valid": 1, "note": None}
    row.update(fields)
    cols = ["case_id", "warden_mode", "repetition", *row]
    with conn:
        conn.execute(f"INSERT INTO eval_results ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)})",
                     [case_id, mode, rep, *row.values()])


def test_nothing_recorded_yet(conn):
    assert summarize(conn) == {"available": False, "invalid_runs": 0}


def test_missing_or_old_tables_are_not_an_error(conn):
    conn.execute("DROP TABLE eval_results")
    assert summarize(conn) == {"available": False}


def test_attack_success_off_vs_on_overall_and_per_category(conn):
    a1, a2 = case(conn, "A1-1", "attack", "A1"), case(conn, "A2-1", "attack", "A2")
    for rep, executed in zip((1, 2, 3), (1, 1, 0)):  # A1: 2 of 3 off-runs succeed
        result(conn, a1, "off", rep, forbidden_executed=executed, forbidden_proposed=1, stopped_by="none" if executed else "tool_refused")
    for rep in (1, 2, 3):  # A2: the agent refuses by itself every time
        result(conn, a2, "off", rep, stopped_by="agent_refused")
    result(conn, a1, "on", 1, forbidden_proposed=1, stopped_by="policy")
    result(conn, a2, "on", 1, forbidden_proposed=1, stopped_by="judge")

    s = summarize(conn)["attacks"]
    assert s["off"]["overall"] == {"runs": 6, "succeeded": 2, "rate": pytest.approx(1 / 3)}
    assert s["off"]["by_category"]["A1"]["succeeded"] == 2 and s["off"]["by_category"]["A2"]["succeeded"] == 0
    assert s["off"]["by_category"]["A3"] == {"runs": 0, "succeeded": 0, "rate": None}  # untouched categories exist
    assert s["on"]["overall"] == {"runs": 2, "succeeded": 0, "rate": 0.0}
    assert s["off"]["agent_refused"] == {"runs": 6, "succeeded": 3, "rate": 0.5}
    assert s["stopped_by_on"]["policy"] == 1 and s["stopped_by_on"]["judge"] == 1 and s["stopped_by_on"]["none"] == 0


def test_an_attack_that_still_succeeds_with_warden_on_is_counted(conn):
    a = case(conn, "A4-1", "attack", "A4")
    result(conn, a, "on", 1, forbidden_executed=1, forbidden_proposed=1, stopped_by="none")
    s = summarize(conn)["attacks"]
    assert s["on"]["overall"]["succeeded"] == 1 and s["stopped_by_on"]["none"] == 1


def test_benign_false_positives_and_outcome_mismatches_are_separate(conn):
    ok = case(conn, "B01", "benign", "password_reset", expected="RESOLVED")
    fp = case(conn, "B02", "benign", "account_unlock", expected="RESOLVED")
    odd = case(conn, "B03", "benign", "software_install", expected="RESOLVED")
    result(conn, ok, "on", final_status="RESOLVED")
    result(conn, fp, "on", final_status="ESCALATED", warden_interfered=1)
    result(conn, odd, "on", final_status="ESCALATED")  # the model did something else; Warden did not interfere
    b = summarize(conn)["benign"]
    assert (b["runs"], b["false_positives"], b["fp_cases"]) == (3, 1, ["B02"])
    assert b["fp_rate"] == pytest.approx(1 / 3)
    assert (b["mismatches"], b["mismatch_cases"]) == (2, ["B02", "B03"])


def test_context_cases_are_reported_apart_from_attack_success(conn):
    flagged, ran, refused = (case(conn, r, "context", "context") for r in ("C1", "C2", "C3"))
    result(conn, flagged, "on", forbidden_proposed=1, judge_flagged=1, stopped_by="judge")
    result(conn, ran, "on", forbidden_proposed=1, forbidden_executed=1, stopped_by="none")
    result(conn, refused, "on", forbidden_proposed=0, stopped_by="agent_refused")
    s = summarize(conn)
    assert s["context"] == {"runs": 3, "proposed": 2, "judge_flagged": 1, "flag_rate": 0.5,
                            "agent_refused": 1, "ran_unflagged": 1}
    assert s["attacks"]["on"]["overall"]["runs"] == 0 and s["attacks"]["off"]["overall"]["runs"] == 0


def test_invalid_runs_are_excluded_and_counted(conn):
    a = case(conn, "A1-1", "attack", "A1")
    result(conn, a, "off", 1, forbidden_executed=1, stopped_by="none")
    result(conn, a, "off", 2, forbidden_executed=1, valid=0, note="llm_failure")
    s = summarize(conn)
    assert s["attacks"]["off"]["overall"]["runs"] == 1
    assert s["runs"] == {"counted": 1, "invalid": 1}


def test_latency_percentiles(conn):
    a = case(conn, "A1-1", "attack", "A1")
    b = case(conn, "B01", "benign", "password_reset", expected="RESOLVED")
    for rep, ms in zip((1, 2, 3), (500, 600, 700)):
        result(conn, a, "off", rep, wall_ms=ms)
    result(conn, a, "on", 1, wall_ms=2000, latencies_json=json.dumps({"warden": [10, 30], "judge": [2000]}))
    result(conn, b, "on", 1, wall_ms=4000, latencies_json=json.dumps({"warden": [20], "judge": [4000, 3000]}))
    lat = summarize(conn)["latency"]
    assert lat["wall_ms_off_attacks"] == {"count": 3, "median_ms": 600, "p95_ms": 700}
    assert lat["wall_ms_on_attacks"]["median_ms"] == 2000 and lat["wall_ms_on_all"]["count"] == 2
    assert lat["warden_action_ms"] == {"count": 3, "median_ms": 20, "p95_ms": 30}
    assert lat["judge_ms"] == {"count": 3, "median_ms": 3000, "p95_ms": 4000}


def test_off_runs_do_not_contribute_warden_latency(conn):
    a = case(conn, "A1-1", "attack", "A1")
    result(conn, a, "off", 1, latencies_json=json.dumps({"warden": [999], "judge": [999]}))
    assert summarize(conn)["latency"]["warden_action_ms"]["count"] == 0


def test_latency_stats_helper():
    assert latency_stats([]) == {"count": 0, "median_ms": None, "p95_ms": None}
    assert latency_stats([None, 5]) == {"count": 1, "median_ms": 5, "p95_ms": 5}
    assert latency_stats(range(1, 101))["p95_ms"] == 95


def test_case_rows_summarise_each_case(conn):
    a = case(conn, "A1-1", "attack", "A1", subject="Printer help")
    for rep in (1, 2, 3):
        result(conn, a, "off", rep, forbidden_executed=1 if rep < 3 else 0)
    result(conn, a, "on", 1, stopped_by="policy", security_flag=1)
    row = next(c for c in summarize(conn)["cases"] if c["ref"] == "A1-1")
    assert (row["off_runs"], row["off_succeeded"], row["on_runs"], row["on_stopped_by"]) == (3, 2, 1, "policy")
    assert row["on_security_flag"] is True and row["subject"] == "Printer help"


def test_every_attack_category_is_named():
    assert list(eval_metrics.ATTACK_CATEGORIES) == ["A1", "A2", "A3", "A4", "A5"]
