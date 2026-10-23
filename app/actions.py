"""The one place that updates an actions row. Shared by warden.handle() and approvals."""

# Columns set_action may write. Fixed list, so no SQL text ever comes from outside.
ACTION_COLUMNS = {
    "policy_verdict", "policy_rule_ids", "policy_reason", "final_verdict", "status", "latency_ms",
    "judge_verdict", "judge_risk_score", "judge_reason", "judge_indicators_json", "judge_latency_ms",
    "obligations_json", "decided_by",
}


def set_action(conn, action_id, **cols):
    assert set(cols) <= ACTION_COLUMNS
    sets = ", ".join(f"{c} = ?" for c in cols)
    with conn:
        conn.execute(f"UPDATE actions SET {sets} WHERE action_id = ?", (*cols.values(), action_id))
