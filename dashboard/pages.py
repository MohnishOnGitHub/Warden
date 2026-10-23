"""The dashboard pages. Everything comes from the API; nothing here touches the database.

Text that can echo ticket content (subject, body, judge reason, action arguments, agent notes) is
shown with st.text / st.code / dataframes, never st.markdown, so it can never render as markup.
"""
import json

import pandas as pd
import streamlit as st

from dashboard import api_client
from dashboard.demo_tickets import DEMO_BY_LABEL, DEMO_TICKETS

REFRESH_SECONDS = 2
FALLBACK_USERS = ["priya.s", "arjun.m", "rahul.k", "anita.d", "vikram.r", "neha.i", "sam.t"]

# Verdicts are statuses, so they use the status palette, and always show a label and icon too.
VERDICT_STYLE = {
    "ALLOW": {"color": "green", "icon": ":material/check_circle:", "hex": "#0ca30c", "bg": "#d7f0d7", "fg": "#0b5a0b"},
    "REQUIRE_APPROVAL": {"color": "orange", "icon": ":material/hourglass_top:", "hex": "#fab219",
                         "bg": "#fdeec4", "fg": "#6b4a00"},
    "BLOCK": {"color": "red", "icon": ":material/block:", "hex": "#d03b3b", "bg": "#f7d4d4", "fg": "#8a1f1f"},
}
STATUS_STYLE = {
    "NEW": ("#e6e6e6", "#444444"), "IN_PROGRESS": ("#d9e8fb", "#1d4a85"),
    "PENDING_APPROVAL": ("#fdeec4", "#6b4a00"), "RESOLVED": ("#d7f0d7", "#0b5a0b"),
    "ESCALATED": ("#fbe0d2", "#7a3a1c"),
}
STAGE_STYLE = {
    "done": ("DONE", "green", ":material/check:"), "waiting": ("WAITING", "orange", ":material/hourglass_top:"),
    "skipped": ("NOTHING RAN", "gray", ":material/remove:"), "pending": ("PENDING", "gray", ":material/more_horiz:"),
}


def api_get(path, **params):
    """GET from the API, or show the problem and return None."""
    try:
        return api_client.get(path, **params)
    except api_client.ApiError as e:
        st.error(str(e))
        return None


def verdict_badge(verdict, label=None):
    style = VERDICT_STYLE.get(verdict)
    if style is None:
        st.badge(label or "none", color="gray")
    else:
        st.badge(label or verdict.replace("_", " "), color=style["color"], icon=style["icon"])


def _cell(bg_fg):
    return f"background-color: {bg_fg[0]}; color: {bg_fg[1]}" if bg_fg else ""


def style_verdict(v):
    s = VERDICT_STYLE.get(v)
    return _cell((s["bg"], s["fg"]) if s else None)


def style_status(v):
    return _cell(STATUS_STYLE.get(v))


def style_flag(v):
    return _cell(("#f7d4d4", "#8a1f1f") if v else None)


def user_ids():
    directory = api_client_get_quiet("/directory")
    return [u["user_id"] for u in directory["users"]] if directory else FALLBACK_USERS


def api_client_get_quiet(path, **params):
    try:
        return api_client.get(path, **params)
    except api_client.ApiError:
        return None


# Banner and sidebar status ----------------------------------------------------------

@st.fragment(run_every=REFRESH_SECONDS)
def warden_banner():
    health = api_client_get_quiet("/health")
    if health and health["warden_mode"] == "off":
        st.error("## WARDEN IS OFF\nEvery tool call the agent proposes will run with no policy and no judge. "
                 "Use this only for the baseline comparison.")


@st.fragment(run_every=REFRESH_SECONDS)
def health_status():
    health = api_client_get_quiet("/health")
    if health is None:
        st.badge("API unreachable", color="red", icon=":material/cloud_off:")
        return
    st.badge("API ok" if health["db"] else "Database error", color="green" if health["db"] else "red")
    st.badge(f"Policy loaded ({health['policy_rules']} rules)" if health["policy_loaded"] else "Policy NOT loaded",
             color="green" if health["policy_loaded"] else "red")
    gemini = health["gemini"]
    st.badge("Gemini reachable" if gemini["reachable"] else "Gemini unreachable",
             color="green" if gemini["reachable"] else "red")
    st.caption(f"Agents running: {health['running_agents']}")
    if not health["demo_mode"]:
        st.caption("Demo controls are disabled: start the API with DEMO_MODE=1.")


# Live feed ---------------------------------------------------------------------

def _load_demo_ticket():
    demo = DEMO_BY_LABEL.get(st.session_state.get("demo_choice"))
    if demo:
        st.session_state["f_requester"] = demo["requester"]
        st.session_state["f_subject"] = demo["subject"]
        st.session_state["f_body"] = demo["body"]


def new_ticket_form():
    with st.expander("New ticket", expanded=True):
        st.selectbox("Load demo ticket", ["(choose one)"] + [t["label"] for t in DEMO_TICKETS],
                     key="demo_choice", on_change=_load_demo_ticket)
        with st.form("new_ticket"):
            st.selectbox("Requester", user_ids(), key="f_requester")
            st.text_input("Subject", key="f_subject", max_chars=200)
            st.text_area("Body", key="f_body", height=170, max_chars=10000)
            submitted = st.form_submit_button("Submit ticket", type="primary")
        if submitted:
            try:
                status, body = api_client.post("/tickets", json={
                    "requester_id": st.session_state["f_requester"],
                    "subject": st.session_state["f_subject"],
                    "body": st.session_state["f_body"]})
            except api_client.ApiError as e:
                st.error(str(e))
                return
            if status == 202:
                st.session_state["selected_ticket"] = body["ticket_id"]
                st.success(f"Ticket {body['ticket_id']} submitted. The agent is working on it.")
            else:
                st.error(f"Could not submit the ticket: {body.get('detail', status)}")


@st.fragment(run_every=REFRESH_SECONDS)
def ticket_table():
    tickets = api_get("/tickets")
    if tickets is None:
        return
    if not tickets:
        st.info("No tickets yet. Submit one above.")
        return
    df = pd.DataFrame([{
        "Ticket": t["ticket_id"], "Requester": t["requester_id"], "Subject": t["subject"],
        "Status": t["status"], "Verdict": t["verdict"] or "", "Security": "FLAGGED" if t["security_flag"] else "",
        "Actions": t["action_count"], "Warden": (t["warden_mode"] or "").upper(), "Updated": t["updated_at"],
    } for t in tickets])
    styled = (df.style.map(style_status, subset=["Status"]).map(style_verdict, subset=["Verdict"])
              .map(style_flag, subset=["Security"]))
    st.dataframe(styled, hide_index=True, width="stretch")
    left, right = st.columns([4, 1], vertical_alignment="bottom")
    pick = left.selectbox("Inspect ticket", [t["ticket_id"] for t in tickets], key="live_pick")
    if right.button("Open detail"):
        st.session_state["selected_ticket"] = pick
        st.session_state["nav"] = "Ticket detail"
        st.rerun()


def live_feed():
    st.header("Live feed")
    new_ticket_form()
    ticket_table()


# Ticket detail -----------------------------------------------------------------

def _stepper(stages):
    cols = st.columns(len(stages))
    for i, (col, stage) in enumerate(zip(cols, stages), start=1):
        label, color, icon = STAGE_STYLE[stage["state"]]
        with col:
            st.markdown(f"**{i}. {stage['name']}**")
            st.badge(label, color=color, icon=icon)
            st.caption(stage["detail"])


def _judge_column(a):
    st.markdown("**Judge**")
    if a["warden_mode"] == "off":
        st.text("Not run: Warden was off.")
    elif a["judge_verdict"]:
        verdict_badge(a["judge_verdict"])
        st.text(f"Risk score: {a['judge_risk_score']}/100")
        if a["judge_indicators"]:
            st.text("Indicators: " + ", ".join(a["judge_indicators"]))
        st.text(a["judge_reason"] or "")
    elif a["decided_by"] == "judge_unavailable":
        st.badge("Unavailable", color="orange", icon=":material/cloud_off:")
        st.text("The judge could not be reached in time.")
    elif a["decided_by"] == "judge_invalid":
        st.badge("Invalid output", color="red", icon=":material/error:")
        st.text("The judge answered with invalid output.")
    else:
        st.text("Not run: policy had already decided.")


def _action_card(n, a):
    with st.container(border=True):
        st.text(f"Action {n}: {a['description']}")
        policy, judge, final, timing = st.columns(4)
        with policy:
            st.markdown("**Policy**")
            if a["policy_verdict"]:
                verdict_badge(a["policy_verdict"])
                st.text(f"Rule: {', '.join(a['policy_rule_ids'])}")
                st.text(a["policy_reason"] or "")
            else:
                st.text("Not run: Warden was off.")
        with judge:
            _judge_column(a)
        with final:
            st.markdown("**Final verdict**")
            verdict_badge(a["final_verdict"], label=(a["final_verdict"] or "No verdict").replace("_", " "))
            st.text(f"Status: {a['status']}")
            st.text(f"Reason: {a['reason'] or '-'}")
        with timing:
            st.markdown("**Timing**")
            st.text(f"Total: {a['latency_ms']} ms" if a["latency_ms"] is not None else "Total: -")
            if a["judge_latency_ms"] is not None:
                st.text(f"Judge: {a['judge_latency_ms']} ms")
            st.text(f"Warden: {a['warden_mode']}")


@st.fragment(run_every=REFRESH_SECONDS)
def ticket_detail_body(ticket_id):
    d = api_get(f"/tickets/{ticket_id}")
    if d is None:
        return
    t = d["ticket"]
    top = st.columns([1, 1, 4])
    with top[0]:
        st.badge(t["status"].replace("_", " "), color={"RESOLVED": "green", "ESCALATED": "orange",
                                                       "PENDING_APPROVAL": "orange", "IN_PROGRESS": "blue"}.get(t["status"], "gray"))
    with top[1]:
        if t["security_flag"]:
            st.badge("Security flag", color="red", icon=":material/flag:")
    with top[2]:
        r = t["requester"]
        st.caption(f"Requester (from the directory): {r['name']} ({r['user_id']}), {r['role']}, {r['department']}"
                   if r else "Requester unknown")

    st.markdown("##### Progress")
    _stepper(d["stages"])

    st.markdown("##### Ticket text")
    st.caption("UNTRUSTED. Written by the requester. Warden never takes instructions or identity from it.")
    with st.container(border=True):
        st.code(f"Subject: {t['subject']}\n\n{t['body']}", language=None, wrap_lines=True)

    st.markdown("##### Actions")
    if not d["actions"]:
        st.caption("No actions proposed yet.")
    for n, a in enumerate(d["actions"], start=1):
        _action_card(n, a)

    if t["resolution_note"]:
        st.markdown("##### Note on the ticket")
        st.text(t["resolution_note"])

    for ap in d["approvals"]:
        st.text(f"Approval #{ap['approval_id']}: {ap['status']}, approver {ap['approver_id']}, "
                f"expires {ap['expires_at']} UTC")

    with st.expander(f"Audit events ({len(d['audit_events'])})"):
        st.dataframe(pd.DataFrame([{
            "#": e["id"], "Time (UTC)": e["ts"], "Event": e["event_type"], "Actor": e["actor"],
            "Details": json.dumps(e["payload"], default=str)} for e in d["audit_events"]]),
            hide_index=True, width="stretch")


def ticket_detail():
    st.header("Ticket detail")
    tickets = api_get("/tickets")
    if not tickets:
        if tickets is not None:
            st.info("No tickets yet.")
        return
    ids = [t["ticket_id"] for t in tickets]
    selected = st.session_state.get("selected_ticket")
    index = ids.index(selected) if selected in ids else 0
    pick = st.selectbox("Ticket", ids, index=index)
    st.session_state["selected_ticket"] = pick
    ticket_detail_body(pick)


# Approvals ---------------------------------------------------------------------

def _decide(approval_id, decision):
    approver = st.session_state[f"appr_{approval_id}"]
    comment = st.session_state.get(f"cmt_{approval_id}") or None
    try:
        status, body = api_client.post(f"/approvals/{approval_id}/{decision}",
                                       json={"approver_id": approver, "comment": comment})
    except api_client.ApiError as e:
        st.session_state["flash"] = ("error", str(e))
        return
    st.session_state["flash"] = ("success" if status == 200 and body.get("ok") else "error",
                                 f"Approval #{approval_id} ({approver}): {body.get('message') or body.get('detail')}")


def _why(a):
    if a["decided_by"] == "judge":
        return a["judge_reason"] or "The judge asked for a human decision."
    if a["decided_by"] == "judge_unavailable":
        return "The judge was unavailable, so a human has to decide."
    return a["policy_reason"] or ""


@st.fragment(run_every=REFRESH_SECONDS)
def approvals_body():
    flash = st.session_state.pop("flash", None)
    if flash:
        (st.success if flash[0] == "success" else st.error)(flash[1])
    pending = api_get("/approvals")
    if pending is None:
        return
    users = user_ids()
    if not pending:
        st.info("No pending approvals.")
    for a in pending:
        with st.container(border=True):
            st.text(a["description"])
            st.caption(f"Ticket {a['ticket_id']} - requested by {a['requester_name']} ({a['requester_id']}) - "
                       f"approver on record: {a['approver_name']} ({a['approver_id']}) - expires {a['expires_at']} UTC")
            st.text(f"Why approval is needed: {_why(a)}")
            if a["judge_risk_score"] is not None:
                risk = a["judge_risk_score"]
                st.badge(f"Judge risk {risk}/100", color="red" if risk >= 70 else "orange" if risk >= 40 else "green")
            c1, c2, c3, c4 = st.columns([2, 3, 1, 1], vertical_alignment="bottom")
            default = users.index(a["approver_id"]) if a["approver_id"] in users else 0
            c1.selectbox("Decide as", users, index=default, key=f"appr_{a['approval_id']}")
            c2.text_input("Comment (optional)", key=f"cmt_{a['approval_id']}", max_chars=500)
            c3.button("Approve", key=f"approve_{a['approval_id']}", type="primary", on_click=_decide,
                      args=(a["approval_id"], "approve"))
            c4.button("Deny", key=f"deny_{a['approval_id']}", on_click=_decide, args=(a["approval_id"], "deny"))

    decided = [a for a in (api_get("/approvals", status="all") or []) if a["status"] != "PENDING"]
    if decided:
        with st.expander(f"Decided approvals ({len(decided)})"):
            st.dataframe(pd.DataFrame([{
                "#": a["approval_id"], "Ticket": a["ticket_id"], "Action": a["description"], "Status": a["status"],
                "Approver": a["approver_id"], "Decided (UTC)": a["decided_at"], "Comment": a["comment"] or ""}
                for a in decided]), hide_index=True, width="stretch")


def approvals():
    st.header("Approvals")
    st.caption("Only the approver named on the request can decide it, and never the requester. "
               "Pick someone else in the dropdown to see Warden refuse.")
    approvals_body()


# Directory ---------------------------------------------------------------------

@st.fragment(run_every=REFRESH_SECONDS)
def directory_body():
    d = api_get("/directory")
    if d is None:
        return
    st.subheader("Groups")
    for g in d["groups"]:
        extras = [m for m in g["members"] if m != g["owner_id"]] if g["privileged"] else []
        with st.container(border=True):
            head = st.columns([2, 5])
            head[0].text(g["group_name"])
            with head[1]:
                if g["privileged"]:
                    st.badge("PRIVILEGED", color="red", icon=":material/shield:")
                else:
                    st.badge("standard", color="gray")
            st.text(f"Owner: {g['owner_id']}   Members: {', '.join(g['members']) or '(none)'}")
            if extras:
                st.error(f"Unexpected member(s) of {g['group_name']}: {', '.join(extras)}")
    left, right = st.columns(2)
    with left:
        st.subheader("Installs")
        denied = {p["package"] for p in d["software_catalogue"] if p["status"] == "denied"}
        installs = pd.DataFrame(d["installs"], columns=["device_id", "package", "installed_at"])
        if installs.empty:
            st.caption("Nothing installed by the service desk yet.")
        else:
            st.dataframe(installs.style.map(lambda v: _cell(("#f7d4d4", "#8a1f1f")) if v in denied else "",
                                            subset=["package"]), hide_index=True, width="stretch")
    with right:
        st.subheader("Services")
        st.dataframe(pd.DataFrame(d["services"]), hide_index=True, width="stretch")
    with st.expander("Users, devices and software catalogue"):
        st.dataframe(pd.DataFrame(d["users"]), hide_index=True, width="stretch")
        st.dataframe(pd.DataFrame(d["devices"]), hide_index=True, width="stretch")
        st.dataframe(pd.DataFrame(d["software_catalogue"]), hide_index=True, width="stretch")


def directory():
    st.header("Directory")
    directory_body()


# Metrics -----------------------------------------------------------------------

VERDICT_ORDER = ["ALLOW", "REQUIRE_APPROVAL", "BLOCK"]


def verdict_frame(verdicts):
    return pd.DataFrame({"Verdict": [v.replace("_", " ").title() for v in VERDICT_ORDER],
                         "Actions": [verdicts[v] for v in VERDICT_ORDER]})


def verdict_chart_spec():
    """Bar per verdict. Colors are tied to labels explicitly: Vega would otherwise sort the domain
    alphabetically and swap warning and critical. The x axis names every bar, so color is never alone."""
    labels = [v.replace("_", " ").title() for v in VERDICT_ORDER]
    return {
        "mark": {"type": "bar", "cornerRadiusEnd": 4, "size": 56},
        "encoding": {
            "x": {"field": "Verdict", "type": "nominal", "sort": labels, "axis": {"labelAngle": 0, "title": None}},
            "y": {"field": "Actions", "type": "quantitative", "axis": {"tickMinStep": 1}},
            "color": {"field": "Verdict", "type": "nominal", "legend": None,
                      "scale": {"domain": labels, "range": [VERDICT_STYLE[v]["hex"] for v in VERDICT_ORDER]}},
            "tooltip": [{"field": "Verdict", "type": "nominal"}, {"field": "Actions", "type": "quantitative"}],
        },
    }


@st.fragment(run_every=REFRESH_SECONDS)
def metrics_body():
    m = api_get("/metrics")
    if m is None:
        return
    by_status = m["tickets_by_status"]
    rate = m["auto_resolution_rate"]
    judge = m["judge_latency"]
    row1 = st.columns(4)
    row1[0].metric("Tickets", sum(by_status.values()))
    row1[1].metric("Auto-resolved", "n/a" if rate is None else f"{rate:.0%}",
                   help="Resolved with no human approval, as a share of all tickets.")
    row1[2].metric("Attacks blocked", m["attacks_blocked"], help="Actions refused by policy or the judge (Warden on).")
    row1[3].metric("Security flags", m["security_flags"])
    row2 = st.columns(4)
    row2[0].metric("Judge median", "n/a" if judge["median_ms"] is None else f"{judge['median_ms']:.0f} ms")
    row2[1].metric("Judge p95", "n/a" if judge["p95_ms"] is None else f"{judge['p95_ms']:.0f} ms")
    row2[2].metric("Judge calls", judge["count"])
    row2[3].metric("Warden", m["warden_mode"].upper())

    st.subheader("Verdicts")
    st.vega_lite_chart(verdict_frame(m["verdicts"]), verdict_chart_spec(), width="stretch")
    with st.expander("Table view"):
        st.dataframe(verdict_frame(m["verdicts"]), hide_index=True)

    st.subheader("Tickets by status")
    cols = st.columns(len(by_status))
    for col, (status, n) in zip(cols, by_status.items()):
        col.metric(status.replace("_", " ").title(), n)

    st.subheader("Who stopped or paused actions")
    split = pd.DataFrame([{"Decided by": who.replace("_", " "), "Blocked": c["BLOCK"],
                           "Sent to approval": c["REQUIRE_APPROVAL"]} for who, c in m["catch_split"].items()])
    st.dataframe(split, hide_index=True)


def metrics():
    st.header("Metrics")
    metrics_body()


# Red team ----------------------------------------------------------------------

def red_team():
    st.header("Red team")
    st.info("The attack/benign evaluation (Warden off vs on) arrives in milestone 8. "
            "Until then, the demo tickets in the Live feed cover the main attack types.")


PAGES = {
    "Live feed": live_feed, "Ticket detail": ticket_detail, "Approvals": approvals,
    "Directory": directory, "Metrics": metrics, "Red team": red_team,
}
