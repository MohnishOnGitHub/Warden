"""Warden dashboard. Run from the repo root:  streamlit run dashboard/app.py

It talks only to the API (WARDEN_API_URL, default http://127.0.0.1:8000).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st

from dashboard import api_client
from dashboard.pages import PAGES, health_status, warden_banner, warden_indicator_html, warden_state

st.set_page_config(page_title="Warden", layout="wide")


def set_warden_mode():
    """Toggle callback: ask the API to switch. The next run re-reads the real mode from /health."""
    mode = "on" if st.session_state["warden_toggle"] else "off"
    try:
        status, body = api_client.post("/admin/warden_mode", json={"mode": mode})
    except api_client.ApiError as e:
        st.session_state["sidebar_error"] = str(e)
        return
    if status != 200:
        st.session_state["sidebar_error"] = str(body.get("detail", status))


def sidebar():
    st.sidebar.title("Warden")
    nav = st.session_state.get("nav", "Live feed")
    # Changing `index` gives the radio a new identity, which is how a button elsewhere can switch page.
    choice = st.sidebar.radio("Page", list(PAGES), index=list(PAGES).index(nav))
    st.session_state["nav"] = choice
    st.sidebar.divider()

    try:
        health = api_client.get("/health")
    except api_client.ApiError:
        health = None
    demo = bool(health and health["demo_mode"])
    on = bool(health) and health["warden_mode"] == "on"
    st.sidebar.markdown(warden_indicator_html(warden_state(health)), unsafe_allow_html=True)
    st.session_state["warden_toggle"] = on
    label = "Warden protection: UNKNOWN" if health is None else f"Warden protection: {'ON' if on else 'OFF'}"
    st.sidebar.toggle(label, key="warden_toggle", on_change=set_warden_mode, disabled=not demo,
                      help="Off runs every tool call with no checks (the baseline). Needs DEMO_MODE=1.")
    error = st.session_state.pop("sidebar_error", None)
    if error:
        st.sidebar.error(error)

    if st.sidebar.button("Reset demo", disabled=not demo, help="Wipe tickets, approvals and the audit log."):
        try:
            status, body = api_client.post("/admin/reset")
        except api_client.ApiError as e:
            st.sidebar.error(str(e))
        else:
            if status == 200:
                st.session_state.pop("selected_ticket", None)
                st.sidebar.success("Demo reset.")
            else:
                st.sidebar.warning(str(body.get("detail", status)))
    st.sidebar.divider()
    with st.sidebar:
        health_status()
    return choice


choice = sidebar()
warden_banner()
PAGES[choice]()
