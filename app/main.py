"""FastAPI routes. Run from the repo root:  DEMO_MODE=1 uvicorn app.main:app

There is no login in this simulation: approver_id comes from the request body. Keep the server on
127.0.0.1 (the uvicorn default).
"""
import asyncio
import logging
import os
import threading
import time
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse

from app import approvals, audit, eval_metrics, llm, views
from app.agent import run_ticket
from app.audit import log_event
from app.db import get_connection
from app.ingestion import create_ticket
from app.models import ApprovalDecision, TicketCreate, WardenModeBody
from app.seed import reset_in_place
from app.settings import SETTINGS
from app.warden import warden_mode
from app.warden.policy import POLICY

log = logging.getLogger("warden.api")

# Test hooks: tests replace these. None means "use the real Gemini".
agent_llm = None
gemini_ping = llm.ping


def open_conn():
    return get_connection()


def get_db():
    conn = open_conn()
    try:
        yield conn
    finally:
        conn.close()


# Agent runs ---------------------------------------------------------------------

RUNNING = set()  # ticket ids whose agent run has not finished yet
RUNNING_LOCK = threading.Lock()
AGENT_SLOTS = threading.BoundedSemaphore(SETTINGS.max_concurrent_agents)  # free-tier rate limits


def _escalate_after_crash(ticket_id, error):
    """An agent run died unexpectedly: fail closed by handing the ticket to a human."""
    conn = open_conn()
    try:
        with conn:
            conn.execute(
                "UPDATE tickets SET status = 'ESCALATED', resolution_note = ?, updated_at = datetime('now') "
                "WHERE ticket_id = ? AND status IN ('NEW', 'IN_PROGRESS')",
                ("The automated agent failed. A human will follow up.", ticket_id))
        log_event(conn, "agent_error", "agent", ticket_id, {"error": type(error).__name__})
    finally:
        conn.close()


def run_agent_task(ticket_id):
    try:
        with AGENT_SLOTS:
            conn = open_conn()
            try:
                run_ticket(conn, ticket_id, llm_fn=agent_llm)
            finally:
                conn.close()
    except Exception as e:
        log.error("agent run failed for %s: %s", ticket_id, type(e).__name__)
        try:
            _escalate_after_crash(ticket_id, e)
        except Exception:
            log.error("could not escalate %s after a crash", ticket_id)
    finally:
        with RUNNING_LOCK:
            RUNNING.discard(ticket_id)


# Expiry sweep -------------------------------------------------------------------

def sweep_once():
    """Expire overdue approvals. Returns the expired approval ids."""
    conn = open_conn()
    try:
        return approvals.expire_overdue(conn)
    finally:
        conn.close()


async def _sweeper():
    while True:
        await asyncio.sleep(SETTINGS.expiry_sweep_seconds)
        try:
            await asyncio.to_thread(sweep_once)
        except Exception as e:
            log.error("expiry sweep failed: %s", type(e).__name__)


@asynccontextmanager
async def lifespan(_app):
    task = asyncio.create_task(_sweeper())
    yield
    task.cancel()


app = FastAPI(title="Warden", lifespan=lifespan)


def demo_mode():
    return os.environ.get("DEMO_MODE") == "1"


def require_demo_mode():
    if not demo_mode():
        raise HTTPException(403, "Admin endpoints need DEMO_MODE=1.")


# Health -------------------------------------------------------------------------

_gemini_cache = {"at": 0.0, "value": None}
_gemini_lock = threading.Lock()


def gemini_status():
    """Cached for health_cache_seconds: the dashboard polls /health every 2 seconds."""
    with _gemini_lock:
        if _gemini_cache["value"] is None or time.monotonic() - _gemini_cache["at"] > SETTINGS.health_cache_seconds:
            try:
                gemini_ping()
                _gemini_cache["value"] = {"reachable": True, "error": None}
            except Exception as e:
                _gemini_cache["value"] = {"reachable": False, "error": type(e).__name__}
            _gemini_cache["at"] = time.monotonic()
        return _gemini_cache["value"]


@app.get("/health")
def health(conn=Depends(get_db)):
    try:
        conn.execute("SELECT 1 FROM users LIMIT 1").fetchone()
        db_ok = True
    except Exception:
        db_ok = False
    gemini = gemini_status()
    policy_ok = len(POLICY.rules) > 0
    return {
        "status": "ok" if db_ok and policy_ok and gemini["reachable"] else "degraded",
        "db": db_ok,
        "policy_loaded": policy_ok,
        "policy_rules": len(POLICY.rules),
        "gemini": gemini,
        "warden_mode": warden_mode(),
        "demo_mode": demo_mode(),
        "running_agents": len(RUNNING),
    }


# Tickets ------------------------------------------------------------------------

@app.post("/tickets", status_code=202)
def post_ticket(body: TicketCreate, background: BackgroundTasks, conn=Depends(get_db)):
    try:
        ticket_id = create_ticket(conn, body.requester_id, body.subject, body.body)
    except ValueError:
        raise HTTPException(404, f"Unknown requester: {body.requester_id}")
    with RUNNING_LOCK:
        RUNNING.add(ticket_id)
    background.add_task(run_agent_task, ticket_id)
    return {"ticket_id": ticket_id, "status": "NEW"}


@app.get("/tickets")
def get_tickets(conn=Depends(get_db)):
    return views.list_tickets(conn)


@app.get("/tickets/{ticket_id}")
def get_ticket(ticket_id: str, conn=Depends(get_db)):
    detail = views.ticket_detail(conn, ticket_id)
    if detail is None:
        raise HTTPException(404, f"Unknown ticket: {ticket_id}")
    return detail


# Approvals ----------------------------------------------------------------------

STATUS_CODES = {
    "executed": 200, "denied": 200, "failed": 200,
    "not_found": 404, "not_the_approver": 403, "self_approval": 403, "not_pending": 409, "expired": 409,
}


def _decision_response(result):
    return JSONResponse({"ok": result.ok, "status": result.status, "message": result.message},
                        status_code=STATUS_CODES.get(result.status, 400))


@app.get("/approvals")
def get_approvals(status: str = "pending", conn=Depends(get_db)):
    if status not in ("pending", "all"):
        raise HTTPException(422, "status must be 'pending' or 'all'")
    return views.list_approvals(conn, status="PENDING" if status == "pending" else None)


@app.post("/approvals/{approval_id}/approve")
def post_approve(approval_id: int, body: ApprovalDecision, conn=Depends(get_db)):
    return _decision_response(approvals.approve(conn, approval_id, body.approver_id, body.comment))


@app.post("/approvals/{approval_id}/deny")
def post_deny(approval_id: int, body: ApprovalDecision, conn=Depends(get_db)):
    return _decision_response(approvals.deny(conn, approval_id, body.approver_id, body.comment))


# Metrics and directory ------------------------------------------------------------

@app.get("/metrics")
def get_metrics(conn=Depends(get_db)):
    return {**audit.dashboard_metrics(conn), "warden_mode": warden_mode()}


@app.get("/directory")
def get_directory(conn=Depends(get_db)):
    return views.directory(conn)


@app.get("/eval/results")
def get_eval_results(conn=Depends(get_db)):
    """Evaluation summary (redteam/evaluate.py writes the results). {"available": false} until a run exists."""
    return eval_metrics.summarize(conn)


# Admin (DEMO_MODE=1 only) ---------------------------------------------------------

@app.post("/admin/warden_mode", dependencies=[Depends(require_demo_mode)])
def post_warden_mode(body: WardenModeBody, conn=Depends(get_db)):
    old = warden_mode()
    os.environ["WARDEN_MODE"] = body.mode  # process wide, in memory: a restart goes back to "on"
    log_event(conn, "warden_mode_changed", "admin", None, {"old": old, "new": body.mode})
    return {"warden_mode": body.mode}


@app.post("/admin/reset", dependencies=[Depends(require_demo_mode)])
def post_reset(conn=Depends(get_db)):
    with RUNNING_LOCK:
        if RUNNING:
            raise HTTPException(409, f"Agent runs are still in progress: {sorted(RUNNING)}")
        reset_in_place(conn)
    log_event(conn, "demo_reset", "admin", None, {})
    return {"reset": True}
