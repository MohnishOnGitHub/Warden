"""Shared types. Pydantic models for the API arrive in milestone 7."""
from dataclasses import dataclass
from enum import StrEnum


class ActionStatus(StrEnum):
    """Every value actions.status can hold. Use this, never a bare string."""
    EXECUTED = "EXECUTED"                  # allowed by Warden and run
    BLOCKED = "BLOCKED"                    # refused by Warden, nothing ran
    PENDING_APPROVAL = "PENDING_APPROVAL"  # queued, waiting for a human
    APPROVED_EXECUTED = "APPROVED_EXECUTED"  # approved by a human and run once
    DENIED = "DENIED"                      # human said no
    EXPIRED = "EXPIRED"                    # approval timed out
    FAILED = "FAILED"                      # the tool raised while running


@dataclass(frozen=True)
class Decision:
    """What warden.handle() hands back to the agent loop.

    status is what the agent is told: executed, pending_approval or blocked.
    verdict and rule_id are internal (logs, dashboard, tests) and never reach the agent.
    """
    status: str
    tool: str
    action_id: int | None = None
    result: dict | None = None
    reason: str | None = None
    verdict: str | None = None
    rule_id: str | None = None
    approver_id: str | None = None

    def for_agent(self):
        """The only view of a decision the agent may see: no rule ids, no scores."""
        if self.status == "executed":
            return {"status": "executed", "result": self.result}
        if self.status == "pending_approval":
            return {"status": "pending_approval"}
        return {"status": "blocked", "reason": self.reason}
