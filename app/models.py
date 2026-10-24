"""Shared types: action statuses, the Decision handed back by Warden, and the API request bodies."""
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ActionStatus(StrEnum):
    """Every value actions.status can hold. Use this, never a bare string."""
    EXECUTED = "EXECUTED"                  # allowed by Warden and run
    BLOCKED = "BLOCKED"                    # refused by Warden, nothing ran
    PENDING_APPROVAL = "PENDING_APPROVAL"  # queued, waiting for a human
    APPROVED_EXECUTED = "APPROVED_EXECUTED"  # approved by a human and run once
    DENIED = "DENIED"                      # human said no
    EXPIRED = "EXPIRED"                    # approval timed out
    FAILED = "FAILED"                      # the tool raised while running
    DOWNGRADED = "DOWNGRADED"              # resolve_ticket replaced by escalate_to_human: completion check failed


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
    decided_by: str | None = None  # policy | judge | judge_unavailable | judge_invalid (internal)
    judge: dict | None = None     # judge verdict, risk, indicators, reason (internal, never shown to the agent)

    def for_agent(self):
        """The only view of a decision the agent may see: no rule ids, no scores."""
        if self.status == "executed":
            return {"status": "executed", "result": self.result}
        if self.status == "pending_approval":
            return {"status": "pending_approval"}
        return {"status": "blocked", "reason": self.reason}


# API request bodies (milestone 7). Extra fields are rejected, so a client cannot smuggle in anything.

class RequestBase(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TicketCreate(RequestBase):
    requester_id: str = Field(min_length=1, max_length=64)
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=10000)


class ApprovalDecision(RequestBase):
    approver_id: str = Field(min_length=1, max_length=64)
    comment: str | None = Field(default=None, max_length=500)


class WardenModeBody(RequestBase):
    mode: Literal["on", "off"]
