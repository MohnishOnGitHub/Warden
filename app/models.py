"""Shared types. Pydantic models for the API arrive in milestone 7."""
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
