from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.schemas.common import ENTITY_ID_PATTERN, Ref, StrictModel


class ActionType(StrEnum):
    ESCALATE_INCIDENT = "escalate_incident"
    REQUEST_FURTHER_INVESTIGATION = "request_further_investigation"
    ROTATE_CREDENTIALS = "rotate_credentials"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    BLOCK_INDICATOR = "block_indicator"
    PATCH_SERVICE = "patch_service"


class ActionStatus(StrEnum):
    PROPOSED = "proposed"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    EXECUTED_SIMULATION = "executed_simulation"
    REJECTED = "rejected"
    EXPIRED = "expired"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_STATUSES = frozenset(
    {
        ActionStatus.EXECUTED_SIMULATION,
        ActionStatus.REJECTED,
        ActionStatus.EXPIRED,
        ActionStatus.FAILED,
        ActionStatus.CANCELLED,
    }
)


class RecommendedAction(BaseModel):
    id: str
    investigation_id: str
    action_type: ActionType
    title: str
    target_id: str
    target_label: str
    status: ActionStatus
    consequential: bool
    requires_approval: bool
    policy_version: str
    policy_rule: str
    justification: str
    evidence_refs: list[Ref] = Field(default_factory=list)
    risk_score_at_proposal: int
    proposed_by: str
    proposed_at: str
    expires_at: str
    decided_by: str | None = None
    decided_at: str | None = None
    decision_comment: str | None = None
    executed_at: str | None = None
    execution_result: dict[str, Any] | None = None
    simulated: Literal[True] = True
    version: int = 1


class ApprovalRequest(StrictModel):
    """Approval must name the exact investigation and policy version the approver reviewed."""

    investigation_id: str = Field(pattern=ENTITY_ID_PATTERN)
    policy_version: str = Field(min_length=1, max_length=64)
    confirm: Literal[True] = Field(description="Must be true: explicit, deliberate confirmation.")
    comment: str | None = Field(default=None, max_length=1000)


class RejectRequest(StrictModel):
    investigation_id: str = Field(pattern=ENTITY_ID_PATTERN)
    policy_version: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=3, max_length=1000)


class CancelRequest(StrictModel):
    reason: str = Field(min_length=3, max_length=1000)
