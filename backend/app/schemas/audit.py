from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AuditEvent(BaseModel):
    id: str
    seq: int
    ts: str
    actor: str
    actor_role: str | None
    tenant: str
    event_type: str
    resource_type: str
    resource_id: str | None
    request_id: str | None
    details: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str
    hash: str


class ChainVerification(BaseModel):
    valid: bool
    checked: int
    head_hash: str | None
    first_invalid_seq: int | None = None
    reason: str | None = None
    note: str = (
        "Hash chaining detects modification or deletion of individual records by anyone who cannot "
        "also recompute every later hash. It does not make the database tamper-proof against an "
        "attacker with write access to the whole store; anchor the head hash externally for that."
    )
