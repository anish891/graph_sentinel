from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class EvidenceItem(BaseModel):
    """An Evidence record from the graph. `summary` is UNTRUSTED text and is never interpreted."""

    id: str
    kind: str
    source_system: str
    source_ref: str
    observed_at: str | None
    summary: str
    claim: str | None = None
    confidence: float = Field(ge=0, le=1)
    stance: Literal["supports", "contradicts"]
    target_id: str
    target_label: str
    freshness: float | None = Field(default=None, ge=0, le=1, description="0..1 recency weight at as_of")
    suspected_prompt_injection: bool = False
    injection_signals: list[str] = Field(default_factory=list)
    excluded_from_scoring: bool = False
    exclusion_reason: str | None = None
