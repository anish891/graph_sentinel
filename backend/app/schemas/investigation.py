from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from app.schemas.actions import RecommendedAction
from app.schemas.common import ENTITY_ID_PATTERN, Ref, StrictModel
from app.schemas.evidence import EvidenceItem
from app.schemas.graph import GraphPayload
from app.schemas.risk import RiskAssessment, Verdict

InvestigationStatus = Literal["queued", "running", "completed", "inconclusive", "failed"]


class InvestigationRequest(StrictModel):
    question: str = Field(min_length=3, max_length=2000)
    target_id: str | None = Field(
        default=None,
        pattern=ENTITY_ID_PATTERN,
        description="Alert or entity id. If omitted, a single alert id must appear in the question.",
    )


class ProviderInfo(BaseModel):
    name: str
    model: str
    is_mock: bool
    api: str | None = None


class Finding(BaseModel):
    id: str
    kind: Literal["observed_fact", "inference", "hypothesis"]
    statement: str
    refs: list[Ref]
    origin: Literal["graph", "deterministic_analysis", "model"]
    confidence: float | None = Field(default=None, ge=0, le=1)


class UnsupportedClaim(BaseModel):
    statement: str
    reason: str


class ToolCallRecord(BaseModel):
    id: str
    seq: int
    tool: str
    arguments: dict[str, Any]
    status: Literal["ok", "error", "rejected"]
    error: str | None = None
    summary: str
    origin: Literal["llm", "orchestrator_baseline"]
    rationale: str | None = None
    executed_in: str | None = None
    duration_ms: float
    result_hash: str | None = None
    node_ids: list[str] = Field(default_factory=list)
    path_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class Narrative(BaseModel):
    deterministic: str = Field(description="Generated from graph paths by code, not by the model")
    model_summary: str | None = Field(
        default=None, description="Model-written summary. Untrusted; claims are validated separately."
    )


class InvestigationStats(BaseModel):
    steps: int = 0
    tool_calls: int = 0
    rejected_tool_calls: int = 0
    llm_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    duration_ms: float = 0
    limits_hit: list[str] = Field(default_factory=list)


class InvestigationResult(BaseModel):
    id: str
    tenant: str
    status: InvestigationStatus
    question: str
    target_id: str
    target_label: str | None = None
    requested_by: str
    created_at: str
    completed_at: str | None = None
    provider: ProviderInfo
    verdict: Verdict | None = None
    risk: RiskAssessment | None = None
    findings: list[Finding] = Field(default_factory=list)
    unsupported_claims: list[UnsupportedClaim] = Field(default_factory=list)
    supporting_evidence: list[EvidenceItem] = Field(default_factory=list)
    contradicting_evidence: list[EvidenceItem] = Field(default_factory=list)
    narrative: Narrative | None = None
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    graph: GraphPayload = Field(default_factory=GraphPayload)
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    prior_investigations: list[dict[str, Any]] = Field(default_factory=list)
    stats: InvestigationStats = Field(default_factory=InvestigationStats)
    error: str | None = None
    trace_head_hash: str | None = None
    synthetic_data: bool = True


class InvestigationSummary(BaseModel):
    id: str
    status: InvestigationStatus
    question: str
    target_id: str
    requested_by: str
    created_at: str
    completed_at: str | None
    verdict: Verdict | None
    risk_score: int | None
    risk_band: str | None
    provider_name: str
    provider_is_mock: bool


class TraceEvent(BaseModel):
    id: str
    investigation_id: str
    seq: int
    ts: str
    kind: str
    payload: dict[str, Any]
    prev_hash: str
    hash: str


class TraceIntegrity(BaseModel):
    valid: bool
    checked_events: int
    head_hash: str | None
    reason: str | None = None


class InvestigationTrace(BaseModel):
    investigation_id: str
    events: list[TraceEvent]
    integrity: TraceIntegrity
