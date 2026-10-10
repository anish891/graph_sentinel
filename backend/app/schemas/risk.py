from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.common import Ref

RiskBand = Literal["low", "medium", "high", "critical"]
Verdict = Literal["likely_malicious", "suspicious", "likely_benign", "inconclusive"]


class RiskFactor(BaseModel):
    key: str
    label: str
    weight: float
    value: float = Field(ge=0, le=1)
    contribution: float
    explanation: str
    refs: list[Ref] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    method: str = "deterministic-weighted-sum-v1"
    weights_version: str
    calibrated: bool = Field(
        default=False, description="Always false: weights are expert heuristics, not a calibrated model."
    )
    as_of: str
    raw_score: float = Field(ge=0, le=1, description="Weighted sum before contradiction penalty")
    contradiction_strength: float = Field(ge=0, le=1)
    contradiction_penalty: float = Field(ge=0, le=1)
    score: int = Field(ge=0, le=100)
    band: RiskBand
    factors: list[RiskFactor]
    confidence: float = Field(ge=0, le=1)
    confidence_band: Literal["low", "medium", "high"]
    uncertainty_notes: list[str] = Field(default_factory=list)
    verdict: Verdict
    verdict_reason: str
