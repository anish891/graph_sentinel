"""Risk model configuration. Weights are expert heuristics — NOT a calibrated statistical model."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field, model_validator

FACTOR_KEYS = (
    "alert_severity",
    "evidence_strength",
    "compromise_signal",
    "threat_intel",
    "asset_criticality",
    "exploitable_vulnerability",
    "historical_incidents",
    "path_proximity",
)


class RiskWeights(BaseModel):
    version: str = "weights-2026.10.1"
    weights: dict[str, float] = Field(
        default_factory=lambda: {
            "alert_severity": 0.15,
            "evidence_strength": 0.20,
            "compromise_signal": 0.15,
            "threat_intel": 0.10,
            "asset_criticality": 0.15,
            "exploitable_vulnerability": 0.10,
            "historical_incidents": 0.10,
            "path_proximity": 0.05,
        }
    )
    # Fraction of the score removed at full contradiction strength (1.0).
    contradiction_weight: float = Field(default=0.5, ge=0, le=1)
    evidence_half_life_days: float = Field(default=30, gt=0)
    indicator_half_life_days: float = Field(default=90, gt=0)
    incident_half_life_days: float = Field(default=365, gt=0)
    indirect_incident_weight: float = Field(default=0.25, ge=0, le=1)
    direct_incident_max_hops: int = Field(default=3, ge=1, le=6)
    band_thresholds: dict[str, int] = Field(default_factory=lambda: {"medium": 25, "high": 50, "critical": 75})

    @model_validator(mode="after")
    def _check(self) -> RiskWeights:
        if set(self.weights) != set(FACTOR_KEYS):
            raise ValueError(f"weights must define exactly: {FACTOR_KEYS}")
        if any(w < 0 for w in self.weights.values()):
            raise ValueError("weights must be non-negative")
        total = sum(self.weights.values())
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"weights must sum to 1.0 (got {total:.4f})")
        b = self.band_thresholds
        if not (0 < b["medium"] < b["high"] < b["critical"] <= 100):
            raise ValueError("band thresholds must satisfy 0 < medium < high < critical <= 100")
        return self


@lru_cache(maxsize=4)
def load_weights(path: str | None) -> RiskWeights:
    if not path:
        return RiskWeights()
    return RiskWeights.model_validate(json.loads(Path(path).read_text(encoding="utf-8")))
