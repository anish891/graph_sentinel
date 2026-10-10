"""Recency decay used for evidence, indicators and incidents (exponential half-life)."""

from __future__ import annotations

from datetime import datetime

from app.core.timeutil import age_days


def freshness(timestamp: str | None, as_of: datetime, half_life_days: float) -> float | None:
    """0..1 weight: 1.0 for 'now', 0.5 after one half-life. None when the timestamp is unknown."""
    age = age_days(timestamp, as_of)
    if age is None:
        return None
    return round(float(0.5 ** (age / half_life_days)), 4)
