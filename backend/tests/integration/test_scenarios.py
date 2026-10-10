"""The evaluation scenarios as tests (real FalkorDB, deterministic mock planner)."""

from __future__ import annotations

import pytest

from app.evaluation.scenarios import SCENARIOS, run_scenario

pytestmark = pytest.mark.graph


@pytest.mark.parametrize("key", [s[0] for s in SCENARIOS], ids=[f"{s[0]}-{s[2]}" for s in SCENARIOS])
async def test_scenario(harness, key: str) -> None:
    result = await run_scenario(harness, key)
    failed = [f"{c.name}: {c.detail}" for c in result.checks if not c.passed]
    assert result.error is None, result.error
    assert not failed, failed
    assert result.checks, "scenario performed no checks"
