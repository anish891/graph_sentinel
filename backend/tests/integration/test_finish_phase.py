"""A model that keeps exploring is moved into a finish-only phase before the step limit."""

from __future__ import annotations

import pytest

from app.agents.llm.base import AgentDecision, DecisionRequest, FinishPayload, LLMProvider

pytestmark = pytest.mark.graph


class GreedyThenFinish(LLMProvider):
    name, model, is_mock, api = "greedy-test", "test", True, "none"

    def __init__(self) -> None:
        self.requests: list[DecisionRequest] = []

    async def decide(self, request: DecisionRequest) -> AgentDecision:
        self.requests.append(request)
        n = len(self.requests)
        if request.tools:  # keeps exploring while tools are offered
            return AgentDecision(
                kind="tool_call", call_id=f"g{n}", tool_name="get_alert", arguments={"alert_id": "ALT-1001"}
            )
        return AgentDecision(
            kind="finish", call_id=f"f{n}", finish=FinishPayload(summary="Finished within the reserved steps.")
        )


async def test_finish_phase_reserves_steps(harness) -> None:
    provider = GreedyThenFinish()
    harness.use_provider(lambda: provider)
    try:
        r = await harness.investigate("Investigate ALT-1001")
    finally:
        from app.agents.llm.mock import MockLLMProvider

        harness.use_provider(MockLLMProvider)
    assert r.narrative is not None and r.narrative.model_summary == "Finished within the reserved steps."
    offered_tools = [bool(q.tools) for q in provider.requests]
    assert offered_tools[-1] is False and all(offered_tools[:-1])
    assert len(provider.requests) <= harness.settings.agent_max_steps
    assert r.stats.tool_calls <= harness.settings.agent_max_steps - 2 + 5  # model calls + baseline
