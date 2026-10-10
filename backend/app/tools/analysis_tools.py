"""Deterministic analysis tools. They compute from the investigation context; the model only triggers them."""

from __future__ import annotations

from app.agents.context import InvestigationContext
from app.policies.engine import PolicyEngine
from app.risk.engine import RiskEngine
from app.risk.weights import load_weights
from app.tools.base import Tool, ToolArgs, ToolDeps, ToolOutput


class NoArgs(ToolArgs):
    pass


class EvaluateRiskTool(Tool[NoArgs]):
    name = "evaluate_risk"
    description = (
        "Compute the deterministic risk score from evidence gathered so far (weighted factors, "
        "contradiction penalty, uncertainty). The model must not produce its own score."
    )
    args_model = NoArgs

    async def run(self, args: NoArgs, ctx: InvestigationContext, deps: ToolDeps) -> ToolOutput:
        risk = RiskEngine(load_weights(deps.settings.risk_weights_file)).evaluate(ctx)
        ctx.analytics["interim_risk"] = risk.model_dump()
        return ToolOutput(
            summary=(
                f"Interim risk {risk.score} ({risk.band}), verdict {risk.verdict}, confidence {risk.confidence_band}."
            ),
            data={
                "score": risk.score,
                "band": risk.band,
                "verdict": risk.verdict,
                "factors": [{"key": f.key, "value": f.value, "contribution": f.contribution} for f in risk.factors],
                "uncertainty_notes": risk.uncertainty_notes[:8],
            },
            executed_in="application: deterministic risk engine",
        )


class RecommendResponseTool(Tool[NoArgs]):
    name = "recommend_response"
    description = (
        "Ask the deterministic policy engine which simulated response actions are eligible given the "
        "current evidence and risk. Proposals are not executed and require human approval."
    )
    args_model = NoArgs

    async def run(self, args: NoArgs, ctx: InvestigationContext, deps: ToolDeps) -> ToolOutput:
        weights = load_weights(deps.settings.risk_weights_file)
        risk = RiskEngine(weights).evaluate(ctx)
        actions = PolicyEngine(weights).recommend(ctx, risk)
        return ToolOutput(
            summary=f"{len(actions)} eligible simulated action(s) under {PolicyEngine.version}.",
            data={
                "policy_version": PolicyEngine.version,
                "actions": [{"type": a.action_type.value, "target_id": a.target_id, "rule": a.rule} for a in actions],
            },
            executed_in="application: deterministic policy engine",
        )
