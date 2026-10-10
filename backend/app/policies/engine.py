"""Deterministic response policy.

The policy decides which response actions are *eligible* given graph evidence and the risk
assessment. The LLM has no input into eligibility. Every action proposed here is simulated
and, if consequential, must be approved by an authorised human (never the agent, never the
requester).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.agents.context import InvestigationContext
from app.risk.decay import freshness
from app.risk.engine import noisy_or
from app.risk.weights import RiskWeights
from app.schemas.actions import ActionType
from app.schemas.common import Ref
from app.schemas.risk import RiskAssessment

POLICY_VERSION = "policy-2026.10.1"

CONSEQUENTIAL = {
    ActionType.ISOLATE_ENDPOINT,
    ActionType.ROTATE_CREDENTIALS,
    ActionType.BLOCK_INDICATOR,
    ActionType.PATCH_SERVICE,
    ActionType.ESCALATE_INCIDENT,
}

TITLES = {
    ActionType.ISOLATE_ENDPOINT: "Isolate endpoint (simulated)",
    ActionType.ROTATE_CREDENTIALS: "Rotate credentials (simulated)",
    ActionType.BLOCK_INDICATOR: "Block indicator (simulated)",
    ActionType.PATCH_SERVICE: "Prioritise patching (simulated)",
    ActionType.ESCALATE_INCIDENT: "Escalate to incident (simulated)",
    ActionType.REQUEST_FURTHER_INVESTIGATION: "Request further investigation (simulated)",
}

# Rule thresholds — documented in docs/agent-design.md.
ISOLATE_MIN_SCORE = 60
ROTATE_MIN_SCORE = 50
BLOCK_MIN_SCORE = 50
ESCALATE_MIN_SCORE = 50
PATCH_MIN_SCORE = 25
PATCH_MIN_CVSS = 7.0
BLOCK_MIN_FRESHNESS = 0.5
BLOCK_MIN_CONFIDENCE = 0.7
STRONG_CONTRADICTION = 0.6


@dataclass
class ProposedAction:
    action_type: ActionType
    target_id: str
    target_label: str
    rule: str
    justification: str
    refs: list[Ref] = field(default_factory=list)

    @property
    def consequential(self) -> bool:
        return self.action_type in CONSEQUENTIAL


class PolicyEngine:
    version = POLICY_VERSION

    def __init__(self, weights: RiskWeights) -> None:
        self.w = weights

    def recommend(self, ctx: InvestigationContext, risk: RiskAssessment) -> list[ProposedAction]:
        out: list[ProposedAction] = []
        if ctx.target is None:
            return out
        score = risk.score
        usable = [e for e in ctx.evidence.values() if not e.excluded_from_scoring]
        supporting = [e for e in usable if e.stance == "supports"]
        strong_contradiction = risk.contradiction_strength >= STRONG_CONTRADICTION

        if risk.verdict == "inconclusive":
            out.append(
                ProposedAction(
                    ActionType.REQUEST_FURTHER_INVESTIGATION,
                    ctx.target_id,
                    ctx.target.label,
                    "P-INCONCLUSIVE",
                    f"Verdict inconclusive: {risk.verdict_reason} Collect endpoint telemetry and source logs before "
                    "any containment.",
                    [Ref(type="calculation", id="risk")],
                )
            )
            return out
        if risk.verdict == "likely_benign":
            # Benign verdicts propose nothing; closing the alert remains an analyst decision.
            return out

        # P-ISOLATE: endpoint with endpoint-telemetry evidence, high score, no strong contradiction.
        if score >= ISOLATE_MIN_SCORE:
            scope = ctx.related_alert_ids()
            for edge, node in _alert_hosts(ctx, scope):
                ev = [e for e in supporting if e.kind == "edr_telemetry" and e.target_id in (scope | {node.id})]
                if not ev:
                    continue
                if strong_contradiction:
                    continue
                out.append(
                    ProposedAction(
                        ActionType.ISOLATE_ENDPOINT,
                        node.id,
                        node.label,
                        "P-ISOLATE",
                        f"Risk {score} ≥ {ISOLATE_MIN_SCORE}; {node.display_name} triggered {edge.target} and endpoint "
                        f"telemetry ({', '.join(e.id for e in ev)}) supports compromise. Contradiction strength "
                        f"{risk.contradiction_strength:.2f} < {STRONG_CONTRADICTION}.",
                        [Ref(type="edge", id=edge.id), *[Ref(type="evidence", id=e.id) for e in ev]],
                    )
                )

        # P-ROTATE: identities that acted in the alert.
        if score >= ROTATE_MIN_SCORE:
            for edge, node in ctx.triggering:
                if node.label == "Identity" and edge.properties.get("role") == "actor":
                    out.append(
                        ProposedAction(
                            ActionType.ROTATE_CREDENTIALS,
                            node.id,
                            node.label,
                            "P-ROTATE",
                            f"Risk {score} ≥ {ROTATE_MIN_SCORE}; identity {node.display_name} is the actor of "
                            f"{ctx.target_id}" + (" (privileged)" if node.properties.get("privileged") else "") + ".",
                            [Ref(type="edge", id=edge.id)],
                        )
                    )

        # P-BLOCK: fresh, high-confidence, uncontradicted external indicators near the alert.
        if score >= BLOCK_MIN_SCORE:
            dist = ctx.distances()
            for n in ctx.nodes.values():
                if n.label != "Indicator" or dist.get(n.id, 99) > 3:
                    continue
                fr = freshness(n.properties.get("last_seen"), ctx.as_of, self.w.indicator_half_life_days) or 0.0
                conf = float(n.properties.get("confidence", 0))
                con = noisy_or([e.confidence for e in usable if e.stance == "contradicts" and e.target_id == n.id])
                if fr >= BLOCK_MIN_FRESHNESS and conf >= BLOCK_MIN_CONFIDENCE and con < 0.5:
                    ev = [e for e in supporting if e.target_id == n.id]
                    out.append(
                        ProposedAction(
                            ActionType.BLOCK_INDICATOR,
                            n.id,
                            n.label,
                            "P-BLOCK",
                            f"Indicator {n.properties.get('value')} confidence {conf}, freshness {fr:.2f} "
                            f"(≥ {BLOCK_MIN_FRESHNESS}), {dist[n.id]} hop(s) from the alert.",
                            [Ref(type="node", id=n.id), *[Ref(type="evidence", id=e.id) for e in ev]],
                        )
                    )

        # P-PATCH: exploitable open vulnerabilities on impacted assets.
        if score >= PATCH_MIN_SCORE:
            for v in ctx.vulnerabilities.values():
                p = v.vulnerability.properties
                if v.status == "open" and p.get("exploit_available") and float(p.get("cvss", 0)) >= PATCH_MIN_CVSS:
                    asset = ctx.impacted.get(v.asset_id)
                    out.append(
                        ProposedAction(
                            ActionType.PATCH_SERVICE,
                            v.asset_id,
                            asset.node.label if asset else "Service",
                            "P-PATCH",
                            f"{v.vulnerability.id} (CVSS {p.get('cvss')}, exploit available) is open on {v.asset_id}, "
                            f"which is in the blast radius ({asset.relation if asset else 'reachable'}).",
                            [Ref(type="node", id=v.vulnerability.id), Ref(type="edge", id=v.edge_id)]
                            + ([Ref(type="path", id=asset.path_id)] if asset and asset.path_id else []),
                        )
                    )

        if score >= ESCALATE_MIN_SCORE:
            out.append(
                ProposedAction(
                    ActionType.ESCALATE_INCIDENT,
                    ctx.target_id,
                    ctx.target.label,
                    "P-ESCALATE",
                    f"Risk {score} ({risk.band}) with verdict {risk.verdict}.",
                    [Ref(type="calculation", id="risk")],
                )
            )
        elif risk.verdict == "suspicious" or (strong_contradiction and score >= PATCH_MIN_SCORE):
            target = _best_followup_target(ctx)
            out.append(
                ProposedAction(
                    ActionType.REQUEST_FURTHER_INVESTIGATION,
                    target[0],
                    target[1],
                    "P-VERIFY",
                    f"Verdict {risk.verdict} at risk {score}; verify on the current asset before containment.",
                    [Ref(type="calculation", id="risk")],
                )
            )
        # de-duplicate on (type, target)
        seen: set[tuple[str, str]] = set()
        unique = []
        for a in out:
            key = (a.action_type.value, a.target_id)
            if key not in seen:
                seen.add(key)
                unique.append(a)
        return unique


def _alert_hosts(ctx: InvestigationContext, alert_ids: set[str]) -> list[tuple]:  # type: ignore[type-arg]
    hosts = []
    for e in ctx.edges.values():
        if e.type == "TRIGGERED" and e.target in alert_ids and e.source in ctx.nodes:
            node = ctx.nodes[e.source]
            if node.label == "Device":
                hosts.append((e, node))
    return hosts


def _best_followup_target(ctx: InvestigationContext) -> tuple[str, str]:
    devices = [a for a in ctx.impacted.values() if a.node.label == "Device"]
    if devices:
        best = sorted(devices, key=lambda a: a.hops)[0]
        return best.node.id, best.node.label
    assert ctx.target is not None
    return ctx.target_id, ctx.target.label
