from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.agents.context import ImpactedAsset, InvestigationContext, VulnerabilityExposure
from app.policies.engine import PolicyEngine
from app.risk.engine import RiskEngine, noisy_or
from app.risk.weights import RiskWeights
from app.schemas.evidence import EvidenceItem
from app.schemas.graph import GraphEdge, GraphNode

AS_OF = datetime(2026, 10, 1, 12, tzinfo=UTC)


def node(nid: str, label: str, **props) -> GraphNode:
    return GraphNode(id=nid, label=label, labels=[label], display_name=nid, properties=props)


def ev(
    eid: str,
    stance: str,
    target: str,
    conf: float = 0.8,
    fresh: float = 1.0,
    kind: str = "auth_log",
    source: str | None = None,
    excluded: bool = False,
    observed: str = "2026-09-30T12:00:00Z",
) -> EvidenceItem:
    return EvidenceItem(
        id=eid,
        kind=kind,
        source_system=source or f"src-{eid}",
        source_ref="r",
        observed_at=observed,
        summary="s",
        claim="c",
        confidence=conf,
        stance=stance,
        target_id=target,
        target_label="SecurityAlert",
        freshness=fresh,
        excluded_from_scoring=excluded,
    )


def ctx_with_alert(severity: str = "high") -> InvestigationContext:
    ctx = InvestigationContext("inv", "acme", "q", "ALT-1", AS_OF, 5)
    alert = node("ALT-1", "SecurityAlert", severity=severity)
    ctx.target = alert
    ctx.nodes[alert.id] = alert
    return ctx


def test_noisy_or_bounds() -> None:
    assert noisy_or([]) == 0
    assert noisy_or([1.0, 0.2]) == 1.0
    assert noisy_or([0.5, 0.5]) == pytest.approx(0.75)
    assert noisy_or([-1, 2]) == 1.0


def test_weights_must_sum_to_one() -> None:
    w = RiskWeights().weights
    with pytest.raises(ValidationError):
        RiskWeights(weights={**w, "alert_severity": 0.5})
    with pytest.raises(ValidationError):
        RiskWeights(weights={k: v for k, v in w.items() if k != "path_proximity"})
    with pytest.raises(ValidationError):
        RiskWeights(band_thresholds={"medium": 60, "high": 50, "critical": 75})


def test_no_evidence_is_inconclusive_and_score_bounded() -> None:
    r = RiskEngine(RiskWeights()).evaluate(ctx_with_alert("critical"))
    assert r.verdict == "inconclusive"
    assert 0 <= r.score <= 100
    assert r.calibrated is False
    assert abs(sum(f.weight for f in r.factors) - 1.0) < 1e-9


def test_band_boundaries() -> None:
    e = RiskEngine(RiskWeights())
    assert [e.band(s) for s in (0, 24, 25, 49, 50, 74, 75, 100)] == [
        "low",
        "low",
        "medium",
        "medium",
        "high",
        "high",
        "critical",
        "critical",
    ]


def test_same_source_not_double_counted() -> None:
    ctx = ctx_with_alert()
    for i in range(5):
        ctx.evidence[f"E{i}"] = ev(f"E{i}", "supports", "ALT-1", conf=0.5, source="siem")
    one = RiskEngine(RiskWeights()).evaluate(ctx)
    f = next(x for x in one.factors if x.key == "evidence_strength")
    assert f.value == pytest.approx(0.5)  # five records from one source == one record


def test_independent_sources_increase_strength() -> None:
    ctx = ctx_with_alert()
    ctx.evidence["A"] = ev("A", "supports", "ALT-1", conf=0.5, source="siem")
    ctx.evidence["B"] = ev("B", "supports", "ALT-1", conf=0.5, source="edr", kind="edr_telemetry")
    r = RiskEngine(RiskWeights()).evaluate(ctx)
    assert next(x for x in r.factors if x.key == "evidence_strength").value == pytest.approx(0.75)


def test_contradiction_reduces_score_and_excluded_evidence_ignored() -> None:
    ctx = ctx_with_alert()
    ctx.evidence["A"] = ev("A", "supports", "ALT-1", conf=0.9)
    base = RiskEngine(RiskWeights()).evaluate(ctx).score
    ctx.evidence["INJ"] = ev("INJ", "contradicts", "ALT-1", conf=1.0, excluded=True)
    assert RiskEngine(RiskWeights()).evaluate(ctx).score == base  # injection-flagged has no effect
    ctx.evidence["C"] = ev("C", "contradicts", "ALT-1", conf=0.8)
    r = RiskEngine(RiskWeights()).evaluate(ctx)
    assert r.score < base and r.contradiction_penalty == pytest.approx(0.5 * 0.8)


def test_stale_contradiction_on_vulnerability_superseded() -> None:
    ctx = ctx_with_alert()
    ctx.evidence["A"] = ev("A", "supports", "ALT-1")
    vuln = node("v1", "Vulnerability", cvss=9.0, exploit_available=True)
    asset = node("s1", "Service", criticality="high")
    ctx.nodes.update({"v1": vuln, "s1": asset})
    ctx.impacted["s1"] = ImpactedAsset(node=asset, relation="hosted_service", hops=2, path_id="p")
    ctx.vulnerabilities["s1:v1"] = VulnerabilityExposure(vulnerability=vuln, asset_id="s1", edge_id="e", status="open")
    ctx.evidence["SCAN"] = ev("SCAN", "supports", "v1", observed="2026-09-29T00:00:00Z", kind="vuln_scan")
    ctx.evidence["PATCH"] = ev("PATCH", "contradicts", "v1", observed="2026-09-20T00:00:00Z", kind="patch_record")
    r = RiskEngine(RiskWeights()).evaluate(ctx)
    assert next(x for x in r.factors if x.key == "exploitable_vulnerability").value == pytest.approx(0.9)
    assert any("superseded" in n for n in r.uncertainty_notes)
    ctx.evidence["PATCH"] = ev("PATCH", "contradicts", "v1", observed="2026-09-30T23:00:00Z", conf=1.0)
    r2 = RiskEngine(RiskWeights()).evaluate(ctx)
    assert next(x for x in r2.factors if x.key == "exploitable_vulnerability").value < 0.9


def test_upstream_dependents_not_counted_as_reachable() -> None:
    ctx = ctx_with_alert()
    crit = node("db", "Service", criticality="critical")
    ctx.impacted["db"] = ImpactedAsset(node=crit, relation="upstream_dependent", hops=1, path_id=None)
    r = RiskEngine(RiskWeights()).evaluate(ctx)
    assert next(x for x in r.factors if x.key == "asset_criticality").value == 0


def test_policy_inconclusive_proposes_only_investigation() -> None:
    ctx = ctx_with_alert("critical")
    w = RiskWeights()
    risk = RiskEngine(w).evaluate(ctx)
    acts = PolicyEngine(w).recommend(ctx, risk)
    assert [a.action_type.value for a in acts] == ["request_further_investigation"]
    assert not acts[0].consequential


def test_policy_isolation_requires_endpoint_evidence() -> None:
    ctx = ctx_with_alert("critical")
    dev = node("d1", "Device", criticality="high")
    ctx.nodes["d1"] = dev
    trig = GraphEdge(
        id="d1|TRIGGERED|ALT-1", type="TRIGGERED", source="d1", target="ALT-1", properties={"role": "host"}
    )
    ctx.edges[trig.id] = trig
    ctx.triggering = [(trig, dev)]
    for i, src in enumerate(["a", "b", "c", "d"]):
        ctx.evidence[f"E{i}"] = ev(f"E{i}", "supports", "ALT-1", conf=0.95, source=src)
    ctx.impacted["d1"] = ImpactedAsset(node=dev, relation="implicated_entity", hops=0, path_id=None)
    w = RiskWeights()
    risk = RiskEngine(w).evaluate(ctx)
    no_edr = [a.action_type.value for a in PolicyEngine(w).recommend(ctx, risk)]
    assert "isolate_endpoint" not in no_edr
    ctx.evidence["EDR"] = ev("EDR", "supports", "ALT-1", conf=0.95, kind="edr_telemetry", source="edr")
    risk2 = RiskEngine(w).evaluate(ctx)
    acts = PolicyEngine(w).recommend(ctx, risk2)
    if risk2.score >= 60:
        assert ("isolate_endpoint", "d1") in [(a.action_type.value, a.target_id) for a in acts]
    assert all(a.consequential for a in acts if a.action_type.value != "request_further_investigation")
