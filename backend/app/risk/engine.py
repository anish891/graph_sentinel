"""Deterministic risk scoring.

    raw     = Σ_k  w_k · f_k                       (f_k ∈ [0,1], Σ w_k = 1)
    penalty = contradiction_weight · C             (C = noisy-OR of contradicting evidence on the alert)
    score   = round(100 · raw · (1 − penalty))

Factors (see docs/agent-design.md for the full specification):

* alert_severity            low .25 / medium .5 / high .75 / critical 1.0
* evidence_strength         noisy-OR over *independent sources*: per source system the strongest
                            confidence·freshness is used, so ten records from one log source are not
                            counted ten times (no double counting across paths either: keyed by id).
* compromise_signal         1.0 confirmed assertion, 0.6 EDR telemetry / suspected assertion,
                            0.3 correlated related alert, else 0
* threat_intel              max confidence·freshness·(1−contradiction) of indicators ≤ 3 hops away
* asset_criticality         max criticality of assets in the *directed* blast radius
* exploitable_vulnerability max over OPEN vulns on impacted assets of cvss/10 · (1 if exploit else .6),
                            reduced by contradicting evidence only if it is newer than the supporting
                            evidence (stale contradictions are reported as superseded)
* historical_incidents      min(1, Σ link_weight · recency) — direct links count 1.0, indirect .25
* path_proximity            1.0 for a high/critical asset ≤ 2 hops away, .75 at 3, .5 at 4, .25 at 5

Evidence flagged as suspected prompt injection is excluded from every factor.
The score is a heuristic triage aid; it is NOT a calibrated probability.
"""

from __future__ import annotations

from app.agents.context import InvestigationContext
from app.core.timeutil import parse_iso, to_iso
from app.risk.decay import freshness
from app.risk.weights import RiskWeights
from app.schemas.common import Ref
from app.schemas.evidence import EvidenceItem
from app.schemas.risk import RiskAssessment, RiskBand, RiskFactor, Verdict

SEVERITY = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
CRITICALITY = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
COMPROMISE_KINDS = {"edr_telemetry"}
# Posture/background records describe asset state or history, not activity in this alert. They feed
# the vulnerability and incident factors instead of evidence_strength.
POSTURE_KINDS = {"vuln_scan", "patch_record", "incident_report"}
EVIDENCE_SCOPE_HOPS = 3
PROXIMITY = {1: 1.0, 2: 1.0, 3: 0.75, 4: 0.5, 5: 0.25}

FACTOR_LABELS = {
    "alert_severity": "Alert severity",
    "evidence_strength": "Independent supporting evidence",
    "compromise_signal": "Compromise signal",
    "threat_intel": "Threat-intel indicator match",
    "asset_criticality": "Asset criticality in blast radius",
    "exploitable_vulnerability": "Exploitable vulnerability exposure",
    "historical_incidents": "Linked historical incidents",
    "path_proximity": "Proximity to high-value assets",
}


def noisy_or(values: list[float]) -> float:
    prod = 1.0
    for v in values:
        prod *= 1.0 - max(0.0, min(1.0, v))
    return 1.0 - prod


def _ev_strength(ev: EvidenceItem) -> float:
    return ev.confidence * (ev.freshness if ev.freshness is not None else 0.5)


class RiskEngine:
    def __init__(self, weights: RiskWeights) -> None:
        self.w = weights

    def band(self, score: int) -> RiskBand:
        t = self.w.band_thresholds
        if score >= t["critical"]:
            return "critical"
        if score >= t["high"]:
            return "high"
        if score >= t["medium"]:
            return "medium"
        return "low"

    def evaluate(self, ctx: InvestigationContext) -> RiskAssessment:
        notes: list[str] = []
        usable = [e for e in ctx.evidence.values() if not e.excluded_from_scoring]
        for e in ctx.evidence.values():
            if e.excluded_from_scoring:
                notes.append(f"Evidence {e.id} excluded from scoring: {e.exclusion_reason}.")
        supporting = [e for e in usable if e.stance == "supports"]
        contradicting = [e for e in usable if e.stance == "contradicts"]
        dist = ctx.distances()
        factors: dict[str, tuple[float, str, list[Ref]]] = {}

        # 1. alert severity --------------------------------------------------------------
        sev = str(ctx.target.properties.get("severity")) if ctx.target else ""
        if ctx.is_alert and sev in SEVERITY:
            factors["alert_severity"] = (
                SEVERITY[sev],
                f"Alert severity is '{sev}'.",
                [Ref(type="node", id=ctx.target_id)],
            )
        else:
            factors["alert_severity"] = (0.5, "Target is not an alert; neutral severity 0.5 assumed.", [])
            notes.append("No alert severity available; a neutral value was used.")

        # 2. evidence strength (independent sources, activity evidence in the alert's scope) -----
        scoped = [
            e for e in supporting if e.kind not in POSTURE_KINDS and dist.get(e.target_id, 99) <= EVIDENCE_SCOPE_HOPS
        ]
        by_source: dict[str, EvidenceItem] = {}
        for e in scoped:
            cur = by_source.get(e.source_system)
            if cur is None or _ev_strength(e) > _ev_strength(cur):
                by_source[e.source_system] = e
        ev_val = noisy_or([_ev_strength(e) for e in by_source.values()])
        dup = len(scoped) - len(by_source)
        factors["evidence_strength"] = (
            ev_val,
            f"{len(by_source)} independent source(s) across {len(scoped)} in-scope supporting activity record(s)"
            + (f"; {dup} same-source record(s) not double-counted" if dup else "")
            + (
                f"; {len(supporting) - len(scoped)} posture/out-of-scope record(s) excluded"
                if len(supporting) > len(scoped)
                else ""
            )
            + ".",
            [Ref(type="evidence", id=e.id) for e in by_source.values()],
        )
        if not supporting:
            notes.append("No supporting evidence records were found.")

        # 3. compromise signal ----------------------------------------------------------------
        comp_val, comp_refs, comp_why = 0.0, [], "No compromise indicators in evidence."
        confirmed = [e for e in scoped if _assertion(ctx, e) == "confirmed_compromise"]
        suspected = [e for e in scoped if _assertion(ctx, e) == "suspected_compromise" or e.kind in COMPROMISE_KINDS]
        if confirmed:
            comp_val, comp_refs = 1.0, confirmed
            comp_why = "Evidence asserts confirmed compromise."
        elif suspected:
            comp_val, comp_refs = 0.6, suspected
            comp_why = "Endpoint telemetry / suspected-compromise evidence (not confirmed)."
        elif len(ctx.related_alert_ids()) > 1:
            comp_val = 0.3
            comp_why = "Correlated related alerts, no endpoint evidence."
        factors["compromise_signal"] = (comp_val, comp_why, [Ref(type="evidence", id=e.id) for e in comp_refs])

        # 4. threat intel --------------------------------------------------------------------
        ti_best, ti_ref, ti_why = 0.0, None, "No indicator within 3 hops."
        for n in ctx.nodes.values():
            if n.label != "Indicator" or dist.get(n.id, 99) > 3:
                continue
            fr = freshness(n.properties.get("last_seen"), ctx.as_of, self.w.indicator_half_life_days) or 0.0
            con = noisy_or([_ev_strength(e) for e in contradicting if e.target_id == n.id])
            val = float(n.properties.get("confidence", 0.5)) * fr * (1 - con)
            if fr < 0.25:
                notes.append(
                    f"Indicator {n.id} is stale (last seen {n.properties.get('last_seen')}); freshness {fr:.2f}."
                )
            if con > 0:
                notes.append(f"Indicator {n.id} has contradicting evidence (strength {con:.2f}).")
            if val >= ti_best:
                ti_best, ti_ref = val, n.id
                ti_why = (
                    f"Indicator {n.id}: confidence {n.properties.get('confidence')}, freshness {fr:.2f}"
                    + (f", contradiction {con:.2f}" if con else "")
                    + "."
                )
        factors["threat_intel"] = (ti_best, ti_why, [Ref(type="node", id=ti_ref)] if ti_ref else [])

        # 5. asset criticality (directed blast radius) -------------------------------------------
        crit_best, crit_ref, crit_path = 0.0, None, None
        for a in ctx.impacted.values():
            if a.relation == "upstream_dependent":  # availability impact only, not attacker reach
                continue
            v = CRITICALITY.get(str(a.node.properties.get("criticality")), 0.0)
            if v > crit_best:
                crit_best, crit_ref, crit_path = v, a.node.id, a.path_id
        if not ctx.impacted:
            notes.append("Blast radius was not assessed (assess_impact not run or empty).")
        refs = [Ref(type="node", id=crit_ref)] if crit_ref else []
        if crit_path:
            refs.append(Ref(type="path", id=crit_path))
        factors["asset_criticality"] = (
            crit_best,
            f"Highest-criticality impacted asset: {crit_ref} ({crit_best:.2f})."
            if crit_ref
            else "No impacted assets with known criticality.",
            refs,
        )

        # 6. exploitable vulnerability --------------------------------------------------------
        vuln_best, vuln_refs, vuln_why = 0.0, [], "No open vulnerabilities on impacted assets."
        for vx in ctx.vulnerabilities.values():
            if vx.status != "open":
                continue
            p = vx.vulnerability.properties
            base = float(p.get("cvss", 0)) / 10 * (1.0 if p.get("exploit_available") else 0.6)
            sup_times = [
                t for e in supporting if e.target_id == vx.vulnerability.id and (t := parse_iso(e.observed_at))
            ]
            sup_t = max(sup_times) if sup_times else None
            reduce = 0.0
            for e in contradicting:
                if e.target_id != vx.vulnerability.id:
                    continue
                con_t = parse_iso(e.observed_at)
                if sup_t and con_t and con_t < sup_t:
                    notes.append(
                        f"Contradicting record {e.id} on {vx.vulnerability.id} is older than supporting "
                        f"evidence and is treated as superseded."
                    )
                else:
                    reduce = max(reduce, _ev_strength(e))
                    notes.append(f"Vulnerability {vx.vulnerability.id} status disputed by {e.id}.")
            val = base * (1 - reduce)
            if val > vuln_best:
                vuln_best = val
                vuln_refs = [Ref(type="node", id=vx.vulnerability.id), Ref(type="edge", id=vx.edge_id)]
                vuln_why = (
                    f"{vx.vulnerability.id} (CVSS {p.get('cvss')}, exploit "
                    f"{'available' if p.get('exploit_available') else 'not known'}) open on {vx.asset_id}"
                    + (f", reduced by contradiction {reduce:.2f}" if reduce else "")
                    + "."
                )
        factors["exploitable_vulnerability"] = (min(1.0, vuln_best), vuln_why, vuln_refs)

        # 7. historical incidents --------------------------------------------------------------------
        total, inc_refs, parts = 0.0, [], []
        for link in ctx.incidents.values():
            rec = freshness(link.opened_at, ctx.as_of, self.w.incident_half_life_days) or 0.0
            lw = 1.0 if link.link == "direct" else self.w.indirect_incident_weight
            total += lw * rec
            inc_refs += [Ref(type="node", id=link.incident.id), Ref(type="path", id=link.path_id)]
            parts.append(f"{link.incident.id} ({link.link}, {link.hops} hops, recency {rec:.2f})")
        factors["historical_incidents"] = (
            min(1.0, total),
            ("Linked: " + "; ".join(parts) + ".") if parts else "No linked incidents.",
            inc_refs,
        )

        # 8. path proximity ------------------------------------------------------------------------------
        prox_best, prox_ref = 0.0, None
        for nid, d in dist.items():
            node = ctx.nodes.get(nid)
            if (
                node
                and node.label in ("Device", "Service")
                and node.properties.get("criticality") in ("high", "critical")
            ):
                pv = PROXIMITY.get(d, 0.0) if d > 0 else 1.0
                if pv > prox_best:
                    prox_best, prox_ref = pv, (nid, d)
        factors["path_proximity"] = (
            prox_best,
            f"Nearest high/critical asset {prox_ref[0]} is {prox_ref[1]} hop(s) away."
            if prox_ref
            else "No high/critical asset reachable over current relationships.",
            [Ref(type="node", id=prox_ref[0])] if prox_ref else [],
        )

        # ---- combine -------------------------------------------------------------------------------------
        risk_factors = []
        raw = 0.0
        for key, weight in self.w.weights.items():
            val, why, frefs = factors[key]
            val = round(max(0.0, min(1.0, val)), 4)
            contrib = round(weight * val, 4)
            raw += contrib
            risk_factors.append(
                RiskFactor(
                    key=key,
                    label=FACTOR_LABELS[key],
                    weight=weight,
                    value=val,
                    contribution=contrib,
                    explanation=why,
                    refs=frefs,
                )
            )
        scope = ctx.related_alert_ids() | {ctx.target_id} | set(ctx.triggering_ids())
        global_con = [e for e in contradicting if e.target_id in scope]
        c_strength = round(noisy_or([_ev_strength(e) for e in global_con]), 4)
        penalty = round(self.w.contradiction_weight * c_strength, 4)
        for e in global_con:
            notes.append(f"Contradicting evidence {e.id} ({e.claim}) reduces the score.")
        score = max(0, min(100, round(100 * raw * (1 - penalty))))
        band = self.band(score)

        dims = [
            bool(supporting),
            bool(ctx.paths),
            bool(ctx.impacted),
            "find_related_incidents" in ctx.tools_run,
            "get_evidence" in ctx.tools_run,
        ]
        coverage = sum(dims) / len(dims)
        confidence = round(coverage * (1 - 0.5 * c_strength) * (1.0 if supporting else 0.5), 3)
        conf_band = "high" if confidence >= 0.66 else "medium" if confidence >= 0.4 else "low"
        if ctx.truncated:
            notes.append("Some traversals were truncated by node limits; unseen relationships may exist.")
        notes.append("Weights are expert heuristics; the score is not a calibrated probability.")

        verdict, reason = self._verdict(ctx, score, c_strength, scoped)
        return RiskAssessment(
            weights_version=self.w.version,
            as_of=to_iso(ctx.as_of),
            raw_score=round(raw, 4),
            contradiction_strength=c_strength,
            contradiction_penalty=penalty,
            score=score,
            band=band,
            factors=risk_factors,
            confidence=confidence,
            confidence_band=conf_band,
            uncertainty_notes=list(dict.fromkeys(notes)),
            verdict=verdict,
            verdict_reason=reason,
        )

    @staticmethod
    def _verdict(
        ctx: InvestigationContext, score: int, contradiction: float, supporting: list[EvidenceItem]
    ) -> tuple[Verdict, str]:
        if ctx.target is None:
            return "inconclusive", "Target not found in the graph."
        if not supporting:
            if contradiction >= 0.4:
                return "likely_benign", (
                    f"No supporting evidence and contradicting evidence strength {contradiction:.2f}."
                )
            return "inconclusive", "No supporting evidence records; the graph alone cannot establish maliciousness."
        if score >= 60:
            return "likely_malicious", f"Score {score} ≥ 60 with supporting evidence."
        if score >= 35:
            return "suspicious", f"Score {score} in 35–59."
        if contradiction >= 0.4:
            return "likely_benign", f"Score {score} < 35 and contradicting evidence strength {contradiction:.2f}."
        if score < 25:
            return "likely_benign", f"Score {score} < 25."
        return "suspicious", f"Score {score} in 25–34 without contradicting evidence; verification advised."


def _assertion(ctx: InvestigationContext, ev: EvidenceItem) -> str | None:
    node = ctx.nodes.get(ev.id)
    return str(node.properties.get("assertion")) if node and node.properties.get("assertion") else None
