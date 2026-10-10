"""Deterministic offline planner used in demo mode and tests.

This is NOT a language model and never claims to be one: provider name `mock-deterministic-planner`,
`is_mock=True`, surfaced in the UI, API, logs and the audit trail. It chooses the next tool from the
outputs of previous tool calls (the same compact data a real model receives) using fixed rules, and
writes claims that cite only ids present in those outputs.
"""

from __future__ import annotations

from typing import Any

from app.agents.llm.base import AgentDecision, Claim, DecisionRequest, FinishPayload, LLMProvider, StepRecord

_CRIT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


class MockLLMProvider(LLMProvider):
    name = "mock-deterministic-planner"
    model = "rules-v1 (not an LLM)"
    is_mock = True
    api = "none"

    def __init__(self, script: list[AgentDecision] | None = None) -> None:
        # Tests can inject a fixed script of decisions (e.g. invalid tool calls).
        self._script = list(script or [])

    async def decide(self, request: DecisionRequest) -> AgentDecision:
        if self._script:
            return self._script.pop(0)
        step_no = len(request.history) + 1
        call_id = f"mock-{step_no}"
        done = {s.tool: s for s in request.history if s.status == "ok"}
        alert = done.get("get_alert")
        target = request.target_id
        is_alert = target.upper().startswith("ALT-")

        if is_alert and alert is None:
            return self._call(call_id, "get_alert", {"alert_id": target}, "Start from the alert record.")
        if alert is not None and not alert.output.get("found", True):
            return self._finish(call_id, request, not_found=True)

        plan: list[tuple[str, dict[str, Any], str, bool]] = [
            (
                "explore_neighborhood",
                {"entity_id": target, "depth": 2, "include_historical": True, "max_nodes": 60},
                "Map the local neighbourhood, including historical relationships so stale links are visible.",
                True,
            ),
            (
                "find_attack_paths",
                {
                    "source_id": target,
                    "target_labels": ["Service", "Vulnerability", "Incident", "Device"],
                    "max_hops": 5,
                    "limit": 25,
                },
                "Look for multi-hop propagation paths to assets, vulnerabilities and incidents.",
                True,
            ),
            (
                "find_related_incidents",
                {"entity_id": target, "max_hops": 4},
                "Check for historical incidents sharing entities or indicators.",
                True,
            ),
            (
                "assess_impact",
                {} if is_alert else {"entity_ids": [target]},
                "Compute the directed blast radius from the implicated entities.",
                True,
            ),
            ("get_evidence", {}, "Collect supporting and contradicting evidence with provenance.", True),
            (
                "run_graph_algorithm",
                {"algorithm": "connected_component"},
                "Check whether the implicated entities are isolated from critical assets.",
                False,
            ),
        ]
        crit_target = _critical_asset(done.get("assess_impact"))
        if crit_target:
            plan.append(
                (
                    "run_graph_algorithm",
                    {"algorithm": "shortest_path", "source_id": target, "target_id": crit_target, "max_hops": 5},
                    f"Measure the minimum hop distance to critical asset {crit_target}.",
                    False,
                )
            )
        plan += [
            (
                "run_graph_algorithm",
                {"algorithm": "betweenness_centrality"},
                "Identify chokepoint assets on propagation paths.",
                False,
            ),
            ("get_prior_investigations", {}, "Recall earlier investigations involving the same entities.", False),
            ("evaluate_risk", {}, "Compute the deterministic risk score.", False),
        ]
        executed = [(s.tool, s.arguments) for s in request.history]
        essential_left = sum(1 for t, a, _, ess in plan if ess and (t, a) not in executed)
        for tool, args, why, essential in plan:
            if (tool, args) in executed:
                continue
            # Keep budget for the essential steps; optional ones are skipped when budget is tight.
            if not essential and request.remaining_tool_calls <= essential_left:
                continue
            if request.remaining_tool_calls <= 0 or request.remaining_steps <= 1:
                break
            return self._call(call_id, tool, args, why)
        return self._finish(call_id, request)

    @staticmethod
    def _call(call_id: str, tool: str, args: dict[str, Any], why: str) -> AgentDecision:
        return AgentDecision(kind="tool_call", call_id=call_id, tool_name=tool, arguments=dict(args), rationale=why)

    def _finish(self, call_id: str, request: DecisionRequest, not_found: bool = False) -> AgentDecision:
        if not_found:
            return AgentDecision(
                kind="finish",
                call_id=call_id,
                finish=FinishPayload(
                    summary=f"Target {request.target_id} was not found in the graph; nothing can be concluded.",
                    claims=[],
                    missing_information=[f"A record for {request.target_id} in the security graph."],
                ),
            )
        done = {s.tool: s for s in request.history if s.status == "ok"}
        claims: list[Claim] = []
        missing: list[str] = []
        paths = (done.get("find_attack_paths") or _empty()).output.get("paths", [])
        if paths:
            best = sorted(paths, key=lambda p: (p["end_label"] not in ("Incident", "Vulnerability"), -p["hops"]))[0]
            claims.append(
                Claim(
                    kind="inference",
                    refs=[best["path_id"]],
                    statement=f"A {best['hops']}-hop chain connects {request.target_id} to "
                    f"{best['end_id']} ({best['end_label']}).",
                )
            )
        else:
            missing.append("Any propagation path from the target to assets or incidents.")
        for inc in (done.get("find_related_incidents") or _empty()).output.get("incidents", [])[:3]:
            claims.append(
                Claim(
                    kind="observed_fact",
                    refs=[inc["path_id"], inc["incident_id"]],
                    statement=f"Incident {inc['incident_id']} is linked via a {inc['link']} {inc['hops']}-hop chain.",
                )
            )
        crit = _critical_asset(done.get("assess_impact"), with_path=True)
        if crit:
            claims.append(
                Claim(
                    kind="inference",
                    refs=[crit[0], crit[1]] if crit[1] else [crit[0]],
                    statement=f"{crit[0]} ({crit[2]}) is reachable in the blast radius.",
                )
            )
        ev = (done.get("get_evidence") or _empty()).output.get("evidence", [])
        sup = [e["id"] for e in ev if e["stance"] == "supports" and not e.get("suspected_prompt_injection")]
        con = [e["id"] for e in ev if e["stance"] == "contradicts" and not e.get("suspected_prompt_injection")]
        if sup:
            claims.append(
                Claim(
                    kind="observed_fact", refs=sup[:8], statement=f"{len(sup)} evidence record(s) support the activity."
                )
            )
        else:
            missing.append("Supporting evidence (endpoint telemetry, authentication or network logs).")
        if con:
            claims.append(
                Claim(
                    kind="observed_fact",
                    refs=con[:8],
                    statement=f"{len(con)} evidence record(s) contradict parts of the alert.",
                )
            )
        flagged = [e["id"] for e in ev if e.get("suspected_prompt_injection")]
        if flagged:
            claims.append(
                Claim(
                    kind="observed_fact",
                    refs=flagged,
                    statement="Some evidence text contains instructions aimed at the agent; it was "
                    "treated as untrusted data and ignored.",
                )
            )
        comps = (_find(request.history, "run_graph_algorithm", "connected_component") or _empty()).output
        for eid, info in (comps.get("components") or {}).items():
            if info.get("found") and not info.get("critical_or_high_assets"):
                claims.append(
                    Claim(
                        kind="observed_fact",
                        refs=[eid],
                        statement=f"{eid} is in a component with no high/critical assets "
                        f"({info.get('component_size')} entities).",
                    )
                )
        summary = (
            f"[mock-deterministic-planner — not an LLM] Investigated {request.target_id} with "
            f"{len(request.history)} graph tool calls: {len(paths)} propagation paths, "
            f"{len(sup)} supporting and {len(con)} contradicting evidence records. Risk and response "
            "are determined by the deterministic engines."
        )
        return AgentDecision(
            kind="finish",
            call_id=call_id,
            finish=FinishPayload(summary=summary, claims=claims[:25], missing_information=missing),
        )


class _Empty:
    output: dict[str, Any] = {}


def _empty() -> Any:
    return _Empty()


def _find(history: list[StepRecord], tool: str, algorithm: str) -> StepRecord | None:
    for s in history:
        if s.tool == tool and s.status == "ok" and s.arguments.get("algorithm") == algorithm:
            return s
    return None


def _critical_asset(step: StepRecord | None, with_path: bool = False) -> Any:
    if step is None:
        return None
    assets = [a for a in step.output.get("assets", []) if a.get("relation") != "upstream_dependent"]
    assets = [a for a in assets if a.get("criticality") in ("critical", "high") and a.get("hops", 0) > 0]
    if not assets:
        return None
    best = sorted(assets, key=lambda a: (-_CRIT.get(a.get("criticality", ""), 0), a.get("hops", 99)))[0]
    if with_path:
        return best["id"], best.get("path_id"), best.get("criticality")
    return best["id"]
