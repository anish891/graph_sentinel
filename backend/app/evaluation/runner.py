"""Run the evaluation suite and write JSON + Markdown reports from actual execution results."""

from __future__ import annotations

import json
import platform
import sys
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.core.timeutil import now_iso
from app.evaluation.harness import build_harness
from app.evaluation.scenarios import SCENARIOS, ScenarioResult, run_scenario


def aggregate(results: list[ScenarioResult]) -> dict[str, Any]:
    inv = [r.metrics for r in results if "tool_calls" in r.metrics]
    llm_calls = sum(m.get("llm_tool_calls", 0) for m in inv)
    invalid = sum(m.get("invalid_llm_tool_calls", 0) for m in inv)
    model_claims = sum(m.get("model_claims", 0) for m in inv)
    unsupported = sum(m.get("unsupported_claims", 0) for m in inv)
    durations = sorted(m["duration_ms"] for m in inv if m.get("duration_ms"))
    by_cat: dict[str, list[bool]] = {}
    for r in results:
        by_cat.setdefault(r.category, []).append(r.passed)
    return {
        "scenarios": len(results),
        "passed": sum(r.passed for r in results),
        "checks": sum(len(r.checks) for r in results),
        "checks_passed": sum(c.passed for r in results for c in r.checks),
        "pass_rate_by_category": {k: f"{sum(v)}/{len(v)}" for k, v in sorted(by_cat.items())},
        "citation_coverage": round(sum(m.get("citation_coverage", 0) for m in inv) / max(1, len(inv)), 3),
        "unsupported_claim_rate": round(unsupported / model_claims, 3) if model_claims else None,
        "llm_tool_calls": llm_calls,
        "tool_call_validity": round((llm_calls - invalid) / llm_calls, 3) if llm_calls else None,
        "investigation_latency_ms": {
            "min": durations[0],
            "median": durations[len(durations) // 2],
            "max": durations[-1],
        }
        if durations
        else None,
        "llm_tokens": {
            "input": sum(m.get("input_tokens", 0) for m in inv),
            "output": sum(m.get("output_tokens", 0) for m in inv),
        },
    }


def to_markdown(meta: dict[str, Any], agg: dict[str, Any], results: list[ScenarioResult]) -> str:
    lines = [
        "# GraphSentinel AI — Evaluation Report",
        "",
        f"Generated {meta['generated_at']} from an actual run. Provider: **{meta['provider']}**"
        f"{' (deterministic mock planner — not an LLM)' if meta['provider_is_mock'] else ''}. "
        f"FalkorDB graph `{meta['graph']}`, dataset anchored at {meta['anchor']}.",
        "",
        "> The dataset is synthetic. These numbers measure behaviour on designed scenarios; they are not a "
        "benchmark of real-world detection performance.",
        "",
        "## Summary",
        "",
        f"- Scenarios passed: **{agg['passed']}/{agg['scenarios']}** (checks {agg['checks_passed']}/{agg['checks']})",
        f"- Evidence citation coverage (findings with ≥1 valid reference): **{agg['citation_coverage']}**",
        f"- Unsupported-claim rate (model claims rejected by validation): **{agg['unsupported_claim_rate']}** "
        "(includes scenarios that deliberately inject unsupported claims)",
        f"- Tool-call validity (LLM-issued calls accepted): **{agg['tool_call_validity']}** over "
        f"{agg['llm_tool_calls']} calls (includes the deliberately invalid calls of S09)",
        f"- Investigation latency (ms): {agg['investigation_latency_ms']}",
        f"- LLM tokens: {agg['llm_tokens']}",
        f"- Pass rate by category: {agg['pass_rate_by_category']}",
        "",
        "## Scenarios",
        "",
        "| ID | Scenario | Category | Result | Checks | Duration ms |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(
            f"| {r.key} | {r.title} | {r.category} | {'PASS' if r.passed else 'FAIL'} | "
            f"{sum(c.passed for c in r.checks)}/{len(r.checks)} | {r.duration_ms} |"
        )
    lines += ["", "## Details", ""]
    for r in results:
        lines.append(f"### {r.key} — {r.title} ({'PASS' if r.passed else 'FAIL'})")
        if r.error:
            lines.append(f"- **Error:** `{r.error}`")
        for c in r.checks:
            detail = f" — `{c.detail[:200]}`" if c.detail else ""
            lines.append(f"- {'✅' if c.passed else '❌'} {c.name}{detail}")
        if r.metrics:
            keep = {
                k: v
                for k, v in r.metrics.items()
                if k
                in (
                    "verdict",
                    "risk_score",
                    "band",
                    "tool_calls",
                    "baseline_tool_calls",
                    "unsupported_claims",
                    "duration_ms",
                    "contradiction_strength",
                )
            }
            lines.append(f"- Metrics: `{json.dumps(keep)}`")
        lines.append("")
    return "\n".join(lines)


async def run_evaluation(output_dir: str = "../reports", live: bool = False, only: list[str] | None = None) -> int:
    settings = get_settings()
    if live and settings.effective_llm_provider not in ("azure", "groq"):
        print("Live evaluation requires GROQ_API_KEY or full Azure OpenAI settings.", file=sys.stderr)
        return 2
    h = await build_harness(live=live)
    results: list[ScenarioResult] = []
    try:
        for key, *_rest, live_ok in SCENARIOS:
            if live and not live_ok:
                continue
            if only and key not in only:
                continue
            res = await run_scenario(h, key)
            results.append(res)
            print(
                f"{res.key} {'PASS' if res.passed else 'FAIL'} {res.title}" + (f"  [{res.error}]" if res.error else "")
            )
            for c in res.checks:
                if not c.passed:
                    print(f"    ✗ {c.name} {c.detail[:160]}")
    finally:
        await h.close()
    provider = h.provider_holder.get("factory")
    meta = {
        "generated_at": now_iso(),
        "live": live,
        "provider": settings.effective_llm_provider if live else "mock-deterministic-planner",
        "provider_is_mock": not live,
        "model": (
            settings.groq_model if settings.effective_llm_provider == "groq" else settings.azure_openai_deployment
        )
        if live
        else None,
        "graph": h.settings.falkordb_graph_name,
        "anchor": "2026-10-01T12:00:00Z",
        "python": platform.python_version(),
        "factory": getattr(provider, "__name__", None),
    }
    agg = aggregate(results)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    suffix = "live" if live else "offline"
    (out / f"evaluation-{suffix}.json").write_text(
        json.dumps(
            {
                "meta": meta,
                "aggregate": agg,
                "scenarios": [
                    {
                        "key": r.key,
                        "title": r.title,
                        "category": r.category,
                        "passed": r.passed,
                        "error": r.error,
                        "duration_ms": r.duration_ms,
                        "checks": [c.__dict__ for c in r.checks],
                        "metrics": r.metrics,
                    }
                    for r in results
                ],
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    (out / f"evaluation-{suffix}.md").write_text(to_markdown(meta, agg, results), encoding="utf-8")
    print(f"\n{agg['passed']}/{agg['scenarios']} scenarios passed — report: {out / f'evaluation-{suffix}.md'}")
    return 0 if agg["passed"] == agg["scenarios"] else 1
