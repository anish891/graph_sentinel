"""Bounded agent loop.

    decide (LLM) → validate tool name → validate typed args → execute via registry (timeout)
    → record → repeat, until finish or a hard limit (steps, tool calls, tokens, wall clock).

The LLM can only *request* registered tools. It never touches the database, never executes
actions and never produces the risk score. After the loop, an orchestrator-enforced baseline
guarantees that the core evidence tools have run (recorded as origin=orchestrator_baseline),
so a lazy or failed model cannot produce an under-investigated conclusion.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from app.agents.context import InvestigationContext
from app.agents.llm.base import DecisionRequest, FinishPayload, LLMProvider, StepRecord, ToolSpec
from app.agents.safety import sanitize_text
from app.audit.chain import content_hash
from app.core.config import Settings
from app.core.errors import AppError, LLMError
from app.observability.logging import get_logger
from app.observability.metrics import TOOL_CALLS
from app.observability.tracing import tracer
from app.schemas.investigation import InvestigationStats, ToolCallRecord
from app.tools.base import ToolDeps, ToolOutput, ToolRegistry, ToolValidationError

log = get_logger(__name__)

TraceFn = Callable[[str, dict[str, Any]], Awaitable[None]]
BASELINE_ALERT = ["get_alert", "find_attack_paths", "find_related_incidents", "assess_impact", "get_evidence"]
BASELINE_ENTITY = [
    "explore_neighborhood",
    "find_attack_paths",
    "find_related_incidents",
    "assess_impact",
    "get_evidence",
]
MAX_CONSECUTIVE_INVALID = 3
# Steps reserved at the end for the model to finish (only finish_investigation is offered then), so a
# model that over-explores still gets to write its summary and claims.
FINISH_RESERVE_STEPS = 2


@dataclass
class Outcome:
    finish: FinishPayload | None
    stats: InvestigationStats
    llm_errors: list[str] = field(default_factory=list)


class Orchestrator:
    def __init__(
        self, *, registry: ToolRegistry, provider: LLMProvider, deps: ToolDeps, settings: Settings, trace: TraceFn
    ) -> None:
        self.registry = registry
        self.provider = provider
        self.deps = deps
        self.s = settings
        self.trace = trace

    async def run(self, ctx: InvestigationContext) -> Outcome:
        stats = InvestigationStats()
        started = time.perf_counter()
        deadline = time.monotonic() + self.s.agent_investigation_timeout_seconds
        history: list[StepRecord] = []
        specs = [ToolSpec(**spec) for spec in self.registry.specs()]
        finish: FinishPayload | None = None
        llm_errors: list[str] = []
        consecutive_invalid = 0

        finish_only = False
        while True:
            limit = self._limit_hit(stats, deadline)
            if limit:
                stats.limits_hit.append(limit)
                await self.trace("limit_reached", {"limit": limit})
                break
            tool_steps_left = self.s.agent_max_steps - FINISH_RESERVE_STEPS - stats.steps
            remaining_tools = min(self.s.agent_max_tool_calls - stats.tool_calls, tool_steps_left)
            if not finish_only and remaining_tools <= 0:
                finish_only = True
                await self.trace("finish_phase", {"reason": "tool budget used; only finish_investigation offered"})
            req = DecisionRequest(
                investigation_id=ctx.investigation_id,
                question=ctx.question,
                target_id=ctx.target_id,
                tools=[] if finish_only else specs,
                history=history,
                remaining_tool_calls=0 if finish_only else remaining_tools,
                remaining_steps=self.s.agent_max_steps - stats.steps,
            )
            stats.steps += 1
            try:
                remaining = max(1.0, deadline - time.monotonic())
                decision = await asyncio.wait_for(self.provider.decide(req), timeout=remaining)
            except TimeoutError:
                stats.limits_hit.append("investigation_timeout")
                await self.trace("limit_reached", {"limit": "investigation_timeout", "during": "llm_call"})
                break
            except LLMError as exc:
                stats.llm_calls += 1
                llm_errors.append(exc.message)
                await self.trace(
                    "llm_error",
                    {"error": exc.message, "retryable": exc.retryable, "malformed": bool(exc.details.get("malformed"))},
                )
                if exc.details.get("malformed") and consecutive_invalid + 1 < MAX_CONSECUTIVE_INVALID:
                    consecutive_invalid += 1
                    continue
                break
            stats.llm_calls += 1
            stats.input_tokens += decision.usage.input_tokens
            stats.output_tokens += decision.usage.output_tokens

            if decision.kind == "finish":
                finish = decision.finish
                await self.trace(
                    "llm_finish",
                    {
                        "claims": len(finish.claims) if finish else 0,
                        "missing_information": finish.missing_information if finish else [],
                        "usage": decision.usage.model_dump(),
                    },
                )
                break

            if finish_only:
                # Tool budget is spent: do not execute further tools; ask for the finish again.
                consecutive_invalid += 1
                history.append(
                    StepRecord(
                        call_id=decision.call_id,
                        tool=decision.tool_name or "",
                        arguments=_bounded_args(decision.arguments),
                        status="rejected",
                        output={"error": "Tool budget exhausted. Call finish_investigation now."},
                    )
                )
                if consecutive_invalid >= MAX_CONSECUTIVE_INVALID:
                    stats.limits_hit.append("no_finish")
                    break
                continue

            record, output = await self._execute(
                ctx, decision.tool_name or "", decision.arguments, decision.rationale, "llm", decision.call_id
            )
            stats.tool_calls += 1
            if record.status != "ok":
                stats.rejected_tool_calls += 1
                consecutive_invalid += 1
            else:
                consecutive_invalid = 0
            history.append(
                StepRecord(
                    call_id=decision.call_id,
                    tool=record.tool,
                    arguments=record.arguments,
                    status=record.status,
                    output=output if output is not None else {"error": record.error},
                )
            )
            if consecutive_invalid >= MAX_CONSECUTIVE_INVALID:
                stats.limits_hit.append("consecutive_invalid_tool_calls")
                await self.trace("limit_reached", {"limit": "consecutive_invalid_tool_calls"})
                break

        await self._baseline(ctx)
        stats.duration_ms = round((time.perf_counter() - started) * 1000, 1)
        return Outcome(finish=finish, stats=stats, llm_errors=llm_errors)

    def _limit_hit(self, stats: InvestigationStats, deadline: float) -> str | None:
        if stats.steps >= self.s.agent_max_steps:
            return "max_steps"
        if stats.input_tokens + stats.output_tokens >= self.s.agent_token_budget:
            return "token_budget"
        if time.monotonic() >= deadline:
            return "investigation_timeout"
        return None

    async def _baseline(self, ctx: InvestigationContext) -> None:
        is_alert = ctx.is_alert or ctx.target_id.upper().startswith("ALT-")
        required = BASELINE_ALERT if is_alert else BASELINE_ENTITY
        for name in required:
            if name in ctx.target_covered:
                continue
            # Without a resolvable target there is nothing meaningful to traverse.
            if (
                name not in {"get_alert", "explore_neighborhood"}
                and ctx.target is None
                and ctx.target_id not in ctx.nodes
            ):
                break
            baseline_args: dict[str, dict[str, Any]] = {
                "get_alert": {"alert_id": ctx.target_id},
                "explore_neighborhood": {"entity_id": ctx.target_id, "depth": 2},
                "find_attack_paths": {"source_id": ctx.target_id},
                "find_related_incidents": {"entity_id": ctx.target_id},
                "assess_impact": {} if ctx.is_alert else {"entity_ids": [ctx.target_id]},
                "get_evidence": {},
            }
            args = baseline_args[name]
            await self._execute(
                ctx,
                name,
                args,
                "Required evidence step not performed by the model.",
                "orchestrator_baseline",
                f"baseline-{name}",
            )
            if name == "explore_neighborhood" and ctx.target is None and ctx.target_id in ctx.nodes:
                ctx.target = ctx.nodes[ctx.target_id]

    @staticmethod
    def _track_coverage(ctx: InvestigationContext, name: str, args: dict[str, Any], seq: int) -> None:
        """Record whether a successful call covered the *target* with default scope.

        The baseline re-runs a core tool unless the model already ran it this way, so risk inputs do not
        depend on which neighbouring entities the model chose to explore. Evidence is re-collected if any
        traversal discovered new entities after the last full-scope evidence call.
        """
        target = ctx.target_id
        if name in ("explore_neighborhood", "find_attack_paths", "find_related_incidents", "assess_impact"):
            ctx.last_traversal_seq = seq
        if name == "get_evidence" and not args.get("entity_ids"):
            ctx.last_full_evidence_seq = seq
        covered = {
            "get_alert": args.get("alert_id") == target,
            "explore_neighborhood": args.get("entity_id") == target,
            "find_attack_paths": args.get("source_id") == target and not args.get("include_historical"),
            "find_related_incidents": args.get("entity_id") == target,
            "assess_impact": not args.get("entity_ids") or (not ctx.is_alert and target in args["entity_ids"]),
        }.get(name, False)
        if covered:
            ctx.target_covered.add(name)
        if ctx.last_full_evidence_seq and ctx.last_full_evidence_seq > ctx.last_traversal_seq:
            ctx.target_covered.add("get_evidence")
        else:
            ctx.target_covered.discard("get_evidence")

    async def _execute(
        self,
        ctx: InvestigationContext,
        name: str,
        arguments: dict[str, Any],
        rationale: str | None,
        origin: str,
        call_id: str,
    ) -> tuple[ToolCallRecord, dict[str, Any] | None]:
        seq = len(ctx.tool_calls) + 1
        record_id = f"tc-{seq:02d}"
        started = time.perf_counter()
        safe_args = _bounded_args(arguments)
        tool = self.registry.get(name)
        status, error, output = "ok", None, None
        out: ToolOutput | None = None
        if tool is None:
            status, error = "rejected", f"Unknown tool '{sanitize_text(name, 64)}'. Allowed: {self.registry.names()}"
        else:
            try:
                args = tool.args_model.model_validate(arguments)
            except ValidationError as exc:
                status = "rejected"
                error = "Invalid arguments: " + "; ".join(
                    f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:5]
                )
            else:
                try:
                    with tracer.start_as_current_span("agent.tool", attributes={"tool": name}):
                        out = await asyncio.wait_for(
                            tool.run(args, ctx, self.deps), timeout=self.s.agent_tool_timeout_seconds
                        )
                    ctx.tools_run.add(name)
                    self._track_coverage(ctx, name, args.model_dump(), seq)
                except ToolValidationError as exc:
                    status, error = "rejected", str(exc)
                except TimeoutError:
                    status, error = "error", f"Tool timed out after {self.s.agent_tool_timeout_seconds}s."
                except AppError as exc:
                    status, error = "error", exc.message
                except Exception:  # a tool bug must not crash the investigation or leak internals
                    log.exception("agent.tool_crashed", tool=name)
                    status, error = "error", "Tool failed with an internal error."
        if out is not None:
            output = {"summary": out.summary, **out.data}
        record = ToolCallRecord(
            id=record_id,
            seq=seq,
            tool=sanitize_text(name, 64),
            arguments=safe_args,
            status=status,
            error=error,
            summary=out.summary if out else (error or ""),
            origin=origin,
            rationale=sanitize_text(rationale, 400) if rationale else None,
            executed_in=out.executed_in if out else None,
            duration_ms=round((time.perf_counter() - started) * 1000, 1),
            result_hash=content_hash(out.data) if out else None,
            node_ids=out.node_ids[:200] if out else [],
            path_ids=out.path_ids if out else [],
            evidence_ids=out.evidence_ids if out else [],
        )
        ctx.tool_calls.append(record)
        TOOL_CALLS.labels(tool=record.tool if tool else "unknown", outcome=status).inc()
        await self.trace(
            "tool_call",
            {
                "tool_call_id": record.id,
                "call_id": call_id,
                "tool": record.tool,
                "origin": origin,
                "arguments": safe_args,
                "status": status,
                "error": error,
                "summary": record.summary,
                "executed_in": record.executed_in,
                "duration_ms": record.duration_ms,
                "result_hash": record.result_hash,
                "path_ids": record.path_ids,
                "evidence_ids": record.evidence_ids,
            },
        )
        return record, output


def _bounded_args(arguments: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in list(arguments.items())[:20]:
        key = sanitize_text(str(k), 64)
        if isinstance(v, str):
            out[key] = sanitize_text(v, 200)
        elif isinstance(v, list):
            out[key] = [sanitize_text(str(x), 128) if isinstance(x, str) else x for x in v[:50]]
        elif isinstance(v, int | float | bool) or v is None:
            out[key] = v
        else:
            out[key] = sanitize_text(str(v), 200)
    return out
