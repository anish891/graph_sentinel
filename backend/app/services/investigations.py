"""Investigation lifecycle: validate → create → run agent (background, bounded) → finalize → persist."""

from __future__ import annotations

import asyncio
import re
import time
from datetime import timedelta
from typing import Any

from app.actions.executor import ActionExecutor
from app.agents.context import InvestigationContext
from app.agents.findings import (
    build_graph_payload,
    deterministic_findings,
    deterministic_narrative,
    validate_claims,
)
from app.agents.llm.base import LLMProvider
from app.agents.orchestrator import Orchestrator
from app.auth.permissions import Permission
from app.auth.principal import AGENT_PRINCIPAL_ID, Principal
from app.core.config import Settings
from app.core.errors import (
    AmbiguousTargetError,
    AppError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitedError,
)
from app.core.timeutil import now_iso, to_iso, utcnow
from app.graph.client import GraphClient
from app.graph.projection import GraphProjection
from app.graph.repository import GraphRepository
from app.observability.logging import get_logger, investigation_id_var
from app.observability.metrics import INVESTIGATION_LATENCY, INVESTIGATIONS
from app.persistence.db import Database
from app.persistence.stores import ActionStore, InvestigationStore, TraceStore, new_id
from app.policies.engine import PolicyEngine, ProposedAction
from app.risk.engine import RiskEngine
from app.risk.weights import load_weights
from app.schemas.actions import ActionStatus, RecommendedAction
from app.schemas.investigation import (
    InvestigationRequest,
    InvestigationResult,
    InvestigationStats,
    Narrative,
    ProviderInfo,
)
from app.services.audit import AuditService
from app.tools.base import ToolDeps, ToolRegistry

log = get_logger(__name__)

_ALERT_ID = re.compile(r"\bALT-\d{3,6}\b", re.IGNORECASE)


class InvestigationService:
    def __init__(
        self,
        *,
        settings: Settings,
        graph: GraphClient,
        db: Database,
        audit: AuditService,
        provider_factory: Any,
        registry: ToolRegistry,
        executor: ActionExecutor,
    ) -> None:
        self.s = settings
        self.graph = graph
        self.db = db
        self.audit = audit
        self.provider_factory = provider_factory
        self.registry = registry
        self.executor = executor
        self.store = InvestigationStore(db)
        self.traces = TraceStore(db)
        self.actions = ActionStore(db)
        self.projection = GraphProjection(graph)
        self._sem = asyncio.Semaphore(settings.agent_max_concurrent_investigations)
        self._tasks: dict[str, asyncio.Task[None]] = {}

    # ---- create ----------------------------------------------------------------------------
    def resolve_target(self, req: InvestigationRequest) -> str:
        mentioned = sorted({m.upper() for m in _ALERT_ID.findall(req.question)})
        if req.target_id:
            others = [m for m in mentioned if m != req.target_id.upper()]
            if others:
                raise AmbiguousTargetError(
                    f"The question mentions {', '.join(others)} but target_id is {req.target_id}.",
                    details={"mentioned": mentioned},
                )
            return str(req.target_id)
        if len(mentioned) == 1:
            return str(mentioned[0])
        if not mentioned:
            raise AmbiguousTargetError("No target: set target_id or mention exactly one alert id (e.g. ALT-1001).")
        raise AmbiguousTargetError(
            f"The question mentions several alerts ({', '.join(mentioned)}); set target_id to choose one.",
            details={"mentioned": mentioned},
        )

    async def create(self, principal: Principal, req: InvestigationRequest) -> InvestigationResult:
        if not principal.can(Permission.CREATE_INVESTIGATION):
            raise PermissionDeniedError("Starting investigations requires the investigator or admin role.")
        target_id = self.resolve_target(req)
        repo = GraphRepository(self.graph, principal.tenant)
        target = await repo.get_entity(target_id)
        if target is None:
            raise NotFoundError(f"Target {target_id} was not found in the graph.", details={"target_id": target_id})
        active = sum(1 for t in self._tasks.values() if not t.done())
        if active >= self.s.agent_max_concurrent_investigations * 2:
            raise RateLimitedError("Investigation queue is full; try again shortly.")
        provider: LLMProvider = self.provider_factory()
        inv_id = new_id("INV")
        result = InvestigationResult(
            id=inv_id,
            tenant=principal.tenant,
            status="queued",
            question=req.question,
            target_id=target.id,
            target_label=target.label,
            requested_by=principal.id,
            created_at=now_iso(),
            provider=ProviderInfo(name=provider.name, model=provider.model, is_mock=provider.is_mock, api=provider.api),
        )
        await self.store.save(result)
        await self.audit.record(
            actor=principal.id,
            actor_role=principal.role,
            tenant=principal.tenant,
            event_type="investigation.created",
            resource_type="investigation",
            resource_id=inv_id,
            details={"target_id": target.id, "provider": provider.name, "provider_is_mock": provider.is_mock},
        )
        await self.traces.append(
            inv_id,
            "investigation.created",
            {
                "target_id": target.id,
                "requested_by": principal.id,
                "provider": provider.name,
                "provider_is_mock": provider.is_mock,
                "model": provider.model,
                "limits": {
                    "max_steps": self.s.agent_max_steps,
                    "max_tool_calls": self.s.agent_max_tool_calls,
                    "max_depth": self.s.agent_max_traversal_depth,
                    "timeout_s": self.s.agent_investigation_timeout_seconds,
                    "token_budget": self.s.agent_token_budget,
                },
            },
        )
        task = asyncio.create_task(self._run(principal, result, provider), name=f"investigation-{inv_id}")
        self._tasks[inv_id] = task

        def _forget(_t: asyncio.Task[None], i: str = inv_id) -> None:
            self._tasks.pop(i, None)

        task.add_done_callback(_forget)
        return result

    async def wait(self, investigation_id: str, max_seconds: float = 120, cancel_on_timeout: bool = False) -> None:
        task = self._tasks.get(investigation_id)
        if task is None:
            return
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=max_seconds)
        except TimeoutError:
            if cancel_on_timeout:
                # Stop it so it does not keep consuming LLM quota; it is persisted as failed.
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            raise

    async def shutdown(self) -> None:
        for task in list(self._tasks.values()):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)

    # ---- run -------------------------------------------------------------------------------
    async def _run(self, principal: Principal, result: InvestigationResult, provider: LLMProvider) -> None:
        investigation_id_var.set(result.id)
        started = time.perf_counter()
        async with self._sem:
            result.status = "running"
            await self.store.save(result)
            await self.traces.append(result.id, "investigation.running", {})
            try:
                await asyncio.wait_for(
                    self._investigate(principal, result, provider),
                    timeout=self.s.agent_investigation_timeout_seconds + 30,
                )
            except asyncio.CancelledError:
                result.status, result.error = "failed", "Cancelled during shutdown."
                result.completed_at = now_iso()
                await self._persist_failure(principal, result)
                raise
            except Exception as exc:
                log.exception("investigation.failed")
                result.status = "failed"
                result.error = exc.message if isinstance(exc, AppError) else "Internal error during investigation."
                result.completed_at = now_iso()
                await self._persist_failure(principal, result)
            finally:
                await provider.aclose()
                INVESTIGATIONS.labels(status=result.status).inc()
                INVESTIGATION_LATENCY.labels(status=result.status).observe(time.perf_counter() - started)

    async def _persist_failure(self, principal: Principal, result: InvestigationResult) -> None:
        try:
            await self.store.save(result)
            await self.traces.append(result.id, "investigation.failed", {"error": result.error})
            await self.audit.record(
                actor=AGENT_PRINCIPAL_ID,
                actor_role=None,
                tenant=principal.tenant,
                event_type="investigation.failed",
                resource_type="investigation",
                resource_id=result.id,
                details={"error": result.error},
            )
        except Exception:
            log.exception("investigation.persist_failure_failed")

    async def _investigate(self, principal: Principal, result: InvestigationResult, provider: LLMProvider) -> None:
        repo = GraphRepository(self.graph, principal.tenant)
        as_of = await repo.as_of(self.s.demo_mode, utcnow())
        ctx = InvestigationContext(
            investigation_id=result.id,
            tenant=principal.tenant,
            question=result.question,
            target_id=result.target_id,
            as_of=as_of,
            max_depth=self.s.agent_max_traversal_depth,
        )
        if result.target_label != "SecurityAlert":
            ctx.target = await repo.get_entity(result.target_id)

        async def trace(kind: str, payload: dict[str, Any]) -> None:
            await self.traces.append(result.id, kind, payload)
            if kind == "tool_call":  # progressive updates for polling clients
                result.tool_calls = list(ctx.tool_calls)
                result.stats.tool_calls = len(ctx.tool_calls)
                await self.store.save(result)

        orch = Orchestrator(
            registry=self.registry,
            provider=provider,
            deps=ToolDeps(repo=repo, settings=self.s),
            settings=self.s,
            trace=trace,
        )
        outcome = await orch.run(ctx)
        await self._finalize(principal, result, ctx, outcome.finish, outcome.stats, outcome.llm_errors, as_of)

    async def _finalize(
        self,
        principal: Principal,
        result: InvestigationResult,
        ctx: InvestigationContext,
        finish: Any,
        stats: InvestigationStats,
        llm_errors: list[str],
        as_of: Any,
    ) -> None:
        weights = load_weights(self.s.risk_weights_file)
        risk = RiskEngine(weights).evaluate(ctx) if ctx.target is not None else None
        proposals: list[ProposedAction] = PolicyEngine(weights).recommend(ctx, risk) if risk else []
        model_findings, unsupported = validate_claims(finish, ctx)
        findings = deterministic_findings(ctx, risk) + model_findings

        now = utcnow()
        actions: list[RecommendedAction] = []
        for p in proposals:
            requires = p.consequential or self.s.agent_require_approval
            actions.append(
                RecommendedAction(
                    id=new_id("ACT"),
                    investigation_id=result.id,
                    action_type=p.action_type,
                    title=_title(p),
                    target_id=p.target_id,
                    target_label=p.target_label,
                    status=ActionStatus.PENDING_APPROVAL if requires else ActionStatus.PROPOSED,
                    consequential=p.consequential,
                    requires_approval=requires,
                    policy_version=PolicyEngine.version,
                    policy_rule=p.rule,
                    justification=p.justification,
                    evidence_refs=p.refs,
                    risk_score_at_proposal=risk.score if risk else 0,
                    proposed_by=AGENT_PRINCIPAL_ID,
                    proposed_at=to_iso(now),
                    expires_at=to_iso(now + timedelta(hours=self.s.action_approval_ttl_hours)),
                )
            )

        missing = list(finish.missing_information) if finish else []
        if risk and risk.verdict == "inconclusive":
            missing.append("Supporting evidence (logs/telemetry) linked to the target in the graph.")
        if ctx.target is None:
            missing.append(f"A graph record for {ctx.target_id}.")
        # Errors the model recovered from (e.g. one malformed call, then a valid finish) are kept in the
        # trace but are not reported as an investigation error.
        model_failed = bool(llm_errors) and finish is None
        if model_failed:
            missing.append("Model reasoning was interrupted; conclusions rely on deterministic baseline tools.")

        result.risk = risk
        result.verdict = risk.verdict if risk else "inconclusive"
        result.findings = findings
        result.unsupported_claims = unsupported
        result.supporting_evidence = sorted(
            (e for e in ctx.evidence.values() if e.stance == "supports"), key=lambda e: e.id
        )
        result.contradicting_evidence = sorted(
            (e for e in ctx.evidence.values() if e.stance == "contradicts"), key=lambda e: e.id
        )
        result.narrative = Narrative(
            deterministic=deterministic_narrative(ctx, risk, proposals),
            model_summary=finish.summary if finish else None,
        )
        result.recommended_actions = actions
        result.graph = build_graph_payload(ctx)
        result.tool_calls = list(ctx.tool_calls)
        result.missing_information = list(dict.fromkeys(missing))
        result.prior_investigations = ctx.prior_investigations
        stats.tool_calls = len(ctx.tool_calls)
        result.stats = stats
        result.status = "completed" if result.verdict != "inconclusive" else "inconclusive"
        if model_failed:
            result.error = "; ".join(dict.fromkeys(llm_errors))[:500]
        result.completed_at = now_iso()

        final_evt = await self.traces.append(
            result.id,
            "investigation.completed",
            {
                "status": result.status,
                "verdict": result.verdict,
                "risk_score": risk.score if risk else None,
                "actions": [a.id for a in actions],
                "unsupported_claims": len(unsupported),
                "as_of": to_iso(as_of),
            },
        )
        result.trace_head_hash = final_evt.hash

        async with self.db.transaction() as conn:
            await self.store.save(result, conn=conn)
            for a in actions:
                await self.actions.insert(conn, principal.tenant, a)
                await self.audit.record(
                    actor=AGENT_PRINCIPAL_ID,
                    actor_role=None,
                    tenant=principal.tenant,
                    event_type=f"action.{a.status.value}",
                    resource_type="action",
                    resource_id=a.id,
                    details={
                        "action_type": a.action_type.value,
                        "target_id": a.target_id,
                        "policy_rule": a.policy_rule,
                        "investigation_id": result.id,
                    },
                    conn=conn,
                )
            await self.audit.record(
                actor=AGENT_PRINCIPAL_ID,
                actor_role=None,
                tenant=principal.tenant,
                event_type="investigation.completed",
                resource_type="investigation",
                resource_id=result.id,
                details={
                    "status": result.status,
                    "verdict": result.verdict,
                    "risk_score": risk.score if risk else None,
                    "trace_head_hash": result.trace_head_hash,
                    "provider": result.provider.name,
                },
                conn=conn,
            )
        try:
            await self.projection.write_investigation(result, _flags(ctx, actions))
        except Exception:
            log.warning("investigation.graph_projection_failed")

    # ---- queries ---------------------------------------------------------------------------
    async def get(self, principal: Principal, investigation_id: str) -> InvestigationResult:
        result = await self.store.get(principal.tenant, investigation_id)
        if result is None:
            raise NotFoundError(f"Investigation {investigation_id} not found.")
        # Action states change after the investigation completes; reflect current state.
        if result.recommended_actions:
            items, _ = await self.actions.list_page(principal.tenant, offset=0, limit=100, investigation_id=result.id)
            result.recommended_actions = items
        return result


def _title(p: ProposedAction) -> str:
    from app.policies.engine import TITLES

    return f"{TITLES[p.action_type]}: {p.target_id}"


def _flags(ctx: InvestigationContext, actions: list[RecommendedAction]) -> list[dict[str, str]]:
    flags: dict[str, str] = {}
    for edge, node in ctx.triggering:
        flags[node.id] = str(edge.properties.get("role") or "triggering_entity")
    for a in ctx.impacted.values():
        if a.relation != "upstream_dependent" and a.node.properties.get("criticality") in ("high", "critical"):
            flags.setdefault(a.node.id, "impacted_asset")
    for act in actions:
        flags.setdefault(act.target_id, f"action_target:{act.action_type.value}")
    return [{"id": k, "role": v} for k, v in flags.items()]
