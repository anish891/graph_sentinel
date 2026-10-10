from __future__ import annotations

import platform
from typing import Any

from fastapi import APIRouter, Depends, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.api.deps import PrincipalDep, StateDep, require
from app.auth.permissions import Permission
from app.auth.principal import Principal
from app.observability.metrics import REGISTRY
from app.policies.engine import POLICY_VERSION
from app.risk.weights import load_weights

router = APIRouter(tags=["system"])


@router.get("/health", summary="Process liveness (no dependency checks, no details)")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready", summary="Dependency readiness")
async def ready(state: StateDep, response: Response) -> dict[str, Any]:
    graph_ok = await state.graph.ping()
    db_ok = await state.db.ping()
    ok = graph_ok and db_ok
    response.status_code = 200 if ok else 503
    return {"status": "ready" if ok else "not_ready", "checks": {"graph": graph_ok, "metadata_db": db_ok}}


@router.get("/system/status", summary="Integration status for the console (no secrets)")
async def system_status(state: StateDep, principal: PrincipalDep) -> dict[str, Any]:
    s = state.settings
    return {
        "app_env": s.app_env,
        "demo_mode": s.demo_mode,
        "auth_mode": s.auth_mode,
        "llm_provider": s.effective_llm_provider,
        "llm_is_mock": s.effective_llm_provider == "mock",
        "azure_configured": s.azure_configured,
        "groq_configured": s.groq_configured,
        "llm_model": (
            s.groq_model
            if s.effective_llm_provider == "groq"
            else s.azure_openai_deployment
            if s.effective_llm_provider == "azure"
            else None
        ),
        "falkordb": {"reachable": await state.graph.ping(), "graph": s.falkordb_graph_name},
        "metadata_db": {"reachable": await state.db.ping()},
        "simulation_only": True,
        "policy_version": POLICY_VERSION,
        "risk_weights_version": load_weights(s.risk_weights_file).version,
        "synthetic_data": True,
    }


@router.get("/diagnostics", summary="Configuration diagnostics (admin; secret values never rendered)")
async def diagnostics(
    state: StateDep, principal: Principal = Depends(require(Permission.READ_DIAGNOSTICS))
) -> dict[str, Any]:
    s = state.settings
    indexes = await state.graph.list_indices() if await state.graph.ping() else []
    return {
        "issues": [i.model_dump() for i in s.config_issues()],
        "settings": {
            "APP_ENV": s.app_env,
            "DEMO_MODE": s.demo_mode,
            "AUTH_MODE": s.auth_mode,
            "AUTH_SECRET_KEY": "set" if s.auth_secret_key else "not set (ephemeral)",
            "FALKORDB_HOST": s.falkordb_host,
            "FALKORDB_PORT": s.falkordb_port,
            "FALKORDB_PASSWORD": "set" if s.falkordb_password else "not set",
            "FALKORDB_GRAPH_NAME": s.falkordb_graph_name,
            "AZURE_OPENAI_API_KEY": "set" if s.azure_openai_api_key else "not set",
            "AZURE_OPENAI_ENDPOINT": "set" if s.azure_openai_endpoint else "not set",
            "AZURE_OPENAI_DEPLOYMENT": s.azure_openai_deployment or "not set",
            "AZURE_OPENAI_API_VERSION": s.azure_openai_api_version,
            "AZURE_OPENAI_API_MODE": s.azure_openai_api_mode,
            "GROQ_API_KEY": "set" if s.groq_api_key else "not set",
            "GROQ_MODEL": s.groq_model,
            "GROQ_TOOL_OUTPUT_MAX_CHARS": s.groq_tool_output_max_chars,
            "LLM_PROVIDER (effective)": s.effective_llm_provider,
            "AGENT_MAX_STEPS": s.agent_max_steps,
            "AGENT_MAX_TOOL_CALLS": s.agent_max_tool_calls,
            "AGENT_MAX_TRAVERSAL_DEPTH": s.agent_max_traversal_depth,
            "AGENT_TOOL_TIMEOUT_SECONDS": s.agent_tool_timeout_seconds,
            "AGENT_INVESTIGATION_TIMEOUT_SECONDS": s.agent_investigation_timeout_seconds,
            "AGENT_TOKEN_BUDGET": s.agent_token_budget,
            "AGENT_REQUIRE_APPROVAL": s.agent_require_approval,
            "ACTION_APPROVAL_TTL_HOURS": s.action_approval_ttl_hours,
            "RATE_LIMIT_PER_MINUTE": s.rate_limit_per_minute,
            "MAX_REQUEST_BYTES": s.max_request_bytes,
            "OTEL_EXPORTER_OTLP_ENDPOINT": "set" if s.otel_exporter_otlp_endpoint else "not set",
            "MULTI_TENANT": s.multi_tenant,
        },
        "graph_indexes": [{"label": r[0], "properties": r[1]} for r in indexes],
        "runtime": {"python": platform.python_version()},
    }


@router.get("/metrics", summary="Prometheus metrics (admin)")
async def metrics(principal: Principal = Depends(require(Permission.READ_METRICS))) -> Response:
    return Response(generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)


@router.get("/dashboard/summary", summary="Overview dashboard counters")
async def dashboard(
    state: StateDep, principal: Principal = Depends(require(Permission.READ_INVESTIGATIONS))
) -> dict[str, Any]:
    from app.graph.repository import GraphRepository

    repo = GraphRepository(state.graph, principal.tenant)
    alert_counts = await repo.alert_counts()
    stats = await repo.stats()
    inv_counts = await state.investigation_store.counts(principal.tenant)
    recent, _ = await state.investigation_store.list_page(principal.tenant, offset=0, limit=8)
    _, pending_total = await state.actions.list_page(
        principal, offset=0, limit=1, status=["pending_approval"], investigation_id=None
    )
    return {
        "alerts": {"total": sum(alert_counts["by_severity"].values()), **alert_counts},
        "investigations": {
            "total": sum(v for k, v in inv_counts.items() if k != "high_risk"),
            "running": inv_counts.get("running", 0) + inv_counts.get("queued", 0),
            "completed": inv_counts.get("completed", 0),
            "inconclusive": inv_counts.get("inconclusive", 0),
            "failed": inv_counts.get("failed", 0),
            "high_risk": inv_counts.get("high_risk", 0),
        },
        "pending_approvals": pending_total,
        "recent_investigations": [r.model_dump() for r in recent],
        "graph": {
            "node_count": stats.node_count,
            "edge_count": stats.edge_count,
            "nodes_by_label": stats.nodes_by_label,
            "dataset": stats.dataset,
        },
    }
