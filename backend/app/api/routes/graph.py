from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Path, Query

from app.agents.safety import injection_signals
from app.api.deps import PageDep, StateDep, require
from app.auth.permissions import Permission
from app.auth.principal import Principal
from app.core.errors import NotFoundError
from app.core.timeutil import utcnow
from app.graph.repository import GraphRepository
from app.graph.schema import schema_doc
from app.schemas.common import ENTITY_ID_PATTERN, Page
from app.schemas.evidence import EvidenceItem
from app.schemas.graph import GraphEdge, GraphNode, GraphPayload, GraphSchemaDoc, GraphStats, Truncation

router = APIRouter(tags=["graph"])
EntityPath = Annotated[str, Path(pattern=ENTITY_ID_PATTERN)]
ReadGraph = Depends(require(Permission.READ_GRAPH))
ReadAlerts = Depends(require(Permission.READ_ALERTS))


def _repo(state: Any, principal: Principal) -> GraphRepository:
    return GraphRepository(state.graph, principal.tenant)


@router.get("/graph/schema", response_model=GraphSchemaDoc)
async def graph_schema(state: StateDep, principal: Principal = ReadGraph) -> GraphSchemaDoc:
    doc = schema_doc()
    rows = await state.graph.list_indices()
    doc.indexes = [{"label": r[0], "properties": r[1]} for r in rows]
    doc.constraints = await state.graph.list_constraints()
    return doc


@router.get("/graph/stats", response_model=GraphStats)
async def graph_stats(state: StateDep, principal: Principal = ReadGraph) -> GraphStats:
    return await _repo(state, principal).stats()


@router.get("/graph/search", response_model=list[GraphNode])
async def graph_search(
    state: StateDep, q: Annotated[str, Query(min_length=2, max_length=64)], principal: Principal = ReadGraph
) -> list[GraphNode]:
    return await _repo(state, principal).search(q)


@router.get("/entities/{entity_id}")
async def get_entity(entity_id: EntityPath, state: StateDep, principal: Principal = ReadGraph) -> dict[str, Any]:
    repo = _repo(state, principal)
    node = await repo.get_entity(entity_id)
    if node is None:
        raise NotFoundError(f"Entity {entity_id} not found.")
    as_of = await repo.as_of(state.settings.demo_mode, utcnow())
    links = await repo.direct_links(entity_id, as_of)
    return {"entity": node, "relationships": [{"edge": e, "neighbor": n} for e, n in links]}


@router.get("/entities/{entity_id}/neighbors", response_model=GraphPayload)
async def neighbors(
    entity_id: EntityPath,
    state: StateDep,
    depth: Annotated[int, Query(ge=1, le=3)] = 1,
    max_nodes: Annotated[int, Query(ge=5, le=100)] = 40,
    include_historical: bool = False,
    principal: Principal = ReadGraph,
) -> GraphPayload:
    repo = _repo(state, principal)
    if await repo.get_entity(entity_id) is None:
        raise NotFoundError(f"Entity {entity_id} not found.")
    as_of = await repo.as_of(state.settings.demo_mode, utcnow())
    nodes, edges, truncated = await repo.neighborhood(
        entity_id, depth=depth, max_nodes=max_nodes, as_of=as_of, include_historical=include_historical
    )
    return GraphPayload(
        nodes=nodes,
        edges=edges,
        truncation=Truncation(
            truncated=truncated, max_nodes=max_nodes, max_depth=depth, reason="node cap" if truncated else None
        ),
    )


@router.get("/alerts", response_model=Page[GraphNode])
async def list_alerts(
    state: StateDep,
    page: PageDep,
    severity: Annotated[list[Literal["low", "medium", "high", "critical"]] | None, Query()] = None,
    status: Annotated[list[Literal["open", "triaged", "closed"]] | None, Query()] = None,
    q: Annotated[str | None, Query(max_length=64)] = None,
    sort: Literal["detected_at", "severity", "id"] = "detected_at",
    order: Literal["asc", "desc"] = "desc",
    principal: Principal = ReadAlerts,
) -> Page[GraphNode]:
    items, total = await _repo(state, principal).list_alerts(
        severity=list(severity) if severity else None,
        status=list(status) if status else None,
        q=q,
        sort=sort,
        descending=order == "desc",
        offset=page.offset,
        limit=page.page_size,
    )
    return Page(items=items, total=total, page=page.page, page_size=page.page_size)


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: EntityPath, state: StateDep, principal: Principal = ReadAlerts) -> dict[str, Any]:
    repo = _repo(state, principal)
    node = await repo.get_entity(alert_id)
    if node is None or node.label != "SecurityAlert":
        raise NotFoundError(f"Alert {alert_id} not found.")
    as_of = await repo.as_of(state.settings.demo_mode, utcnow())
    links = await repo.direct_links(alert_id, as_of)
    ev_rows = await repo.evidence_for([alert_id])
    evidence = [
        EvidenceItem(
            id=r.node.id,
            kind=str(r.node.properties.get("kind")),
            source_system=str(r.node.properties.get("source_system")),
            source_ref=str(r.node.properties.get("source_ref")),
            observed_at=r.node.properties.get("observed_at"),
            summary=str(r.node.properties.get("summary", "")),
            claim=r.claim,
            confidence=float(r.node.properties.get("confidence", 0.5)),
            stance=r.stance,
            target_id=r.target.id,
            target_label=r.target.label,
            suspected_prompt_injection=bool(sig := injection_signals(str(r.node.properties.get("summary", "")))),
            injection_signals=sig,
        )
        for r in ev_rows
    ]
    investigations, _ = await state.investigation_store.list_page(
        principal.tenant, offset=0, limit=10, target_id=alert_id
    )
    related: list[dict[str, GraphEdge | GraphNode]] = [
        {"edge": e, "neighbor": n} for e, n in links if n.label != "Evidence"
    ]
    return {
        "alert": node,
        "relationships": related,
        "evidence": evidence,
        "investigations": [i.model_dump() for i in investigations],
    }
