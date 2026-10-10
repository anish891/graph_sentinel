from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Path, Query, status

from app.api.deps import PageDep, StateDep, require
from app.auth.permissions import Permission
from app.auth.principal import Principal
from app.policies.engine import POLICY_VERSION
from app.schemas.actions import RecommendedAction
from app.schemas.common import ENTITY_ID_PATTERN, Page
from app.schemas.graph import GraphPayload
from app.schemas.investigation import (
    InvestigationRequest,
    InvestigationResult,
    InvestigationSummary,
    InvestigationTrace,
)

router = APIRouter(prefix="/investigations", tags=["investigations"])
InvId = Annotated[str, Path(pattern=ENTITY_ID_PATTERN)]
Read = Depends(require(Permission.READ_INVESTIGATIONS))


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=InvestigationResult,
    summary="Start an investigation (runs asynchronously; poll GET /investigations/{id})",
)
async def create(
    body: InvestigationRequest,
    state: StateDep,
    principal: Principal = Depends(require(Permission.CREATE_INVESTIGATION)),
) -> InvestigationResult:
    return await state.investigations.create(principal, body)


@router.get("", response_model=Page[InvestigationSummary])
async def list_investigations(
    state: StateDep,
    page: PageDep,
    status_: Annotated[
        Literal["queued", "running", "completed", "inconclusive", "failed"] | None, Query(alias="status")
    ] = None,
    target_id: Annotated[str | None, Query(pattern=ENTITY_ID_PATTERN)] = None,
    principal: Principal = Read,
) -> Page[InvestigationSummary]:
    items, total = await state.investigation_store.list_page(
        principal.tenant, offset=page.offset, limit=page.page_size, status=status_, target_id=target_id
    )
    return Page(items=items, total=total, page=page.page, page_size=page.page_size)


@router.get("/{investigation_id}", response_model=InvestigationResult)
async def get(investigation_id: InvId, state: StateDep, principal: Principal = Read) -> InvestigationResult:
    return await state.investigations.get(principal, investigation_id)


@router.get("/{investigation_id}/trace", response_model=InvestigationTrace)
async def trace(investigation_id: InvId, state: StateDep, principal: Principal = Read) -> InvestigationTrace:
    await state.investigations.get(principal, investigation_id)  # tenant + existence check
    events = await state.traces.list_events(investigation_id)
    return InvestigationTrace(investigation_id=investigation_id, events=events, integrity=state.traces.verify(events))


@router.get("/{investigation_id}/evidence")
async def evidence(investigation_id: InvId, state: StateDep, principal: Principal = Read) -> dict[str, Any]:
    r = await state.investigations.get(principal, investigation_id)
    return {
        "investigation_id": r.id,
        "target_id": r.target_id,
        "as_of": r.risk.as_of if r.risk else None,
        "supporting": r.supporting_evidence,
        "contradicting": r.contradicting_evidence,
        "findings": r.findings,
        "unsupported_claims": r.unsupported_claims,
        "risk": r.risk,
        "tool_calls": r.tool_calls,
        "trace_head_hash": r.trace_head_hash,
        "missing_information": r.missing_information,
    }


@router.get("/{investigation_id}/graph", response_model=GraphPayload)
async def graph(investigation_id: InvId, state: StateDep, principal: Principal = Read) -> GraphPayload:
    return (await state.investigations.get(principal, investigation_id)).graph


@router.get("/{investigation_id}/recommendations")
async def recommendations(investigation_id: InvId, state: StateDep, principal: Principal = Read) -> dict[str, Any]:
    r = await state.investigations.get(principal, investigation_id)
    actions: list[RecommendedAction] = r.recommended_actions
    return {
        "investigation_id": r.id,
        "policy_version": POLICY_VERSION,
        "simulated_only": True,
        "risk_score": r.risk.score if r.risk else None,
        "verdict": r.verdict,
        "actions": actions,
    }
