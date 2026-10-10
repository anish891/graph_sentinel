from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, Path, Query

from app.api.deps import PageDep, PrincipalDep, StateDep, require
from app.auth.permissions import Permission
from app.auth.principal import Principal
from app.schemas.actions import ApprovalRequest, CancelRequest, RecommendedAction, RejectRequest
from app.schemas.common import ENTITY_ID_PATTERN, Page

router = APIRouter(prefix="/actions", tags=["actions"])
ActId = Annotated[str, Path(pattern=ENTITY_ID_PATTERN)]
IdemKey = Annotated[str, Header(alias="Idempotency-Key", min_length=1, max_length=128)]
StatusName = Literal[
    "proposed", "pending_approval", "approved", "executed_simulation", "rejected", "expired", "failed", "cancelled"
]


@router.get("", response_model=Page[RecommendedAction])
async def list_actions(
    state: StateDep,
    page: PageDep,
    status: Annotated[list[StatusName] | None, Query()] = None,
    investigation_id: Annotated[str | None, Query(pattern=ENTITY_ID_PATTERN)] = None,
    principal: Principal = Depends(require(Permission.READ_ACTIONS)),
) -> Page[RecommendedAction]:
    items, total = await state.actions.list_page(
        principal,
        offset=page.offset,
        limit=page.page_size,
        status=list(status) if status else None,
        investigation_id=investigation_id,
    )
    return Page(items=items, total=total, page=page.page, page_size=page.page_size)


@router.get("/{action_id}", response_model=RecommendedAction)
async def get_action(
    action_id: ActId, state: StateDep, principal: Principal = Depends(require(Permission.READ_ACTIONS))
) -> RecommendedAction:
    return await state.actions.get(principal, action_id)


# Authorization for decisions is enforced inside ActionService (permission, four-eyes, tenant),
# so that denied attempts are also written to the audit log.
@router.post("/{action_id}/approve", summary="Approve and execute (simulation) — requires Idempotency-Key")
async def approve(
    action_id: ActId, body: ApprovalRequest, idempotency_key: IdemKey, state: StateDep, principal: PrincipalDep
) -> dict[str, Any]:
    _, payload = await state.actions.approve(principal, action_id, body, idempotency_key)
    return payload


@router.post("/{action_id}/reject", summary="Reject — requires Idempotency-Key")
async def reject(
    action_id: ActId, body: RejectRequest, idempotency_key: IdemKey, state: StateDep, principal: PrincipalDep
) -> dict[str, Any]:
    _, payload = await state.actions.reject(principal, action_id, body, idempotency_key)
    return payload


@router.post("/{action_id}/cancel", summary="Cancel a pending action — requires Idempotency-Key")
async def cancel(
    action_id: ActId, body: CancelRequest, idempotency_key: IdemKey, state: StateDep, principal: PrincipalDep
) -> dict[str, Any]:
    _, payload = await state.actions.cancel(principal, action_id, body, idempotency_key)
    return payload
