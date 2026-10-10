from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.deps import PageDep, StateDep, require
from app.auth.permissions import Permission
from app.auth.principal import Principal
from app.schemas.audit import AuditEvent, ChainVerification
from app.schemas.common import ENTITY_ID_PATTERN, Page

router = APIRouter(prefix="/audit", tags=["audit"])
ReadAudit = Depends(require(Permission.READ_AUDIT))


@router.get("/events", response_model=Page[AuditEvent])
async def events(
    state: StateDep,
    page: PageDep,
    event_type: Annotated[str | None, Query(pattern=r"^[a-z_.]{1,64}$")] = None,
    resource_id: Annotated[str | None, Query(pattern=ENTITY_ID_PATTERN)] = None,
    principal: Principal = ReadAudit,
) -> Page[AuditEvent]:
    items, total = await state.audit.list_page(
        principal.tenant, offset=page.offset, limit=page.page_size, event_type=event_type, resource_id=resource_id
    )
    return Page(items=items, total=total, page=page.page, page_size=page.page_size)


@router.get("/verify", response_model=ChainVerification)
async def verify(state: StateDep, principal: Principal = ReadAudit) -> ChainVerification:
    return await state.audit.verify_chain()
