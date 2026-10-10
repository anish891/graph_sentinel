"""FastAPI dependencies: state, authentication, authorization, pagination."""

from __future__ import annotations

import hmac
from collections.abc import Callable, Coroutine
from typing import Annotated, Any

from fastapi import Depends, Query, Request

from app.api.state import AppState
from app.auth.permissions import Permission
from app.auth.principal import Principal
from app.core.errors import AuthenticationRequiredError, PermissionDeniedError
from app.schemas.common import MAX_PAGE_SIZE

SESSION_COOKIE = "gs_session"
CSRF_COOKIE = "gs_csrf"
CSRF_HEADER = "x-csrf-token"
_UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


def get_state(request: Request) -> AppState:
    state: AppState = request.app.state.container
    return state


StateDep = Annotated[AppState, Depends(get_state)]


async def get_principal(request: Request, state: StateDep) -> Principal:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if state.settings.auth_mode == "oidc":
            principal = state.tokens.verify_oidc(token)
        else:
            principal, _ = state.tokens.verify_demo(token)
        # Bearer tokens are not sent automatically by browsers, so no CSRF check is needed.
    else:
        cookie = request.cookies.get(SESSION_COOKIE)
        if not cookie or state.settings.auth_mode != "demo":
            raise AuthenticationRequiredError()
        principal, csrf = state.tokens.verify_demo(cookie)
        if request.method in _UNSAFE:
            header = request.headers.get(CSRF_HEADER, "")
            if not csrf or not hmac.compare_digest(header, csrf):
                raise PermissionDeniedError("CSRF token missing or invalid.")
    request.state.principal = principal
    return principal


PrincipalDep = Annotated[Principal, Depends(get_principal)]


def require(permission: Permission) -> Callable[..., Coroutine[Any, Any, Principal]]:
    async def checker(principal: PrincipalDep) -> Principal:
        if not principal.can(permission):
            raise PermissionDeniedError(f"Missing permission '{permission.value}'.")
        return principal

    return checker


class PageParams:
    def __init__(
        self,
        page: Annotated[int, Query(ge=1, le=10000)] = 1,
        page_size: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 25,
    ) -> None:
        self.page = page
        self.page_size = page_size

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


PageDep = Annotated[PageParams, Depends(PageParams)]
