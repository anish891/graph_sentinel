"""Demo authentication endpoints. Disabled unless AUTH_MODE=demo (never allowed in production)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request, Response
from pydantic import Field

from app.api.deps import CSRF_COOKIE, SESSION_COOKIE, PrincipalDep, StateDep
from app.auth.tokens import DEMO_USERS
from app.core.errors import NotFoundError, ValidationFailedError
from app.schemas.common import StrictModel

router = APIRouter(prefix="/auth", tags=["auth"])


class DemoLoginRequest(StrictModel):
    user_id: str = Field(pattern=r"^[a-z]{1,32}$")
    as_bearer: bool = Field(default=False, description="Also return the token for API clients (curl, tests).")


def _require_demo(state: Any) -> None:
    if state.settings.auth_mode != "demo":
        raise NotFoundError("Demo authentication is disabled.")


@router.get("/demo-users", summary="Synthetic demo identities (demo mode only)")
async def demo_users(state: StateDep) -> dict[str, Any]:
    _require_demo(state)
    return {
        "notice": "DEMO AUTHENTICATION — synthetic users, no credentials, not production authentication.",
        "users": [
            {"id": u.id, "name": u.name, "role": u.role, "description": u.description} for u in DEMO_USERS.values()
        ],
    }


@router.post("/demo-login", summary="Start a demo session (demo mode only)")
async def demo_login(body: DemoLoginRequest, request: Request, response: Response, state: StateDep) -> dict[str, Any]:
    _require_demo(state)
    user = DEMO_USERS.get(body.user_id)
    if user is None:
        raise ValidationFailedError("Unknown demo user.")
    token, csrf, ttl = state.tokens.issue_demo(user)
    secure = request.url.scheme == "https" or state.settings.app_env == "production"
    response.set_cookie(SESSION_COOKIE, token, max_age=ttl, httponly=True, secure=secure, samesite="strict", path="/")
    response.set_cookie(CSRF_COOKIE, csrf, max_age=ttl, httponly=False, secure=secure, samesite="strict", path="/")
    await state.audit.record(
        actor=f"demo:{user.id}",
        actor_role=user.role,
        tenant=state.settings.default_tenant,
        event_type="auth.demo_login",
        resource_type="session",
        resource_id=None,
    )
    out: dict[str, Any] = {
        "user": {"id": f"demo:{user.id}", "name": user.name, "role": user.role},
        "csrf_token": csrf,
        "expires_in": ttl,
        "auth_mode": "demo",
    }
    if body.as_bearer:
        out["access_token"] = token
    return out


@router.post("/logout", summary="End the session")
async def logout(response: Response) -> dict[str, str]:
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return {"status": "logged_out"}


@router.get("/me", summary="Current principal and permissions")
async def me(principal: PrincipalDep) -> dict[str, Any]:
    return {
        "id": principal.id,
        "name": principal.name,
        "role": principal.role,
        "tenant": principal.tenant,
        "auth_method": principal.auth_method,
        "permissions": sorted(p.value for p in principal.permissions),
    }
