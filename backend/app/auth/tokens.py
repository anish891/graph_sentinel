"""Session tokens (demo mode) and OIDC bearer validation.

DEMO MODE IS NOT PRODUCTION AUTHENTICATION. It issues signed session tokens for a fixed set of
synthetic users without any credential check. Production must use AUTH_MODE=oidc; the settings
validator refuses to start production with demo auth.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any

import jwt

from app.auth.principal import Principal
from app.core.config import Settings
from app.core.errors import AuthenticationRequiredError


@dataclass(frozen=True)
class DemoUser:
    id: str
    name: str
    role: str
    person_id: str
    description: str


DEMO_USERS: dict[str, DemoUser] = {
    u.id: u
    for u in [
        DemoUser("vera", "Vera Viewer", "viewer", "per-vera", "Read-only: dashboards, alerts, investigations."),
        DemoUser("alice", "Alice Analyst", "investigator", "per-alice", "Runs investigations; cannot approve actions."),
        DemoUser("bob", "Bob Approver", "approver", "per-bob", "Approves/rejects simulated response actions."),
        DemoUser("ada", "Ada Admin", "admin", "per-ada", "All permissions incl. diagnostics and metrics."),
    ]
}

_ISSUER = "graphsentinel-demo"
_AUDIENCE = "graphsentinel"


class TokenService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        if settings.auth_secret_key is not None:
            self._key = settings.auth_secret_key.get_secret_value()
        else:
            # Ephemeral key: sessions do not survive restarts. Reported in diagnostics.
            self._key = secrets.token_urlsafe(48)
        self._jwks: jwt.PyJWKClient | None = None
        if settings.auth_mode == "oidc" and settings.oidc_jwks_url:
            self._jwks = jwt.PyJWKClient(settings.oidc_jwks_url, cache_keys=True, lifespan=3600, timeout=5)

    # ---- demo sessions -------------------------------------------------------------------
    def issue_demo(self, user: DemoUser) -> tuple[str, str, int]:
        now = int(time.time())
        ttl = self.settings.session_ttl_minutes * 60
        csrf = secrets.token_urlsafe(24)
        token = jwt.encode(
            {
                "sub": user.id,
                "role": user.role,
                "tenant": self.settings.default_tenant,
                "iss": _ISSUER,
                "aud": _AUDIENCE,
                "iat": now,
                "nbf": now,
                "exp": now + ttl,
                "csrf": csrf,
                "jti": secrets.token_hex(8),
            },
            self._key,
            algorithm="HS256",
        )
        return token, csrf, ttl

    def verify_demo(self, token: str) -> tuple[Principal, str]:
        try:
            claims = jwt.decode(
                token,
                self._key,
                algorithms=["HS256"],
                audience=_AUDIENCE,
                issuer=_ISSUER,
                options={"require": ["exp", "sub", "iss", "aud"]},
            )
        except jwt.PyJWTError as exc:
            raise AuthenticationRequiredError("Session invalid or expired.") from exc
        user = DEMO_USERS.get(str(claims["sub"]))
        if user is None or user.role != claims.get("role"):
            raise AuthenticationRequiredError("Session invalid or expired.")
        # Tenant always comes from server-side configuration, never from the client.
        principal = Principal.build(
            id=f"demo:{user.id}",
            name=user.name,
            role=user.role,
            tenant=self.settings.default_tenant,
            auth_method="demo",
            person_id=user.person_id,
        )
        return principal, str(claims.get("csrf", ""))

    # ---- OIDC --------------------------------------------------------------------------------
    def verify_oidc(self, token: str) -> Principal:
        if self._jwks is None:
            raise AuthenticationRequiredError("OIDC is not configured.")
        try:
            signing_key = self._jwks.get_signing_key_from_jwt(token)
            claims: dict[str, Any] = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "ES256", "PS256"],
                audience=self.settings.oidc_audience,
                issuer=self.settings.oidc_issuer,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
        except jwt.PyJWTError as exc:
            raise AuthenticationRequiredError("Bearer token invalid.") from exc
        roles = claims.get(self.settings.oidc_roles_claim) or []
        if isinstance(roles, str):
            roles = [roles]
        # Highest privilege role recognised wins; unknown roles grant nothing.
        role = next((r for r in ("admin", "approver", "investigator", "viewer") if r in roles), None)
        if role is None:
            raise AuthenticationRequiredError("Token carries no GraphSentinel role.")
        return Principal.build(
            id=f"oidc:{claims['sub']}",
            name=str(claims.get("name") or claims["sub"]),
            role=role,
            tenant=self.settings.default_tenant,
            auth_method="oidc",
        )
