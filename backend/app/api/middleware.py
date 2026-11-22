"""HTTP hardening: request ids, security headers, body-size limit, rate limiting, metrics.

Rate limiting here is a per-process token bucket keyed by the verified session principal, else by
client IP (see `rate_limit_key`). With more than one replica, enforce limits at the ingress
(documented in docs/deployment.md).
"""

from __future__ import annotations

import re
import time
import uuid
from collections import OrderedDict
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from app.core.config import Settings
from app.core.errors import AppError
from app.observability.logging import get_logger, request_id_var
from app.observability.metrics import HTTP_LATENCY, HTTP_REQUESTS

log = get_logger("http")
_RID = re.compile(r"^[A-Za-z0-9\-_.]{8,64}$")


class TokenBucket:
    """Per-key token bucket with least-recently-used eviction.

    Eviction drops only the least recently seen keys. (Clearing every bucket when the table fills up
    would let anyone reset everyone's limits by flooding the table with new keys.)
    """

    def __init__(self, per_minute: int, max_keys: int = 10000) -> None:
        self.rate = per_minute / 60.0
        self.capacity = float(per_minute)
        self.buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self.max_keys = max_keys

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        tokens, last = self.buckets.pop(key, (self.capacity, now))
        tokens = min(self.capacity, tokens + (now - last) * self.rate)
        allowed = tokens >= 1
        self.buckets[key] = (tokens - 1 if allowed else tokens, now)  # re-inserted as most recent
        while len(self.buckets) > self.max_keys:
            self.buckets.popitem(last=False)
        return allowed


def rate_limit_key(request: Request) -> str:
    """Key on the *verified* demo session principal, else on the client address.

    The raw cookie or Authorization header must not be the key: an unauthenticated client could send a
    new random value per request and get a fresh bucket each time. Bearer tokens are not verified here
    (OIDC verification may need a network call), so bearer and anonymous traffic is keyed by client IP.
    """
    cookie = request.cookies.get("gs_session")
    container = getattr(request.app.state, "container", None)
    if cookie and container is not None and container.settings.auth_mode == "demo":
        try:
            principal, _ = container.tokens.verify_demo(cookie)
        except AppError:
            pass
        else:
            return f"user:{principal.id}"
    return f"ip:{request.client.host if request.client else 'unknown'}"


def _error(status: int, code: str, message: str, rid: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "request_id": rid, "details": {}}},
        headers={"X-Request-ID": rid},
    )


def install_middleware(app: FastAPI, settings: Settings) -> None:
    bucket = TokenBucket(settings.rate_limit_per_minute)

    @app.middleware("http")
    async def hardening(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        incoming = request.headers.get("x-request-id", "")
        rid = incoming if _RID.match(incoming) else uuid.uuid4().hex
        token = request_id_var.set(rid)
        started = time.perf_counter()
        route = "unmatched"
        status = 500
        try:
            length = request.headers.get("content-length")
            if length is not None and (not length.isdigit() or int(length) > settings.max_request_bytes):
                status = 413
                return _error(413, "payload_too_large", "Request body too large.", rid)
            if request.method in ("POST", "PUT", "PATCH") and length is None:
                body = await request.body()
                if len(body) > settings.max_request_bytes:
                    status = 413
                    return _error(413, "payload_too_large", "Request body too large.", rid)
            limited = request.url.path.startswith("/api/") and not request.url.path.endswith(("/health", "/ready"))
            if limited and not bucket.allow(rate_limit_key(request)):
                status = 429
                return _error(429, "rate_limited", "Too many requests.", rid)
            response = await call_next(request)
            status = response.status_code
            r = request.scope.get("route")
            route = getattr(r, "path", "unmatched")
            response.headers["X-Request-ID"] = rid
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["Cache-Control"] = "no-store"
            response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
            if not request.url.path.startswith(("/api/docs", "/api/redoc")):
                response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
            return response
        finally:
            elapsed = time.perf_counter() - started
            HTTP_REQUESTS.labels(method=request.method, route=route, status=str(status)).inc()
            HTTP_LATENCY.labels(method=request.method, route=route).observe(elapsed)
            log.info(
                "http.request",
                method=request.method,
                path=request.url.path,
                status=status,
                duration_ms=round(elapsed * 1000, 1),
            )
            request_id_var.reset(token)
