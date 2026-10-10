"""HTTP hardening: request ids, security headers, body-size limit, rate limiting, metrics.

Rate limiting here is a per-process token bucket keyed by session/bearer or client IP. With more
than one replica, enforce limits at the ingress (documented in docs/deployment.md).
"""

from __future__ import annotations

import re
import time
import uuid
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from app.core.config import Settings
from app.observability.logging import get_logger, request_id_var
from app.observability.metrics import HTTP_LATENCY, HTTP_REQUESTS

log = get_logger("http")
_RID = re.compile(r"^[A-Za-z0-9\-_.]{8,64}$")


class TokenBucket:
    def __init__(self, per_minute: int, max_keys: int = 10000) -> None:
        self.rate = per_minute / 60.0
        self.capacity = float(per_minute)
        self.buckets: dict[str, tuple[float, float]] = {}
        self.max_keys = max_keys

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        tokens, last = self.buckets.get(key, (self.capacity, now))
        tokens = min(self.capacity, tokens + (now - last) * self.rate)
        if len(self.buckets) > self.max_keys:
            self.buckets.clear()
        if tokens < 1:
            self.buckets[key] = (tokens, now)
            return False
        self.buckets[key] = (tokens - 1, now)
        return True


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
            if request.url.path.startswith("/api/") and not request.url.path.endswith(("/health", "/ready")):
                key = (
                    request.cookies.get("gs_session")
                    or request.headers.get("authorization")
                    or (request.client.host if request.client else "anon")
                )
                if not bucket.allow(key[-48:]):
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
