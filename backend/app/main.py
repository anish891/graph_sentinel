"""GraphSentinel AI — FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.middleware import install_middleware
from app.api.routes import actions, audit, auth, graph, investigations, system
from app.api.state import AppState
from app.core.config import Settings, get_settings
from app.core.errors import AppError
from app.observability.logging import configure_logging, get_logger, request_id_var
from app.observability.tracing import configure_tracing

log = get_logger(__name__)

API_DESCRIPTION = """
Explainable, graph-native security investigation agent. All data is **synthetic**.
Response actions are **simulated** and require human approval. Authenticate with a demo session
(`POST /api/v1/auth/demo-login`) or an OIDC bearer token depending on `AUTH_MODE`.
"""


def _error(status: int, code: str, message: str, details: dict[str, Any] | None = None) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={
            "error": {"code": code, "message": message, "request_id": request_id_var.get(), "details": details or {}}
        },
    )


def create_app(settings: Settings | None = None, provider_factory: Any = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    configure_tracing(settings.otel_exporter_otlp_endpoint)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        container = AppState.build(settings, provider_factory)
        await container.db.connect()
        interrupted = await container.investigation_store.mark_interrupted()
        if interrupted:
            log.warning("startup.interrupted_investigations_failed", count=interrupted)
        for issue in settings.config_issues():
            log.warning("config.issue", setting=issue.setting, severity=issue.severity, message=issue.message)
        if not await container.graph.ping():
            log.error("startup.falkordb_unreachable", host=settings.falkordb_host, port=settings.falkordb_port)
        app.state.container = container
        log.info(
            "startup.complete",
            env=settings.app_env,
            llm=settings.effective_llm_provider,
            auth=settings.auth_mode,
            demo=settings.demo_mode,
        )
        try:
            yield
        finally:
            await container.investigations.shutdown()
            await container.graph.close()
            await container.db.close()
            log.info("shutdown.complete")

    app = FastAPI(
        title="GraphSentinel AI API",
        version="0.1.0",
        description=API_DESCRIPTION,
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/v1/openapi.json",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Authorization", "X-CSRF-Token", "Idempotency-Key", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
    )
    install_middleware(app, settings)

    @app.exception_handler(AppError)
    async def app_error(_: Request, exc: AppError) -> JSONResponse:
        if exc.status_code >= 500:
            log.warning("request.app_error", code=exc.code, message=exc.message)
        return _error(exc.status_code, exc.code, exc.message, exc.details)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [
            {"loc": [str(p) for p in e.get("loc", [])], "msg": str(e.get("msg")), "type": e.get("type")}
            for e in exc.errors()[:20]
        ]
        return _error(422, "validation_failed", "Request validation failed.", {"errors": errors})

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
        return _error(exc.status_code, code, str(exc.detail) if exc.status_code < 500 else "Server error.")

    @app.exception_handler(Exception)
    async def unhandled(_: Request, exc: Exception) -> JSONResponse:
        log.exception("request.unhandled", error_type=type(exc).__name__)
        return _error(500, "internal_error", "An internal error occurred.")

    api = APIRouter(prefix="/api/v1")
    for module in (system, auth, graph, investigations, actions, audit):
        api.include_router(module.router)
    app.include_router(api)
    return app


app = create_app()
