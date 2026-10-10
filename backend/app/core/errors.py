"""Domain exceptions. The API layer maps these to redacted HTTP error responses."""

from __future__ import annotations

from typing import Any


class AppError(Exception):
    status_code = 500
    code = "internal_error"
    public_message = "An internal error occurred."

    def __init__(self, message: str | None = None, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message or self.public_message)
        self.message = message or self.public_message
        self.details = details or {}


class NotFoundError(AppError):
    status_code = 404
    code = "not_found"
    public_message = "Resource not found."


class ValidationFailedError(AppError):
    status_code = 422
    code = "validation_failed"
    public_message = "Request validation failed."


class AmbiguousTargetError(AppError):
    status_code = 422
    code = "ambiguous_target"
    public_message = "The investigation target could not be determined unambiguously."


class AuthenticationRequiredError(AppError):
    status_code = 401
    code = "authentication_required"
    public_message = "Authentication required."


class PermissionDeniedError(AppError):
    status_code = 403
    code = "permission_denied"
    public_message = "You do not have permission to perform this operation."


class ConflictError(AppError):
    status_code = 409
    code = "conflict"
    public_message = "The request conflicts with the current state of the resource."


class RateLimitedError(AppError):
    status_code = 429
    code = "rate_limited"
    public_message = "Too many requests."


class DependencyUnavailableError(AppError):
    status_code = 503
    code = "dependency_unavailable"
    public_message = "A required dependency is unavailable."


class GraphUnavailableError(DependencyUnavailableError):
    code = "graph_unavailable"
    public_message = "The graph database is unavailable."


class GraphQueryTimeoutError(AppError):
    status_code = 504
    code = "graph_query_timeout"
    public_message = "A graph query exceeded its time limit."


class GraphQueryError(AppError):
    status_code = 502
    code = "graph_query_failed"
    public_message = "A graph query failed."


class LLMError(AppError):
    status_code = 502
    code = "llm_error"
    public_message = "The language model provider returned an error."

    def __init__(
        self, message: str | None = None, *, retryable: bool = False, details: dict[str, Any] | None = None
    ) -> None:
        super().__init__(message, details=details)
        self.retryable = retryable


class LLMConfigurationError(LLMError):
    status_code = 503
    code = "llm_not_configured"
    public_message = "No language model provider is configured."
