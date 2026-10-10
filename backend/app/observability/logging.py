"""Structured JSON logging with request/investigation correlation and secret redaction."""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Mapping, MutableMapping
from contextvars import ContextVar
from typing import Any

import structlog

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
investigation_id_var: ContextVar[str | None] = ContextVar("investigation_id", default=None)

_SENSITIVE_KEYS = re.compile(
    r"(api[_-]?key|authorization|password|passwd|secret|cookie|^token$|access[_-]?token|refresh[_-]?token|csrf)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)bearer\s+[a-z0-9\-._~+/]+=*")


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if _SENSITIVE_KEYS.search(str(k)) else _redact(v)) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_redact(v) for v in value]
    if isinstance(value, str):
        return _BEARER.sub("Bearer [REDACTED]", value)
    return value


def _redaction_processor(_: Any, __: str, event_dict: MutableMapping[str, Any]) -> Mapping[str, Any]:
    return _redact(dict(event_dict))  # type: ignore[no-any-return]


def _context_processor(_: Any, __: str, event_dict: MutableMapping[str, Any]) -> Mapping[str, Any]:
    rid = request_id_var.get()
    if rid:
        event_dict.setdefault("request_id", rid)
    iid = investigation_id_var.get()
    if iid:
        event_dict.setdefault("investigation_id", iid)
    return event_dict


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level, force=True)
    # Third-party libraries can be chatty and may log request details.
    for noisy in ("httpx", "httpx2", "httpcore", "openai", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _context_processor,
            _redaction_processor,
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level)),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> Any:
    return structlog.get_logger(name)
