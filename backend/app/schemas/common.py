from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

MAX_PAGE_SIZE = 100

# Stable identifier pattern used by every graph entity and app record.
ENTITY_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,127}$"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Page[T](BaseModel):
    items: list[T]
    total: int
    page: int
    page_size: int


class ErrorDetail(BaseModel):
    code: str
    message: str
    request_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    error: ErrorDetail


class Ref(BaseModel):
    """A reference from a claim to the record that supports it."""

    type: Literal["node", "edge", "evidence", "path", "tool_call", "calculation"]
    id: str
