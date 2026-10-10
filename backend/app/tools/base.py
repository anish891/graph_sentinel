"""Tool registry primitives.

The model may only *select* a registered tool and supply arguments. Arguments are validated
against a strict Pydantic model (unknown fields rejected) before anything executes. The
registry is constructed in code; nothing read from the graph or from a prompt can add,
remove or modify tools.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict

from app.agents.context import InvestigationContext
from app.core.config import Settings
from app.graph.repository import GraphRepository


class ToolArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


@dataclass
class ToolDeps:
    repo: GraphRepository
    settings: Settings


@dataclass
class ToolOutput:
    summary: str
    data: dict[str, Any]
    executed_in: str
    node_ids: list[str] = field(default_factory=list)
    path_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)


class ToolValidationError(ValueError):
    """Arguments are syntactically valid but violate a runtime limit or precondition."""


class Tool[A: ToolArgs](ABC):
    name: ClassVar[str]
    description: ClassVar[str]
    args_model: ClassVar[type[ToolArgs]]
    read_only: ClassVar[bool] = True

    @abstractmethod
    async def run(self, args: A, ctx: InvestigationContext, deps: ToolDeps) -> ToolOutput: ...

    def json_schema(self) -> dict[str, Any]:
        schema = self.args_model.model_json_schema()
        schema.pop("title", None)
        return schema


class ToolRegistry:
    def __init__(self, tools: list[Tool[Any]]) -> None:
        self._tools: dict[str, Tool[Any]] = {}
        for tool in tools:
            if tool.name in self._tools:
                raise ValueError(f"duplicate tool {tool.name}")
            self._tools[tool.name] = tool

    def get(self, name: str) -> Tool[Any] | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return list(self._tools)

    def specs(self) -> list[dict[str, Any]]:
        return [
            {"name": t.name, "description": t.description, "parameters": t.json_schema()} for t in self._tools.values()
        ]

    def read_only_subset(self) -> ToolRegistry:
        return ToolRegistry([t for t in self._tools.values() if t.read_only])
