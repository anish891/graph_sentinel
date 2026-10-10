"""Evaluation harness: an isolated, deterministic environment (separate graph + temp SQLite)."""

from __future__ import annotations

import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.agents.llm.base import LLMProvider
from app.agents.llm.mock import MockLLMProvider
from app.api.state import AppState
from app.auth.principal import Principal
from app.core.config import Settings, get_settings
from app.graph.seed import seed
from app.schemas.investigation import InvestigationRequest, InvestigationResult

# Fixed anchor => identical relative timestamps on every run => reproducible scores.
EVAL_ANCHOR = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)


def principal(user: str, role: str, person: str | None = None) -> Principal:
    return Principal.build(
        id=f"demo:{user}", name=user.title(), role=role, tenant="acme", auth_method="demo", person_id=person
    )


ALICE = principal("alice", "investigator", "per-alice")
BOB = principal("bob", "approver", "per-bob")
VERA = principal("vera", "viewer", "per-vera")


@dataclass
class Harness:
    state: AppState
    settings: Settings
    provider_holder: dict[str, Callable[[], LLMProvider]]

    def use_provider(self, factory: Callable[[], LLMProvider]) -> None:
        self.provider_holder["factory"] = factory

    async def investigate(
        self, question: str, target_id: str | None = None, who: Principal = ALICE
    ) -> InvestigationResult:
        created = await self.state.investigations.create(
            who, InvestigationRequest(question=question, target_id=target_id)
        )
        await self.state.investigations.wait(
            created.id,
            max_seconds=self.settings.agent_investigation_timeout_seconds + 60,
            cancel_on_timeout=True,
        )
        return await self.state.investigations.get(who, created.id)

    async def close(self) -> None:
        await self.state.investigations.shutdown()
        await self.state.graph.close()
        await self.state.db.close()


async def build_harness(
    graph_name: str = "graphsentinel_eval", live: bool = False, overrides: dict[str, Any] | None = None
) -> Harness:
    base = get_settings()
    tmp = Path(tempfile.mkdtemp(prefix="gs-eval-"))
    values: dict[str, Any] = {
        "falkordb_graph_name": graph_name,
        "sqlite_path": str(tmp / "eval.db"),
        "demo_mode": True,
        "app_env": "test",
        "llm_provider": base.llm_provider if live else "mock",
        "log_level": "WARNING",
        "agent_investigation_timeout_seconds": base.agent_investigation_timeout_seconds if live else 60,
    }
    values.update(overrides or {})
    settings = base.model_copy(update=values)
    holder: dict[str, Callable[[], LLMProvider]] = {}
    if not live:
        holder["factory"] = MockLLMProvider

    def factory() -> LLMProvider:
        if "factory" in holder:
            return holder["factory"]()
        from app.agents.llm.factory import build_provider

        return build_provider(settings)

    state = AppState.build(settings, factory)
    await state.graph.delete_graph()
    await seed(state.graph, settings.synthetic_data_dir, anchor=EVAL_ANCHOR, tenant="acme")
    await state.db.connect()
    return Harness(state=state, settings=settings, provider_holder=holder)
