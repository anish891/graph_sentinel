"""Application container: built once in the lifespan, injected into routes."""

from __future__ import annotations

from dataclasses import dataclass

from app.actions.executor import SimulationActionExecutor
from app.agents.llm.base import LLMProvider
from app.agents.llm.factory import build_provider
from app.auth.tokens import TokenService
from app.core.config import Settings
from app.graph.client import GraphClient
from app.graph.projection import GraphProjection
from app.persistence.db import Database
from app.persistence.stores import InvestigationStore, TraceStore
from app.services.actions import ActionService
from app.services.audit import AuditService
from app.services.investigations import InvestigationService
from app.tools.registry import build_registry


@dataclass
class AppState:
    settings: Settings
    graph: GraphClient
    db: Database
    tokens: TokenService
    audit: AuditService
    investigations: InvestigationService
    actions: ActionService
    investigation_store: InvestigationStore
    traces: TraceStore

    @classmethod
    def build(cls, settings: Settings, provider_factory: object | None = None) -> AppState:
        graph = GraphClient(settings)
        db = Database(settings.sqlite_path)
        audit = AuditService(db)
        executor = SimulationActionExecutor()

        def default_factory() -> LLMProvider:
            return build_provider(settings)

        investigations = InvestigationService(
            settings=settings,
            graph=graph,
            db=db,
            audit=audit,
            provider_factory=provider_factory or default_factory,
            registry=build_registry(),
            executor=executor,
        )
        return cls(
            settings=settings,
            graph=graph,
            db=db,
            tokens=TokenService(settings),
            audit=audit,
            investigations=investigations,
            actions=ActionService(db, audit, executor, GraphProjection(graph)),
            investigation_store=InvestigationStore(db),
            traces=TraceStore(db),
        )
