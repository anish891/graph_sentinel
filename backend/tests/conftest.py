from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest

from app.core.config import get_settings


def _falkordb_up() -> bool:
    from app.graph.client import GraphClient

    async def ping() -> bool:
        c = GraphClient(get_settings(), graph_name="graphsentinel_probe")
        try:
            return await c.ping()
        finally:
            await c.close()

    try:
        return asyncio.run(ping())
    except Exception:
        return False


FALKORDB_AVAILABLE = _falkordb_up()


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    skip = pytest.mark.skip(reason="FalkorDB not reachable (run `make up` or `docker compose up -d falkordb`)")
    for item in items:
        if "graph" in item.keywords and not FALKORDB_AVAILABLE:
            item.add_marker(skip)


@pytest.fixture(scope="session")
async def harness() -> AsyncIterator[object]:
    from app.evaluation.harness import build_harness

    h = await build_harness(graph_name="graphsentinel_test")
    yield h
    await h.close()
