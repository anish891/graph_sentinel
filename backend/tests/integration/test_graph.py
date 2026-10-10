"""Graph layer against a real FalkorDB: seeding, read-only enforcement, tenancy, algorithms."""

from __future__ import annotations

import pytest

from app.core.errors import GraphQueryError
from app.graph.repository import GraphRepository
from app.graph.seed import seed, validate_graph

pytestmark = pytest.mark.graph


async def test_seed_is_idempotent(harness) -> None:
    g = harness.state.graph
    before = await g.ro("MATCH (n:Entity) RETURN count(n)")
    edges_before = await g.ro("MATCH ()-[r]->() WHERE r.synthetic = true RETURN count(r)")
    await seed(g, harness.settings.synthetic_data_dir, tenant="acme")
    assert await g.ro("MATCH (n:Entity) RETURN count(n)") == before
    assert await g.ro("MATCH ()-[r]->() WHERE r.synthetic = true RETURN count(r)") == edges_before
    assert await validate_graph(g, harness.settings.synthetic_data_dir) == []


async def test_unique_constraint_enforced(harness) -> None:
    with pytest.raises(GraphQueryError):
        await harness.state.graph.rw("CREATE (:Entity:Device {id: 'dev-wks-0142'})")


async def test_read_only_queries_cannot_write(harness) -> None:
    with pytest.raises(GraphQueryError):
        await harness.state.graph.ro("CREATE (:Entity {id: 'evil'})")
    assert await harness.state.graph.ro("MATCH (n {id: 'evil'}) RETURN count(n)") == [[0]]


async def test_tenant_isolation(harness) -> None:
    other = GraphRepository(harness.state.graph, "other-tenant")
    assert await other.get_entity("ALT-1001") is None
    nodes, total = await other.list_alerts(
        severity=None, status=None, q=None, sort="id", descending=False, offset=0, limit=10
    )
    assert nodes == [] and total == 0


async def test_parameters_are_not_interpolated(harness) -> None:
    repo = GraphRepository(harness.state.graph, "acme")
    assert await repo.search("') MATCH (n) DETACH DELETE n //") == []
    assert await repo.get_entity("ALT-1001") is not None


async def test_paths_exclude_historical_by_default(harness) -> None:
    repo = GraphRepository(harness.state.graph, "acme")
    as_of = await repo.as_of(True, __import__("app.core.timeutil", fromlist=["utcnow"]).utcnow())
    cur = await repo.paths_from("ip-10-20-4-88", target_labels=["Device"], max_hops=1, as_of=as_of, limit=10)
    hist = await repo.paths_from(
        "ip-10-20-4-88", target_labels=["Device"], max_hops=1, as_of=as_of, limit=10, include_historical=True
    )
    assert {p.path.end_id for p in cur} == {"dev-wks-0201"}
    assert {p.path.end_id for p in hist} == {"dev-wks-0201", "dev-wks-0077"}
    assert any(p.path.contains_historical for p in hist)


async def test_falkordb_algorithms(harness) -> None:
    repo = GraphRepository(harness.state.graph, "acme")
    comp = await repo.component_of(["dev-orphan-001", "dev-lab-099", "ALT-1001"])
    assert comp["dev-orphan-001"]["isolated"] is True
    assert comp["dev-lab-099"]["critical_or_high_assets"] == []
    assert "svc-ledger-db" in comp["ALT-1001"]["critical_or_high_assets"]
    ranked = await repo.betweenness(5)
    assert ranked and all(score > 0 for _, score in ranked)
