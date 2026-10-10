"""HTTP API against a real FalkorDB with the full app (lifespan, middleware, auth, CSRF)."""

from __future__ import annotations

import asyncio
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from app.core.config import get_settings
from app.evaluation.harness import EVAL_ANCHOR
from app.graph.client import GraphClient
from app.graph.seed import seed
from app.main import create_app

pytestmark = pytest.mark.graph
GRAPH = "graphsentinel_apitest"


@pytest.fixture(scope="module")
async def client() -> AsyncIterator[httpx.AsyncClient]:
    tmp = Path(tempfile.mkdtemp(prefix="gs-api-"))
    settings = get_settings().model_copy(
        update={
            "falkordb_graph_name": GRAPH,
            "sqlite_path": str(tmp / "api.db"),
            "demo_mode": True,
            "app_env": "test",
            "llm_provider": "mock",
            "log_level": "WARNING",
            "rate_limit_per_minute": 10000,
            "max_request_bytes": 4096,
        }
    )
    g = GraphClient(settings)
    await g.delete_graph()
    await seed(g, settings.synthetic_data_dir, anchor=EVAL_ANCHOR, tenant="acme")
    await g.close()
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
            yield c


async def login(c: httpx.AsyncClient, user: str) -> dict[str, str]:
    r = await c.post("/api/v1/auth/demo-login", json={"user_id": user, "as_bearer": True})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


async def test_health_and_ready(client) -> None:
    assert (await client.get("/api/v1/health")).json() == {"status": "ok"}
    r = await client.get("/api/v1/ready")
    assert r.status_code == 200 and r.json()["checks"] == {"graph": True, "metadata_db": True}


async def test_requires_authentication(client) -> None:
    r = await client.get("/api/v1/alerts")
    assert r.status_code == 401
    body = r.json()["error"]
    assert body["code"] == "authentication_required" and body["request_id"]


async def test_security_headers(client) -> None:
    r = await client.get("/api/v1/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "x-request-id" in r.headers


async def test_alerts_pagination_and_filters(client) -> None:
    h = await login(client, "vera")
    r = await client.get("/api/v1/alerts?page_size=3&sort=severity", headers=h)
    d = r.json()
    assert d["total"] == 8 and len(d["items"]) == 3 and d["items"][0]["properties"]["severity"] == "high"
    r = await client.get("/api/v1/alerts?severity=low&status=closed", headers=h)
    assert [a["id"] for a in r.json()["items"]] == ["ALT-1007"]
    assert (await client.get("/api/v1/alerts?page_size=1000", headers=h)).status_code == 422


async def test_viewer_cannot_start_investigation(client) -> None:
    h = await login(client, "vera")
    r = await client.post("/api/v1/investigations", headers=h, json={"question": "Investigate ALT-1001"})
    assert r.status_code == 403


async def test_validation_and_not_found(client) -> None:
    h = await login(client, "alice")
    r = await client.post("/api/v1/investigations", headers=h, json={"question": "x", "target_id": "ALT-1001"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_failed"
    r = await client.post("/api/v1/investigations", headers=h, json={"question": "Investigate ALT-9999"})
    assert r.status_code == 404
    r = await client.post("/api/v1/investigations", headers=h, json={"question": "Investigate", "unknown": 1})
    assert r.status_code == 422
    assert (await client.get("/api/v1/entities/bad id!", headers=h)).status_code in (404, 422)


async def test_body_size_limit(client) -> None:
    h = await login(client, "alice")
    r = await client.post("/api/v1/investigations", headers=h, json={"question": "A" * 5000})
    assert r.status_code == 413


async def test_cookie_session_requires_csrf(client) -> None:
    r = await client.post("/api/v1/auth/demo-login", json={"user_id": "alice"})
    csrf = r.json()["csrf_token"]
    body = {"question": "Investigate ALT-1003"}
    no_csrf = await client.post("/api/v1/investigations", json=body)
    assert no_csrf.status_code == 403
    ok = await client.post("/api/v1/investigations", json=body, headers={"X-CSRF-Token": csrf})
    assert ok.status_code == 202
    client.cookies.clear()


async def test_full_investigation_and_approval_flow(client) -> None:
    alice, bob = await login(client, "alice"), await login(client, "bob")
    r = await client.post(
        "/api/v1/investigations", headers=alice, json={"question": "Investigate alert ALT-1001. Larger attack?"}
    )
    assert r.status_code == 202
    inv_id = r.json()["id"]
    for _ in range(100):
        d = (await client.get(f"/api/v1/investigations/{inv_id}", headers=alice)).json()
        if d["status"] not in ("queued", "running"):
            break
        await asyncio.sleep(0.1)
    assert d["status"] == "completed" and d["verdict"] == "likely_malicious"
    assert d["provider"]["is_mock"] is True
    g = (await client.get(f"/api/v1/investigations/{inv_id}/graph", headers=alice)).json()
    node_ids = {n["id"] for n in g["nodes"]}
    assert all(e["source"] in node_ids and e["target"] in node_ids for e in g["edges"])
    tr = (await client.get(f"/api/v1/investigations/{inv_id}/trace", headers=alice)).json()
    assert tr["integrity"]["valid"] is True and tr["events"][0]["kind"] == "investigation.created"
    ev = (await client.get(f"/api/v1/investigations/{inv_id}/evidence", headers=alice)).json()
    assert {e["id"] for e in ev["contradicting"]} >= {"EV-1005", "EV-1006"}
    rec = (await client.get(f"/api/v1/investigations/{inv_id}/recommendations", headers=alice)).json()
    action = rec["actions"][0]
    body = {"investigation_id": inv_id, "policy_version": rec["policy_version"], "confirm": True}
    # missing Idempotency-Key
    assert (await client.post(f"/api/v1/actions/{action['id']}/approve", headers=bob, json=body)).status_code == 422
    # confirm must be true
    bad = {**body, "confirm": False}
    r = await client.post(f"/api/v1/actions/{action['id']}/approve", headers={**bob, "Idempotency-Key": "z"}, json=bad)
    assert r.status_code == 422
    r = await client.post(
        f"/api/v1/actions/{action['id']}/approve", headers={**alice, "Idempotency-Key": "a1"}, json=body
    )
    assert r.status_code == 403
    r = await client.post(
        f"/api/v1/actions/{action['id']}/approve", headers={**bob, "Idempotency-Key": "b1"}, json=body
    )
    assert r.status_code == 200 and r.json()["status"] == "executed_simulation"
    assert r.json()["execution_result"]["external_systems_contacted"] == []
    r2 = await client.post(
        f"/api/v1/actions/{action['id']}/approve", headers={**bob, "Idempotency-Key": "b1"}, json=body
    )
    assert r2.json() == r.json()
    r3 = await client.post(
        f"/api/v1/actions/{action['id']}/approve", headers={**bob, "Idempotency-Key": "b2"}, json=body
    )
    assert r3.status_code == 409
    audit = (await client.get("/api/v1/audit/events?page_size=100", headers=bob)).json()
    types = [e["event_type"] for e in audit["items"]]
    assert "action.executed_simulation" in types and "action.decision_denied" in types
    assert (await client.get("/api/v1/audit/verify", headers=bob)).json()["valid"] is True
    # second investigation recalls the first through the graph
    r = await client.post("/api/v1/investigations", headers=alice, json={"question": "Re-check ALT-1002"})
    inv2 = r.json()["id"]
    for _ in range(100):
        d2 = (await client.get(f"/api/v1/investigations/{inv2}", headers=alice)).json()
        if d2["status"] not in ("queued", "running"):
            break
        await asyncio.sleep(0.1)
    assert any(p["investigation_id"] == inv_id for p in d2["prior_investigations"])


async def test_diagnostics_admin_only_and_redacted(client) -> None:
    assert (await client.get("/api/v1/diagnostics", headers=await login(client, "alice"))).status_code == 403
    r = await client.get("/api/v1/diagnostics", headers=await login(client, "ada"))
    assert r.status_code == 200
    text = r.text
    settings = get_settings()
    for secret in (settings.falkordb_password, settings.azure_openai_api_key, settings.auth_secret_key):
        if secret is not None:
            assert secret.get_secret_value() not in text


async def test_entity_neighbors_and_schema(client) -> None:
    h = await login(client, "vera")
    r = await client.get("/api/v1/entities/dev-wks-0142/neighbors?depth=1", headers=h)
    d = r.json()
    assert r.status_code == 200 and any(n["id"] == "dev-srv-fin-01" for n in d["nodes"])
    assert (await client.get("/api/v1/entities/dev-wks-0142/neighbors?depth=9", headers=h)).status_code == 422
    s = (await client.get("/api/v1/graph/schema", headers=h)).json()
    assert {lbl["label"] for lbl in s["labels"]} >= {"SecurityAlert", "Evidence", "ResponseAction"}
    assert any(c["label"] == "Entity" for c in s["constraints"])
