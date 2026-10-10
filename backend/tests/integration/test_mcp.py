"""MCP adapter via the SDK's in-memory client (real FalkorDB test graph)."""

from __future__ import annotations

import json

import mcp
import pytest

from app.mcp.server import build_server

pytestmark = pytest.mark.graph


def _payload(result) -> dict:
    return json.loads(result.content[0].text)


async def test_mcp_read_only_tools(harness) -> None:
    server = build_server(harness.settings)
    async with mcp.Client(server) as c:
        names = {t.name for t in (await c.list_tools()).tools}
        assert names == {
            "get_alert",
            "explore_neighborhood",
            "find_attack_paths",
            "find_related_incidents",
            "assess_impact",
            "get_evidence",
            "run_graph_algorithm",
        }
        assert "start_investigation" not in names
        out = _payload(await c.call_tool("find_attack_paths", {"source_id": "ALT-1001", "max_hops": 4}))
        assert out["paths"] and out["synthetic_data"] is True
        bad = _payload(await c.call_tool("explore_neighborhood", {"entity_id": "ALT-1001", "depth": 9}))
        assert "error" in bad
        inj = _payload(await c.call_tool("get_alert", {"alert_id": "x') DETACH DELETE n //"}))
        assert inj == {"error": "invalid entity id"}


async def test_mcp_write_tool_requires_opt_in_and_role(harness) -> None:
    viewer = harness.settings.model_copy(update={"mcp_enable_write_tools": True, "mcp_principal_role": "viewer"})
    async with mcp.Client(build_server(viewer)) as c:
        assert "start_investigation" not in {t.name for t in (await c.list_tools()).tools}
    inv = harness.settings.model_copy(update={"mcp_enable_write_tools": True, "mcp_principal_role": "investigator"})
    async with mcp.Client(build_server(inv)) as c:
        assert "start_investigation" in {t.name for t in (await c.list_tools()).tools}
