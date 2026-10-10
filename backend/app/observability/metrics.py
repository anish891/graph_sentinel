"""Prometheus metrics (exposed at /api/v1/metrics, admin only)."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Histogram

REGISTRY = CollectorRegistry(auto_describe=True)

HTTP_REQUESTS = Counter("gs_http_requests_total", "HTTP requests", ["method", "route", "status"], registry=REGISTRY)
HTTP_LATENCY = Histogram("gs_http_request_seconds", "HTTP request latency", ["method", "route"], registry=REGISTRY)
GRAPH_QUERY_LATENCY = Histogram(
    "gs_graph_query_seconds",
    "FalkorDB query latency",
    ["operation", "outcome"],
    registry=REGISTRY,
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
LLM_LATENCY = Histogram(
    "gs_llm_call_seconds",
    "LLM call latency",
    ["provider", "api", "outcome"],
    registry=REGISTRY,
    buckets=(0.05, 0.25, 0.5, 1, 2, 5, 10, 20, 45, 90),
)
LLM_TOKENS = Counter("gs_llm_tokens_total", "LLM tokens", ["provider", "kind"], registry=REGISTRY)
TOOL_CALLS = Counter("gs_tool_calls_total", "Agent tool calls", ["tool", "outcome"], registry=REGISTRY)
INVESTIGATIONS = Counter("gs_investigations_total", "Investigations by terminal status", ["status"], registry=REGISTRY)
INVESTIGATION_LATENCY = Histogram(
    "gs_investigation_seconds",
    "Investigation duration",
    ["status"],
    registry=REGISTRY,
    buckets=(0.5, 1, 2, 5, 10, 20, 40, 80, 160, 320),
)
ACTIONS = Counter("gs_actions_total", "Action lifecycle transitions", ["transition"], registry=REGISTRY)
