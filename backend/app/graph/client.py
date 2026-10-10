"""Async FalkorDB access with timeouts, metrics and error mapping.

Investigation tools only use `ro()` which executes `GRAPH.RO_QUERY`: FalkorDB rejects any
write in a read-only query, so a bug in a tool query cannot mutate the graph.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from falkordb.asyncio import FalkorDB
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import ResponseError
from redis.exceptions import TimeoutError as RedisTimeoutError

from app.core.config import Settings
from app.core.errors import GraphQueryError, GraphQueryTimeoutError, GraphUnavailableError
from app.observability.logging import get_logger
from app.observability.metrics import GRAPH_QUERY_LATENCY
from app.observability.tracing import tracer

log = get_logger(__name__)


class GraphClient:
    def __init__(self, settings: Settings, graph_name: str | None = None) -> None:
        self._settings = settings
        self.graph_name = graph_name or settings.falkordb_graph_name
        self.default_timeout_ms = settings.falkordb_query_timeout_ms
        self._db = FalkorDB(
            host=settings.falkordb_host,
            port=settings.falkordb_port,
            username=settings.falkordb_username,
            password=settings.falkordb_password.get_secret_value() if settings.falkordb_password else None,
            socket_timeout=max(5.0, settings.falkordb_query_timeout_ms / 1000 + 2),
            socket_connect_timeout=3.0,
            max_connections=settings.falkordb_max_connections,
        )
        self._graph = self._db.select_graph(self.graph_name)

    async def ping(self) -> bool:
        try:
            return bool(await asyncio.wait_for(self._db.connection.ping(), timeout=3))
        except Exception:
            return False

    async def close(self) -> None:
        try:
            await self._db.connection.aclose()
        except Exception:
            log.warning("graph.close_failed")

    async def ro(
        self, query: str, params: dict[str, Any] | None = None, *, op: str = "read", timeout_ms: int | None = None
    ) -> list[list[Any]]:
        return await self._run(query, params, read_only=True, op=op, timeout_ms=timeout_ms)

    async def rw(
        self, query: str, params: dict[str, Any] | None = None, *, op: str = "write", timeout_ms: int | None = None
    ) -> list[list[Any]]:
        return await self._run(query, params, read_only=False, op=op, timeout_ms=timeout_ms)

    async def _run(
        self, query: str, params: dict[str, Any] | None, *, read_only: bool, op: str, timeout_ms: int | None
    ) -> list[list[Any]]:
        timeout = int(timeout_ms or self.default_timeout_ms)
        fn = self._graph.ro_query if read_only else self._graph.query
        started = time.perf_counter()
        outcome = "ok"
        with tracer.start_as_current_span("graph.query", attributes={"graph.op": op, "graph.ro": read_only}):
            try:
                # Server-side timeout (FalkorDB aborts the query) plus a client-side guard.
                result = await asyncio.wait_for(fn(query, params or {}, timeout=timeout), timeout=timeout / 1000 + 2)
                return list(result.result_set or [])
            except (TimeoutError, RedisTimeoutError) as exc:
                outcome = "timeout"
                raise GraphQueryTimeoutError(details={"operation": op}) from exc
            except RedisConnectionError as exc:
                outcome = "unavailable"
                raise GraphUnavailableError() from exc
            except ResponseError as exc:
                msg = str(exc)
                if "timed out" in msg.lower():
                    outcome = "timeout"
                    raise GraphQueryTimeoutError(details={"operation": op}) from exc
                if read_only and "empty key" in msg.lower():
                    # The graph has not been created/seeded yet: a read legitimately returns nothing.
                    outcome = "empty_graph"
                    return []
                outcome = "error"
                # The raw message may echo query text; log it server-side only.
                log.error("graph.query_failed", operation=op, error=msg[:500])
                raise GraphQueryError(details={"operation": op}) from exc
            finally:
                GRAPH_QUERY_LATENCY.labels(operation=op, outcome=outcome).observe(time.perf_counter() - started)

    # ---- admin helpers (CLI / seeding only) -------------------------------------------
    async def delete_graph(self) -> None:
        try:
            await self._graph.delete()
        except ResponseError as exc:
            if "empty key" not in str(exc).lower() and "invalid graph" not in str(exc).lower():
                raise

    async def list_indices(self) -> list[list[Any]]:
        return await self.ro("CALL db.indexes()", op="list_indexes")

    async def list_constraints(self) -> list[dict[str, Any]]:
        try:
            return list(await self._graph.list_constraints())
        except ResponseError:
            return []

    async def create_unique_constraint(self, label: str, prop: str) -> None:
        try:
            await self._graph.create_node_unique_constraint(label, prop)
        except ResponseError as exc:
            if "already exists" not in str(exc).lower():
                raise
