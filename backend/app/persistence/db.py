"""SQLite persistence for transactional application metadata.

Why a relational store at all? FalkorDB is authoritative for the security graph and holds a
projection of investigations/actions for graph-native memory. The following need ACID
transactions with compare-and-set semantics, which this store provides:

* the hash-chained audit log (strict ordering, append-only),
* action approval state transitions and idempotency keys (no double execution),
* full investigation documents and per-step traces (large JSON documents).

SQLite runs embedded (no extra server). For multi-replica deployments swap it for PostgreSQL
(the SQL here is portable apart from the PRAGMAs); see docs/deployment.md.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import aiosqlite

from app.observability.logging import get_logger

log = get_logger(__name__)

MIGRATIONS: list[tuple[int, str, str]] = [
    (
        1,
        "initial schema",
        """
    CREATE TABLE investigations (
        id TEXT PRIMARY KEY,
        tenant TEXT NOT NULL,
        status TEXT NOT NULL,
        question TEXT NOT NULL,
        target_id TEXT NOT NULL,
        requested_by TEXT NOT NULL,
        provider_name TEXT NOT NULL,
        provider_is_mock INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        completed_at TEXT,
        verdict TEXT,
        risk_score INTEGER,
        risk_band TEXT,
        result_json TEXT NOT NULL,
        error TEXT
    );
    CREATE INDEX ix_investigations_tenant_created ON investigations(tenant, created_at DESC);
    CREATE INDEX ix_investigations_target ON investigations(tenant, target_id);

    CREATE TABLE trace_events (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL REFERENCES investigations(id),
        seq INTEGER NOT NULL,
        ts TEXT NOT NULL,
        kind TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        hash TEXT NOT NULL,
        UNIQUE (investigation_id, seq)
    );

    CREATE TABLE actions (
        id TEXT PRIMARY KEY,
        tenant TEXT NOT NULL,
        investigation_id TEXT NOT NULL REFERENCES investigations(id),
        action_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        status TEXT NOT NULL,
        policy_version TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        version INTEGER NOT NULL DEFAULT 1,
        doc_json TEXT NOT NULL
    );
    CREATE INDEX ix_actions_tenant_status ON actions(tenant, status);
    CREATE INDEX ix_actions_investigation ON actions(investigation_id);

    CREATE TABLE idempotency_keys (
        key TEXT NOT NULL,
        principal_id TEXT NOT NULL,
        scope TEXT NOT NULL,
        request_hash TEXT NOT NULL,
        status_code INTEGER NOT NULL,
        response_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (principal_id, scope, key)
    );

    CREATE TABLE audit_events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL UNIQUE,
        ts TEXT NOT NULL,
        actor TEXT NOT NULL,
        actor_role TEXT,
        tenant TEXT NOT NULL,
        event_type TEXT NOT NULL,
        resource_type TEXT NOT NULL,
        resource_id TEXT,
        request_id TEXT,
        details_json TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        hash TEXT NOT NULL
    );
    CREATE INDEX ix_audit_tenant_seq ON audit_events(tenant, seq DESC);
    CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events
        BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
    CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events
        BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
    """,
    ),
]


class Database:
    def __init__(self, path: str) -> None:
        self.path = path
        self._conn: aiosqlite.Connection | None = None
        # Serialises write transactions within this process (SQLite has a single writer).
        self.write_lock = asyncio.Lock()

    async def connect(self) -> None:
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self.path, isolation_level=None)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._conn.execute("PRAGMA busy_timeout=5000")
        await self._conn.execute("PRAGMA synchronous=NORMAL")
        await self.migrate()

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("database not connected")
        return self._conn

    async def migrate(self) -> None:
        await self.conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT, applied_at TEXT)"
        )
        rows = await self.fetchall("SELECT version FROM schema_migrations")
        applied = {r["version"] for r in rows}
        for version, name, sql in MIGRATIONS:
            if version in applied:
                continue
            # executescript() cannot run inside an outer transaction (it commits first), so each
            # migration is one atomic script. Values are code constants, not input.
            safe_name = name.replace("'", "''")
            async with self.write_lock:
                try:
                    await self.conn.executescript(
                        f"BEGIN IMMEDIATE;\n{sql}\nINSERT INTO schema_migrations(version, name, applied_at) "
                        f"VALUES ({int(version)}, '{safe_name}', datetime('now'));\nCOMMIT;"
                    )
                except Exception:
                    if self.conn.in_transaction:
                        await self.conn.execute("ROLLBACK")
                    raise
            log.info("db.migrated", version=version, name=name)

    async def reset_all(self) -> None:
        """Demo reset: drop every table in place and re-run migrations.

        Never unlink the database file — a running API process holding it open would keep writing
        to the deleted inode and silently lose data. Dropping through SQLite is seen by all
        connections. (DROP TABLE is permitted; the append-only triggers only block UPDATE/DELETE.)
        """
        async with self.write_lock:
            rows = await self.fetchall(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
            await self.conn.execute("PRAGMA foreign_keys=OFF")
            for r in rows:
                await self.conn.execute(f'DROP TABLE IF EXISTS "{r["name"]}"')
            await self.conn.execute("PRAGMA foreign_keys=ON")
        await self.migrate()

    async def ping(self) -> bool:
        try:
            await self.fetchone("SELECT 1 AS ok")
            return True
        except Exception:
            return False

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[aiosqlite.Connection]:
        """IMMEDIATE transaction: takes the write lock up front, so check-then-write is atomic."""
        async with self.write_lock:
            await self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self.conn
            except BaseException:
                await self.conn.execute("ROLLBACK")
                raise
            else:
                await self.conn.execute("COMMIT")

    async def fetchone(self, sql: str, params: Iterable[Any] = ()) -> aiosqlite.Row | None:
        async with self.conn.execute(sql, tuple(params)) as cur:
            return await cur.fetchone()

    async def fetchall(self, sql: str, params: Iterable[Any] = ()) -> list[aiosqlite.Row]:
        async with self.conn.execute(sql, tuple(params)) as cur:
            return list(await cur.fetchall())
