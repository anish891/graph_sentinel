"""Append-only, hash-chained audit log."""

from __future__ import annotations

import json
from typing import Any

import aiosqlite

from app.audit.chain import GENESIS_HASH, chain_hash
from app.core.timeutil import now_iso
from app.observability.logging import request_id_var
from app.persistence.db import Database
from app.persistence.stores import new_id
from app.schemas.audit import AuditEvent, ChainVerification


def _record(e: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "id",
        "ts",
        "actor",
        "actor_role",
        "tenant",
        "event_type",
        "resource_type",
        "resource_id",
        "request_id",
        "details",
    )
    return {k: e[k] for k in keys}


class AuditService:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def record(
        self,
        *,
        actor: str,
        actor_role: str | None,
        tenant: str,
        event_type: str,
        resource_type: str,
        resource_id: str | None,
        details: dict[str, Any] | None = None,
        conn: aiosqlite.Connection | None = None,
    ) -> AuditEvent:
        """Append an event. Pass `conn` to include it in a caller's transaction (atomic with a state change)."""
        if conn is not None:
            return await self._append(
                conn, actor, actor_role, tenant, event_type, resource_type, resource_id, details or {}
            )
        async with self.db.transaction() as c:
            return await self._append(
                c, actor, actor_role, tenant, event_type, resource_type, resource_id, details or {}
            )

    async def _append(
        self,
        conn: aiosqlite.Connection,
        actor: str,
        actor_role: str | None,
        tenant: str,
        event_type: str,
        resource_type: str,
        resource_id: str | None,
        details: dict[str, Any],
    ) -> AuditEvent:
        async with conn.execute("SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1") as cur:
            last = await cur.fetchone()
        prev = last["hash"] if last else GENESIS_HASH
        event = {
            "id": new_id("aud"),
            "ts": now_iso(),
            "actor": actor,
            "actor_role": actor_role,
            "tenant": tenant,
            "event_type": event_type,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "request_id": request_id_var.get(),
            "details": details,
        }
        h = chain_hash(prev, _record(event))
        cur2 = await conn.execute(
            "INSERT INTO audit_events (id, ts, actor, actor_role, tenant, event_type, resource_type, resource_id, "
            "request_id, details_json, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                event["id"],
                event["ts"],
                actor,
                actor_role,
                tenant,
                event_type,
                resource_type,
                resource_id,
                event["request_id"],
                json.dumps(details, default=str),
                prev,
                h,
            ),
        )
        return AuditEvent(**event, seq=int(cur2.lastrowid or 0), prev_hash=prev, hash=h)

    async def list_page(
        self, tenant: str, *, offset: int, limit: int, event_type: str | None = None, resource_id: str | None = None
    ) -> tuple[list[AuditEvent], int]:
        where, params = ["tenant = ?"], [tenant]
        if event_type:
            where.append("event_type = ?")
            params.append(event_type)
        if resource_id:
            where.append("resource_id = ?")
            params.append(resource_id)
        clause = " AND ".join(where)
        total = await self.db.fetchone(f"SELECT count(*) AS c FROM audit_events WHERE {clause}", params)
        rows = await self.db.fetchall(
            f"SELECT * FROM audit_events WHERE {clause} ORDER BY seq DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        )
        return [self._row(r) for r in rows], int(total["c"]) if total else 0

    @staticmethod
    def _row(r: aiosqlite.Row) -> AuditEvent:
        return AuditEvent(
            id=r["id"],
            seq=r["seq"],
            ts=r["ts"],
            actor=r["actor"],
            actor_role=r["actor_role"],
            tenant=r["tenant"],
            event_type=r["event_type"],
            resource_type=r["resource_type"],
            resource_id=r["resource_id"],
            request_id=r["request_id"],
            details=json.loads(r["details_json"]),
            prev_hash=r["prev_hash"],
            hash=r["hash"],
        )

    async def verify_chain(self, batch: int = 1000) -> ChainVerification:
        prev = GENESIS_HASH
        checked = 0
        last_seq = 0
        while True:
            rows = await self.db.fetchall(
                "SELECT * FROM audit_events WHERE seq > ? ORDER BY seq LIMIT ?", (last_seq, batch)
            )
            if not rows:
                break
            for r in rows:
                e = self._row(r)
                checked += 1
                if e.prev_hash != prev or chain_hash(prev, _record(e.model_dump())) != e.hash:
                    return ChainVerification(
                        valid=False,
                        checked=checked,
                        head_hash=None,
                        first_invalid_seq=e.seq,
                        reason="hash mismatch or broken link",
                    )
                prev = e.hash
                last_seq = e.seq
        return ChainVerification(valid=True, checked=checked, head_hash=prev if checked else None)
