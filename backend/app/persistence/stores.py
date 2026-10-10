"""Repositories over the SQLite metadata store."""

from __future__ import annotations

import json
import uuid
from typing import Any

import aiosqlite

from app.audit.chain import GENESIS_HASH, chain_hash
from app.core.timeutil import now_iso
from app.persistence.db import Database
from app.schemas.actions import ActionStatus, RecommendedAction
from app.schemas.investigation import (
    InvestigationResult,
    InvestigationSummary,
    TraceEvent,
    TraceIntegrity,
)


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class InvestigationStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def save(self, result: InvestigationResult, *, conn: aiosqlite.Connection | None = None) -> None:
        params = (
            result.id,
            result.tenant,
            result.status,
            result.question,
            result.target_id,
            result.requested_by,
            result.provider.name,
            int(result.provider.is_mock),
            result.created_at,
            result.completed_at,
            result.verdict,
            result.risk.score if result.risk else None,
            result.risk.band if result.risk else None,
            result.model_dump_json(),
            result.error,
        )
        sql = (
            "INSERT INTO investigations (id, tenant, status, question, target_id, requested_by, provider_name, "
            "provider_is_mock, created_at, completed_at, verdict, risk_score, risk_band, result_json, error) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status, "
            "completed_at=excluded.completed_at, verdict=excluded.verdict, risk_score=excluded.risk_score, "
            "risk_band=excluded.risk_band, result_json=excluded.result_json, error=excluded.error, "
            "provider_name=excluded.provider_name, provider_is_mock=excluded.provider_is_mock"
        )
        if conn is not None:
            await conn.execute(sql, params)
        else:
            async with self.db.transaction() as c:
                await c.execute(sql, params)

    async def get(self, tenant: str, investigation_id: str) -> InvestigationResult | None:
        row = await self.db.fetchone(
            "SELECT result_json FROM investigations WHERE id = ? AND tenant = ?", (investigation_id, tenant)
        )
        return InvestigationResult.model_validate_json(row["result_json"]) if row else None

    async def list_page(
        self, tenant: str, *, offset: int, limit: int, status: str | None = None, target_id: str | None = None
    ) -> tuple[list[InvestigationSummary], int]:
        where, params = ["tenant = ?"], [tenant]
        if status:
            where.append("status = ?")
            params.append(status)
        if target_id:
            where.append("target_id = ?")
            params.append(target_id)
        clause = " AND ".join(where)
        total_row = await self.db.fetchone(f"SELECT count(*) AS c FROM investigations WHERE {clause}", params)
        rows = await self.db.fetchall(
            "SELECT id, status, question, target_id, requested_by, created_at, completed_at, verdict, risk_score, "
            f"risk_band, provider_name, provider_is_mock FROM investigations WHERE {clause} "
            "ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        )
        items = [
            InvestigationSummary(
                id=r["id"],
                status=r["status"],
                question=r["question"],
                target_id=r["target_id"],
                requested_by=r["requested_by"],
                created_at=r["created_at"],
                completed_at=r["completed_at"],
                verdict=r["verdict"],
                risk_score=r["risk_score"],
                risk_band=r["risk_band"],
                provider_name=r["provider_name"],
                provider_is_mock=bool(r["provider_is_mock"]),
            )
            for r in rows
        ]
        return items, int(total_row["c"]) if total_row else 0

    async def counts(self, tenant: str) -> dict[str, int]:
        rows = await self.db.fetchall(
            "SELECT status, count(*) AS c FROM investigations WHERE tenant = ? GROUP BY status", (tenant,)
        )
        out = {r["status"]: int(r["c"]) for r in rows}
        high = await self.db.fetchone(
            "SELECT count(*) AS c FROM investigations WHERE tenant = ? AND risk_band IN ('high','critical')", (tenant,)
        )
        out["high_risk"] = int(high["c"]) if high else 0
        return out

    async def mark_interrupted(self) -> int:
        """Investigations still running when the process stopped cannot be resumed: fail them honestly."""
        rows = await self.db.fetchall("SELECT id, result_json FROM investigations WHERE status IN ('queued','running')")
        for r in rows:
            result = InvestigationResult.model_validate_json(r["result_json"])
            result.status = "failed"
            result.error = "Interrupted by a service restart before completion."
            result.completed_at = now_iso()
            await self.save(result)
        return len(rows)


class TraceStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def append(self, investigation_id: str, kind: str, payload: dict[str, Any]) -> TraceEvent:
        async with self.db.transaction() as conn:
            async with conn.execute(
                "SELECT seq, hash FROM trace_events WHERE investigation_id = ? ORDER BY seq DESC LIMIT 1",
                (investigation_id,),
            ) as cur:
                last = await cur.fetchone()
            seq = (last["seq"] + 1) if last else 1
            prev = last["hash"] if last else GENESIS_HASH
            ts = now_iso()
            eid = new_id("evt")
            record = {
                "id": eid,
                "investigation_id": investigation_id,
                "seq": seq,
                "ts": ts,
                "kind": kind,
                "payload": payload,
            }
            h = chain_hash(prev, record)
            await conn.execute(
                "INSERT INTO trace_events (id, investigation_id, seq, ts, kind, payload_json, prev_hash, hash) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (eid, investigation_id, seq, ts, kind, json.dumps(payload, default=str), prev, h),
            )
        return TraceEvent(
            id=eid,
            investigation_id=investigation_id,
            seq=seq,
            ts=ts,
            kind=kind,
            payload=payload,
            prev_hash=prev,
            hash=h,
        )

    async def list_events(self, investigation_id: str) -> list[TraceEvent]:
        rows = await self.db.fetchall(
            "SELECT * FROM trace_events WHERE investigation_id = ? ORDER BY seq", (investigation_id,)
        )
        return [
            TraceEvent(
                id=r["id"],
                investigation_id=r["investigation_id"],
                seq=r["seq"],
                ts=r["ts"],
                kind=r["kind"],
                payload=json.loads(r["payload_json"]),
                prev_hash=r["prev_hash"],
                hash=r["hash"],
            )
            for r in rows
        ]

    @staticmethod
    def verify(events: list[TraceEvent]) -> TraceIntegrity:
        prev = GENESIS_HASH
        for i, e in enumerate(events, start=1):
            record = {
                "id": e.id,
                "investigation_id": e.investigation_id,
                "seq": e.seq,
                "ts": e.ts,
                "kind": e.kind,
                "payload": e.payload,
            }
            if e.seq != i or e.prev_hash != prev or chain_hash(prev, record) != e.hash:
                return TraceIntegrity(
                    valid=False, checked_events=i, head_hash=None, reason=f"chain broken at seq {e.seq}"
                )
            prev = e.hash
        return TraceIntegrity(valid=True, checked_events=len(events), head_hash=prev if events else None)


class ActionStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def insert(self, conn: aiosqlite.Connection, tenant: str, action: RecommendedAction) -> None:
        await conn.execute(
            "INSERT INTO actions (id, tenant, investigation_id, action_type, target_id, status, policy_version, "
            "created_at, expires_at, version, doc_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                action.id,
                tenant,
                action.investigation_id,
                action.action_type.value,
                action.target_id,
                action.status.value,
                action.policy_version,
                action.proposed_at,
                action.expires_at,
                action.version,
                action.model_dump_json(),
            ),
        )

    async def get(
        self, tenant: str, action_id: str, conn: aiosqlite.Connection | None = None
    ) -> RecommendedAction | None:
        sql, params = "SELECT doc_json FROM actions WHERE id = ? AND tenant = ?", (action_id, tenant)
        if conn is not None:
            async with conn.execute(sql, params) as cur:
                row = await cur.fetchone()
        else:
            row = await self.db.fetchone(sql, params)
        return RecommendedAction.model_validate_json(row["doc_json"]) if row else None

    async def compare_and_set(
        self,
        conn: aiosqlite.Connection,
        tenant: str,
        action: RecommendedAction,
        expected_status: ActionStatus,
        expected_version: int,
    ) -> bool:
        """Atomic state transition: succeeds only if nobody else changed the action meanwhile."""
        cur = await conn.execute(
            "UPDATE actions SET status = ?, version = ?, doc_json = ? "
            "WHERE id = ? AND tenant = ? AND status = ? AND version = ?",
            (
                action.status.value,
                action.version,
                action.model_dump_json(),
                action.id,
                tenant,
                expected_status.value,
                expected_version,
            ),
        )
        return cur.rowcount == 1

    async def list_page(
        self,
        tenant: str,
        *,
        offset: int,
        limit: int,
        status: list[str] | None = None,
        investigation_id: str | None = None,
    ) -> tuple[list[RecommendedAction], int]:
        where, params = ["tenant = ?"], [tenant]
        if status:
            where.append(f"status IN ({','.join('?' for _ in status)})")
            params.extend(status)
        if investigation_id:
            where.append("investigation_id = ?")
            params.append(investigation_id)
        clause = " AND ".join(where)
        total = await self.db.fetchone(f"SELECT count(*) AS c FROM actions WHERE {clause}", params)
        rows = await self.db.fetchall(
            f"SELECT doc_json FROM actions WHERE {clause} ORDER BY created_at DESC, id LIMIT ? OFFSET ?",
            [*params, limit, offset],
        )
        return ([RecommendedAction.model_validate_json(r["doc_json"]) for r in rows], int(total["c"]) if total else 0)

    async def pending_ids(self, tenant: str) -> list[str]:
        rows = await self.db.fetchall(
            "SELECT id FROM actions WHERE tenant = ? AND status = ?", (tenant, ActionStatus.PENDING_APPROVAL.value)
        )
        return [r["id"] for r in rows]


class IdempotencyStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def get(self, conn: aiosqlite.Connection, principal_id: str, scope: str, key: str) -> aiosqlite.Row | None:
        async with conn.execute(
            "SELECT request_hash, status_code, response_json FROM idempotency_keys "
            "WHERE principal_id = ? AND scope = ? AND key = ?",
            (principal_id, scope, key),
        ) as cur:
            return await cur.fetchone()

    async def put(
        self,
        conn: aiosqlite.Connection,
        principal_id: str,
        scope: str,
        key: str,
        request_hash: str,
        status_code: int,
        response: dict[str, Any],
    ) -> None:
        await conn.execute(
            "INSERT INTO idempotency_keys (key, principal_id, scope, request_hash, status_code, response_json, "
            "created_at) VALUES (?,?,?,?,?,?,?)",
            (key, principal_id, scope, request_hash, status_code, json.dumps(response, default=str), now_iso()),
        )
