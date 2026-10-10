"""Action lifecycle with server-side enforcement.

    proposed ──► pending_approval ──► approved ──► executed_simulation
                         │                │
                         ├──► rejected    └──► failed
                         ├──► expired
                         └──► cancelled

Rules enforced here (not in the UI):
* permission check (approver/admin), tenant check;
* approval must name the exact investigation and policy version the approver reviewed;
* the agent can never approve; the investigation requester cannot approve their own case (four-eyes);
* stale (expired) or already-decided actions are rejected with 409;
* compare-and-set on (status, version) inside an IMMEDIATE transaction → no double execution;
* Idempotency-Key replays return the original response; a key reused with a different body is rejected.
"""

from __future__ import annotations

import json
from typing import Any

from app.actions.executor import ActionExecutor
from app.audit.chain import content_hash
from app.auth.permissions import Permission
from app.auth.principal import AGENT_PRINCIPAL_ID, Principal
from app.core.errors import ConflictError, NotFoundError, PermissionDeniedError, ValidationFailedError
from app.core.timeutil import now_iso, parse_iso, utcnow
from app.graph.projection import GraphProjection
from app.observability.logging import get_logger
from app.observability.metrics import ACTIONS
from app.persistence.db import Database
from app.persistence.stores import ActionStore, IdempotencyStore, InvestigationStore
from app.schemas.actions import (
    TERMINAL_STATUSES,
    ActionStatus,
    ApprovalRequest,
    CancelRequest,
    RecommendedAction,
    RejectRequest,
)
from app.services.audit import AuditService

log = get_logger(__name__)

ALLOWED: dict[ActionStatus, set[ActionStatus]] = {
    ActionStatus.PROPOSED: {ActionStatus.PENDING_APPROVAL, ActionStatus.CANCELLED},
    ActionStatus.PENDING_APPROVAL: {
        ActionStatus.APPROVED,
        ActionStatus.REJECTED,
        ActionStatus.EXPIRED,
        ActionStatus.CANCELLED,
    },
    ActionStatus.APPROVED: {ActionStatus.EXECUTED_SIMULATION, ActionStatus.FAILED},
}


def can_transition(src: ActionStatus, dst: ActionStatus) -> bool:
    return dst in ALLOWED.get(src, set())


class ActionService:
    def __init__(
        self, db: Database, audit: AuditService, executor: ActionExecutor, projection: GraphProjection | None
    ) -> None:
        self.db = db
        self.store = ActionStore(db)
        self.idem = IdempotencyStore(db)
        self.investigations = InvestigationStore(db)
        self.audit = audit
        self.executor = executor
        self.projection = projection

    async def get(self, principal: Principal, action_id: str) -> RecommendedAction:
        action = await self.store.get(principal.tenant, action_id)
        if action is None:
            raise NotFoundError(f"Action {action_id} not found.")
        return await self._expire_if_stale(principal, action)

    async def list_page(
        self, principal: Principal, *, offset: int, limit: int, status: list[str] | None, investigation_id: str | None
    ) -> tuple[list[RecommendedAction], int]:
        await self.expire_stale(principal.tenant)
        return await self.store.list_page(
            principal.tenant, offset=offset, limit=limit, status=status, investigation_id=investigation_id
        )

    # ---- decisions -------------------------------------------------------------------------------
    async def approve(
        self, principal: Principal, action_id: str, req: ApprovalRequest, idempotency_key: str
    ) -> tuple[int, dict[str, Any]]:
        if not principal.can(Permission.APPROVE_ACTION):
            await self._denied(principal, action_id, "approve", "missing permission actions:approve")
            raise PermissionDeniedError("Approving actions requires the approver or admin role.")
        return await self._decide(
            principal,
            action_id,
            "approve",
            req.model_dump(),
            idempotency_key,
            investigation_id=req.investigation_id,
            policy_version=req.policy_version,
            comment=req.comment,
        )

    async def reject(
        self, principal: Principal, action_id: str, req: RejectRequest, idempotency_key: str
    ) -> tuple[int, dict[str, Any]]:
        if not principal.can(Permission.REJECT_ACTION):
            await self._denied(principal, action_id, "reject", "missing permission actions:reject")
            raise PermissionDeniedError("Rejecting actions requires the approver or admin role.")
        return await self._decide(
            principal,
            action_id,
            "reject",
            req.model_dump(),
            idempotency_key,
            investigation_id=req.investigation_id,
            policy_version=req.policy_version,
            comment=req.reason,
        )

    async def cancel(
        self, principal: Principal, action_id: str, req: CancelRequest, idempotency_key: str
    ) -> tuple[int, dict[str, Any]]:
        if not principal.can(Permission.CANCEL_ACTION):
            raise PermissionDeniedError("Cancelling actions requires the investigator or admin role.")
        return await self._decide(
            principal,
            action_id,
            "cancel",
            req.model_dump(),
            idempotency_key,
            investigation_id=None,
            policy_version=None,
            comment=req.reason,
        )

    async def _decide(
        self,
        principal: Principal,
        action_id: str,
        verb: str,
        body: dict[str, Any],
        idempotency_key: str,
        *,
        investigation_id: str | None,
        policy_version: str | None,
        comment: str | None,
    ) -> tuple[int, dict[str, Any]]:
        if not idempotency_key or len(idempotency_key) > 128:
            raise ValidationFailedError("An Idempotency-Key header (1-128 chars) is required.")
        if principal.id == AGENT_PRINCIPAL_ID:
            raise PermissionDeniedError("The agent cannot decide on actions.")
        scope = f"action:{verb}:{action_id}"
        req_hash = content_hash(body)
        executed: RecommendedAction | None = None
        # Errors whose side effects (expiry transition, denial audit record) must be committed are
        # raised after the transaction closes instead of inside it (which would roll them back).
        deferred: Exception | None = None
        async with self.db.transaction() as conn:
            prior = await self.idem.get(conn, principal.id, scope, idempotency_key)
            if prior is not None:
                if prior["request_hash"] != req_hash:
                    raise ConflictError("Idempotency-Key was already used with a different request body.")
                return int(prior["status_code"]), json.loads(prior["response_json"])
            action = await self.store.get(principal.tenant, action_id, conn=conn)
            if action is None:
                raise NotFoundError(f"Action {action_id} not found.")
            if investigation_id is not None and action.investigation_id != investigation_id:
                raise ConflictError("Approval references a different investigation than the action belongs to.")
            if policy_version is not None and action.policy_version != policy_version:
                raise ConflictError(f"Stale approval: action was proposed under {action.policy_version}.")
            expected_status, expected_version = action.status, action.version

            if action.status in TERMINAL_STATUSES or action.status == ActionStatus.APPROVED:
                raise ConflictError(f"Action is already {action.status.value}; it cannot be {verb}d.")
            expires = parse_iso(action.expires_at)
            if expires and expires < utcnow() and action.status == ActionStatus.PENDING_APPROVAL:
                action.status = ActionStatus.EXPIRED
                action.version += 1
                await self.store.compare_and_set(conn, principal.tenant, action, expected_status, expected_version)
                await self.audit.record(
                    actor="system",
                    actor_role=None,
                    tenant=principal.tenant,
                    event_type="action.expired",
                    resource_type="action",
                    resource_id=action.id,
                    details={},
                    conn=conn,
                )
                ACTIONS.labels(transition="expired").inc()
                deferred = ConflictError("Approval window expired; the action can no longer be approved.")

            target = ActionStatus.CANCELLED
            if deferred is None and verb in ("approve", "reject"):
                if not action.requires_approval:
                    raise ConflictError("This action does not require approval.")
                inv = await self.investigations.get(principal.tenant, action.investigation_id)
                if inv is not None and inv.requested_by == principal.id:
                    await self.audit.record(
                        actor=principal.id,
                        actor_role=principal.role,
                        tenant=principal.tenant,
                        event_type="action.decision_denied",
                        resource_type="action",
                        resource_id=action.id,
                        details={"verb": verb, "reason": "four-eyes: requester cannot decide"},
                        conn=conn,
                    )
                    deferred = PermissionDeniedError(
                        f"Separation of duties: the investigation requester cannot {verb} its actions."
                    )
                target = ActionStatus.APPROVED if verb == "approve" else ActionStatus.REJECTED
            if deferred is None:
                if not can_transition(action.status, target):
                    raise ConflictError(f"Invalid transition {action.status.value} -> {target.value}.")
                executed = await self._apply(
                    conn,
                    principal,
                    action,
                    target,
                    expected_status,
                    expected_version,
                    comment,
                    idempotency_key,
                    scope,
                    req_hash,
                )
        if deferred is not None:
            raise deferred
        if self.projection is not None and executed is not None:
            try:
                await self.projection.update_action(executed, principal.tenant, principal.person_id)
            except Exception:
                log.warning("action.graph_projection_failed", action_id=executed.id)
        return 200, executed.model_dump(mode="json") if executed else {}

    async def _apply(
        self,
        conn: Any,
        principal: Principal,
        action: RecommendedAction,
        target: ActionStatus,
        expected_status: ActionStatus,
        expected_version: int,
        comment: str | None,
        idempotency_key: str,
        scope: str,
        req_hash: str,
    ) -> RecommendedAction:
        action.status = target
        action.version += 1
        action.decided_by = principal.id
        action.decided_at = now_iso()
        action.decision_comment = comment
        if not await self.store.compare_and_set(conn, principal.tenant, action, expected_status, expected_version):
            raise ConflictError("Action was modified concurrently; reload and retry.")
        await self.audit.record(
            actor=principal.id,
            actor_role=principal.role,
            tenant=principal.tenant,
            event_type=f"action.{target.value}",
            resource_type="action",
            resource_id=action.id,
            details={
                "investigation_id": action.investigation_id,
                "policy_version": action.policy_version,
                "action_type": action.action_type.value,
                "target_id": action.target_id,
                "comment": comment,
                "idempotency_key_hash": content_hash(idempotency_key)[:16],
            },
            conn=conn,
        )
        ACTIONS.labels(transition=target.value).inc()

        if target == ActionStatus.APPROVED:
            # Execute (simulation) inside the same transaction so approve+execute is all-or-nothing
            # and a replay can never execute twice.
            prev_status, prev_version = action.status, action.version
            try:
                result = await self.executor.execute(action)
                action.status = ActionStatus.EXECUTED_SIMULATION if result.success else ActionStatus.FAILED
                action.execution_result = result.details
            except Exception as exc:
                log.exception("action.executor_failed", action_id=action.id)
                action.status = ActionStatus.FAILED
                action.execution_result = {"error": type(exc).__name__}
            action.executed_at = now_iso()
            action.version += 1
            if not await self.store.compare_and_set(conn, principal.tenant, action, prev_status, prev_version):
                raise ConflictError("Action was modified concurrently during execution.")
            await self.audit.record(
                actor="executor:simulation",
                actor_role=None,
                tenant=principal.tenant,
                event_type=f"action.{action.status.value}",
                resource_type="action",
                resource_id=action.id,
                details={"approved_by": principal.id, "result": action.execution_result},
                conn=conn,
            )
            ACTIONS.labels(transition=action.status.value).inc()
        response = action.model_dump(mode="json")
        await self.idem.put(conn, principal.id, scope, idempotency_key, req_hash, 200, response)
        return action

    # ---- expiry -------------------------------------------------------------------------------------
    async def expire_stale(self, tenant: str) -> int:
        expired = 0
        for aid in await self.store.pending_ids(tenant):
            action = await self.store.get(tenant, aid)
            if action and (exp := parse_iso(action.expires_at)) and exp < utcnow():
                async with self.db.transaction() as conn:
                    v = action.version
                    action.status = ActionStatus.EXPIRED
                    action.version += 1
                    if await self.store.compare_and_set(conn, tenant, action, ActionStatus.PENDING_APPROVAL, v):
                        await self.audit.record(
                            actor="system",
                            actor_role=None,
                            tenant=tenant,
                            event_type="action.expired",
                            resource_type="action",
                            resource_id=action.id,
                            details={},
                            conn=conn,
                        )
                        expired += 1
        return expired

    async def _expire_if_stale(self, principal: Principal, action: RecommendedAction) -> RecommendedAction:
        if action.status == ActionStatus.PENDING_APPROVAL and (exp := parse_iso(action.expires_at)) and exp < utcnow():
            await self.expire_stale(principal.tenant)
            return await self.store.get(principal.tenant, action.id) or action
        return action

    async def _denied(self, principal: Principal, action_id: str, verb: str, reason: str) -> None:
        await self.audit.record(
            actor=principal.id,
            actor_role=principal.role,
            tenant=principal.tenant,
            event_type="action.decision_denied",
            resource_type="action",
            resource_id=action_id,
            details={"verb": verb, "reason": reason},
        )
