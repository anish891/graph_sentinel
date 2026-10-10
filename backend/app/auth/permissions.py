"""Role-based access control. The ONLY place that maps roles to permissions."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

Role = Literal["viewer", "investigator", "approver", "admin"]


class Permission(StrEnum):
    READ_GRAPH = "graph:read"
    READ_ALERTS = "alerts:read"
    READ_INVESTIGATIONS = "investigations:read"
    CREATE_INVESTIGATION = "investigations:create"
    READ_ACTIONS = "actions:read"
    APPROVE_ACTION = "actions:approve"
    REJECT_ACTION = "actions:reject"
    CANCEL_ACTION = "actions:cancel"
    READ_AUDIT = "audit:read"
    READ_DIAGNOSTICS = "diagnostics:read"
    READ_METRICS = "metrics:read"


_READ = {Permission.READ_GRAPH, Permission.READ_ALERTS, Permission.READ_INVESTIGATIONS, Permission.READ_ACTIONS}

ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    "viewer": frozenset(_READ),
    "investigator": frozenset(
        _READ | {Permission.CREATE_INVESTIGATION, Permission.CANCEL_ACTION, Permission.READ_AUDIT}
    ),
    "approver": frozenset(_READ | {Permission.APPROVE_ACTION, Permission.REJECT_ACTION, Permission.READ_AUDIT}),
    "admin": frozenset(set(Permission)),
}


def permissions_for(role: str) -> frozenset[Permission]:
    return ROLE_PERMISSIONS.get(role, frozenset())
