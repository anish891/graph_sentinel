from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from app.auth.permissions import Permission, permissions_for

AGENT_PRINCIPAL_ID = "agent:graphsentinel"


@dataclass(frozen=True)
class Principal:
    id: str
    name: str
    role: str
    tenant: str
    auth_method: Literal["demo", "oidc", "mcp", "system"]
    person_id: str | None = None
    permissions: frozenset[Permission] = field(default_factory=frozenset)

    @classmethod
    def build(
        cls,
        *,
        id: str,
        name: str,
        role: str,
        tenant: str,
        auth_method: Literal["demo", "oidc", "mcp", "system"],
        person_id: str | None = None,
    ) -> Principal:
        return cls(
            id=id,
            name=name,
            role=role,
            tenant=tenant,
            auth_method=auth_method,
            person_id=person_id,
            permissions=permissions_for(role),
        )

    def can(self, permission: Permission) -> bool:
        return permission in self.permissions
