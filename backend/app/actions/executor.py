"""Action execution. Only a simulation executor exists.

Real integrations (EDR isolation, IdP credential rotation, firewall blocks) are intentionally not
implemented. Adding one requires: explicit configuration (disabled by default), scoped credentials,
server-side authorisation, and a separate security review. `Settings.simulation_only` cannot be
set to False.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from app.core.timeutil import now_iso
from app.schemas.actions import ActionType, RecommendedAction

_DESCRIPTIONS = {
    ActionType.ISOLATE_ENDPOINT: "Would request network containment of {target} from the EDR platform.",
    ActionType.ROTATE_CREDENTIALS: "Would force credential reset and session revocation for {target} in the IdP.",
    ActionType.BLOCK_INDICATOR: "Would add indicator {target} to perimeter/EDR blocklists.",
    ActionType.PATCH_SERVICE: "Would open a priority remediation ticket for {target}.",
    ActionType.ESCALATE_INCIDENT: "Would open an incident for {target} and page the on-call responder.",
    ActionType.REQUEST_FURTHER_INVESTIGATION: "Would open an analyst task to collect more evidence on {target}.",
}


@dataclass
class ExecutionResult:
    success: bool
    details: dict[str, Any]


class ActionExecutor(ABC):
    simulated: bool

    @abstractmethod
    async def execute(self, action: RecommendedAction) -> ExecutionResult: ...


class SimulationActionExecutor(ActionExecutor):
    """Performs no external calls. Records what a real executor would do."""

    simulated = True

    async def execute(self, action: RecommendedAction) -> ExecutionResult:
        return ExecutionResult(
            success=True,
            details={
                "simulated": True,
                "executor": "SimulationActionExecutor",
                "description": _DESCRIPTIONS[action.action_type].format(target=action.target_id),
                "external_systems_contacted": [],
                "simulated_at": now_iso(),
            },
        )
