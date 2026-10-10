from __future__ import annotations

from app.tools.analysis_tools import EvaluateRiskTool, RecommendResponseTool
from app.tools.base import ToolRegistry
from app.tools.graph_tools import (
    AssessImpactTool,
    ExploreNeighborhoodTool,
    FindAttackPathsTool,
    FindRelatedIncidentsTool,
    GetAlertTool,
    GetEvidenceTool,
    GetPriorInvestigationsTool,
    GraphAlgorithmTool,
)


def build_registry() -> ToolRegistry:
    """The complete, fixed set of tools the agent may use. Built in code only."""
    return ToolRegistry(
        [
            GetAlertTool(),
            ExploreNeighborhoodTool(),
            FindAttackPathsTool(),
            FindRelatedIncidentsTool(),
            AssessImpactTool(),
            GraphAlgorithmTool(),
            GetEvidenceTool(),
            GetPriorInvestigationsTool(),
            EvaluateRiskTool(),
            RecommendResponseTool(),
        ]
    )
