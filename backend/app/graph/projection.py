"""Write completed investigations and actions back into FalkorDB as graph-native memory.

These are the ONLY application writes to the graph (besides seeding). They use fixed,
parameterized statements. SQLite remains the system of record for action state; the graph
copy enables later investigations to discover prior conclusions by traversal.
"""

from __future__ import annotations

from typing import Any

from app.graph.client import GraphClient
from app.schemas.actions import RecommendedAction
from app.schemas.investigation import InvestigationResult


class GraphProjection:
    def __init__(self, client: GraphClient) -> None:
        self.client = client

    async def write_investigation(self, result: InvestigationResult, flags: list[dict[str, str]]) -> None:
        await self.client.rw(
            "MERGE (i:Investigation {id: $id}) SET i.tenant = $tenant, i.target_id = $target, i.verdict = $verdict, "
            "i.risk_score = $score, i.risk_band = $band, i.completed_at = $completed, i.status = $status, "
            "i.provider = $provider "
            "WITH i MATCH (t:Entity {id: $target}) WHERE t.tenant = $tenant MERGE (i)-[:INVESTIGATED]->(t)",
            {
                "id": result.id,
                "tenant": result.tenant,
                "target": result.target_id,
                "verdict": result.verdict,
                "score": result.risk.score if result.risk else None,
                "band": result.risk.band if result.risk else None,
                "completed": result.completed_at,
                "status": result.status,
                "provider": result.provider.name,
            },
            op="project_investigation",
        )
        if flags:
            await self.client.rw(
                "MATCH (i:Investigation {id: $id}) UNWIND $flags AS f MATCH (t:Entity {id: f.id}) "
                "WHERE t.tenant = $tenant MERGE (i)-[r:FLAGGED]->(t) SET r.role = f.role",
                {"id": result.id, "flags": flags, "tenant": result.tenant},
                op="project_flags",
            )
        cited = [{"id": e.id, "stance": e.stance} for e in result.supporting_evidence + result.contradicting_evidence]
        if cited:
            await self.client.rw(
                "MATCH (i:Investigation {id: $id}) UNWIND $ev AS e MATCH (x:Evidence {id: e.id}) "
                "WHERE x.tenant = $tenant MERGE (x)-[r:RECORDED_IN]->(i) SET r.stance = e.stance",
                {"id": result.id, "ev": cited, "tenant": result.tenant},
                op="project_evidence",
            )
        if result.recommended_actions:
            rows: list[dict[str, Any]] = [
                {
                    "id": a.id,
                    "target": a.target_id,
                    "props": {
                        "action_type": a.action_type.value,
                        "status": a.status.value,
                        "policy_version": a.policy_version,
                        "policy_rule": a.policy_rule,
                        "simulated": True,
                        "tenant": result.tenant,
                        "proposed_at": a.proposed_at,
                    },
                }
                for a in result.recommended_actions
            ]
            await self.client.rw(
                "MATCH (i:Investigation {id: $id}) UNWIND $rows AS row MERGE (a:ResponseAction {id: row.id}) "
                "SET a += row.props MERGE (i)-[:RECOMMENDED_ACTION]->(a) "
                "WITH a, row MATCH (t:Entity {id: row.target}) WHERE t.tenant = $tenant MERGE (a)-[:TARGETS]->(t)",
                {"id": result.id, "rows": rows, "tenant": result.tenant},
                op="project_actions",
            )

    async def update_action(self, action: RecommendedAction, tenant: str, person_id: str | None) -> None:
        await self.client.rw(
            "MATCH (a:ResponseAction {id: $id}) WHERE a.tenant = $tenant SET a.status = $status, "
            "a.decided_by = $by, a.decided_at = $at",
            {
                "id": action.id,
                "tenant": tenant,
                "status": action.status.value,
                "by": action.decided_by,
                "at": action.decided_at,
            },
            op="project_action_status",
        )
        if person_id and action.status.value in ("approved", "executed_simulation", "rejected"):
            rel = "REJECTED_BY" if action.status.value == "rejected" else "APPROVED_BY"
            await self.client.rw(
                f"MATCH (a:ResponseAction {{id: $id}}) MATCH (p:Person {{id: $pid}}) WHERE p.tenant = $tenant "
                f"MERGE (a)-[r:{rel}]->(p) SET r.at = $at",
                {"id": action.id, "pid": person_id, "tenant": tenant, "at": action.decided_at},
                op="project_action_decider",
            )
