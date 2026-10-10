"""Investigation context: everything the agent has learned from the graph so far.

Only tool executions write to the context. The LLM never writes to it directly; it can only
request tools. Every fact used by risk scoring, policy and findings comes from here.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from app.schemas.evidence import EvidenceItem
from app.schemas.graph import GraphEdge, GraphNode, GraphPath
from app.schemas.investigation import ToolCallRecord


@dataclass
class IncidentLink:
    incident: GraphNode
    path_id: str
    hops: int
    link: Literal["direct", "indirect"]
    opened_at: str | None


@dataclass
class ImpactedAsset:
    node: GraphNode
    relation: Literal[
        "implicated_entity",
        "hosted_service",
        "downstream_dependency",
        "network_reachable",
        "accessed_by_identity",
        "assigned_device",
        "upstream_dependent",
    ]
    hops: int
    path_id: str | None
    via: str | None = None


@dataclass
class VulnerabilityExposure:
    vulnerability: GraphNode
    asset_id: str
    edge_id: str
    status: str


@dataclass
class InvestigationContext:
    investigation_id: str
    tenant: str
    question: str
    target_id: str
    as_of: datetime
    max_depth: int
    target: GraphNode | None = None
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: dict[str, GraphEdge] = field(default_factory=dict)
    paths: dict[str, GraphPath] = field(default_factory=dict)
    path_kinds: dict[str, str] = field(default_factory=dict)
    evidence: dict[str, EvidenceItem] = field(default_factory=dict)
    triggering: list[tuple[GraphEdge, GraphNode]] = field(default_factory=list)
    incidents: dict[str, IncidentLink] = field(default_factory=dict)
    impacted: dict[str, ImpactedAsset] = field(default_factory=dict)
    vulnerabilities: dict[str, VulnerabilityExposure] = field(default_factory=dict)
    owners: dict[str, list[str]] = field(default_factory=dict)
    analytics: dict[str, Any] = field(default_factory=dict)
    prior_investigations: list[dict[str, Any]] = field(default_factory=list)
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    tools_run: set[str] = field(default_factory=set)
    # Core tools that have run *on the target with default scope* (see Orchestrator._covers_target).
    target_covered: set[str] = field(default_factory=set)
    last_traversal_seq: int = 0
    last_full_evidence_seq: int = 0
    notes: list[str] = field(default_factory=list)
    truncated: bool = False

    # ---- mutation (tools only) -----------------------------------------------------
    def add_nodes(self, nodes: list[GraphNode]) -> None:
        for n in nodes:
            self.nodes[n.id] = n

    def add_edges(self, edges: list[GraphEdge]) -> None:
        for e in edges:
            self.edges[e.id] = e

    def add_path(self, path: GraphPath, nodes: list[GraphNode], edges: list[GraphEdge], kind: str) -> None:
        self.add_nodes(nodes)
        self.add_edges(edges)
        self.paths[path.id] = path
        self.path_kinds.setdefault(path.id, kind)

    # ---- queries ---------------------------------------------------------------------
    @property
    def is_alert(self) -> bool:
        return self.target is not None and self.target.label == "SecurityAlert"

    def known_ref_ids(self) -> set[str]:
        return (
            set(self.nodes) | set(self.edges) | set(self.paths) | set(self.evidence) | {t.id for t in self.tool_calls}
        )

    def distances(self, include_historical: bool = False) -> dict[str, int]:
        """Hop distance from the target over the discovered (current) subgraph."""
        adj: dict[str, set[str]] = {}
        for e in self.edges.values():
            if e.temporal_status == "historical" and not include_historical:
                continue
            if e.type in ("SUPPORTS", "CONTRADICTS", "OWNS", "MEMBER_OF", "HAS_IDENTITY"):
                continue
            adj.setdefault(e.source, set()).add(e.target)
            adj.setdefault(e.target, set()).add(e.source)
        dist = {self.target_id: 0}
        queue = deque([self.target_id])
        while queue:
            cur = queue.popleft()
            for nxt in adj.get(cur, ()):
                if nxt not in dist:
                    dist[nxt] = dist[cur] + 1
                    queue.append(nxt)
        return dist

    def related_alert_ids(self) -> set[str]:
        ids = {self.target_id} if self.is_alert else set()
        for e in self.edges.values():
            if e.type == "RELATED_TO" and self.target_id in (e.source, e.target):
                ids.update((e.source, e.target))
        return {i for i in ids if i in self.nodes and self.nodes[i].label == "SecurityAlert"}

    def triggering_ids(self, roles: tuple[str, ...] | None = None) -> list[str]:
        out = []
        for edge, node in self.triggering:
            if roles is None or edge.properties.get("role") in roles:
                out.append(node.id)
        return out
