"""Read-side graph access. Every query is parameterized, tenant-scoped, bounded, and read-only.

Labels/relationship types are interpolated only from the schema whitelists (they cannot be
Cypher parameters); all user- or model-supplied values are passed as parameters.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from app.core.timeutil import parse_iso, to_iso
from app.graph.client import GraphClient
from app.graph.mapping import edge_proj, node_proj, path_proj, to_edge, to_node, to_path
from app.graph.schema import (
    ENTITY_LABEL,
    PROPAGATION_RELS,
    SECURITY_LABELS,
    SECURITY_RELS,
    rel_pattern,
)
from app.schemas.graph import GraphEdge, GraphNode, GraphPath, GraphStats

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

_TENANT_PATH = "all(x IN nodes(p) WHERE x.tenant = $tenant)"
_CURRENT_PATH = "all(r IN relationships(p) WHERE r.valid_to IS NULL OR r.valid_to >= $as_of)"
_SECURITY_NODES = "all(x IN nodes(p) WHERE any(l IN labels(x) WHERE l IN $allowed_labels))"
# Incidents and vulnerabilities are terminal: a shared historical incident or a CVE present on two
# assets is correlation, not a route along which compromise propagates.
_NO_TERMINAL_INTERIOR = (
    "all(i IN range(1, size(nodes(p)) - 2) WHERE NOT any(l IN labels(nodes(p)[i]) WHERE l IN $terminal_labels))"
)
TERMINAL_LABELS = ["Incident", "Vulnerability"]


@dataclass
class PathResult:
    path: GraphPath
    nodes: list[GraphNode]
    edges: list[GraphEdge]


@dataclass
class EvidenceRow:
    node: GraphNode
    stance: Literal["supports", "contradicts"]
    claim: str | None
    target: GraphNode


class GraphRepository:
    def __init__(self, client: GraphClient, tenant: str) -> None:
        self.client = client
        self.tenant = tenant

    # ---- metadata -------------------------------------------------------------------
    async def dataset_meta(self) -> dict[str, Any]:
        rows = await self.client.ro(
            "MATCH (m:GraphMeta {id: 'graph-meta'}) WHERE m.tenant = $tenant RETURN properties(m)",
            {"tenant": self.tenant},
            op="meta",
        )
        return dict(rows[0][0]) if rows else {}

    async def as_of(self, demo_mode: bool, now: datetime) -> datetime:
        """In demo mode the investigation clock is pinned to the dataset anchor (reproducible)."""
        if demo_mode:
            anchor = parse_iso((await self.dataset_meta()).get("anchor"))
            if anchor:
                return anchor
        return now

    async def stats(self) -> GraphStats:
        rows = await self.client.ro("CALL db.meta.stats()", op="stats")
        if not rows:
            return GraphStats(
                graph_name=self.client.graph_name, node_count=0, edge_count=0, nodes_by_label={}, edges_by_type={}
            )
        labels, rels, edge_count, node_count = rows[0][0], rows[0][1], rows[0][2], rows[0][3]
        return GraphStats(
            graph_name=self.client.graph_name,
            node_count=int(node_count),
            edge_count=int(edge_count),
            nodes_by_label={k: int(v) for k, v in dict(labels).items() if k != ENTITY_LABEL and int(v) > 0},
            edges_by_type={k: int(v) for k, v in dict(rels).items() if int(v) > 0},
            dataset=await self.dataset_meta(),
        )

    # ---- entities ---------------------------------------------------------------------
    async def get_entity(self, entity_id: str) -> GraphNode | None:
        rows = await self.client.ro(
            f"MATCH (n:{ENTITY_LABEL} {{id: $id}}) WHERE n.tenant = $tenant RETURN {node_proj('n')}",
            {"id": entity_id, "tenant": self.tenant},
            op="get_entity",
        )
        return to_node(rows[0][0]) if rows else None

    async def get_entities(self, ids: list[str]) -> list[GraphNode]:
        if not ids:
            return []
        rows = await self.client.ro(
            f"MATCH (n:{ENTITY_LABEL}) WHERE n.id IN $ids AND n.tenant = $tenant RETURN {node_proj('n')}",
            {"ids": ids[:500], "tenant": self.tenant},
            op="get_entities",
        )
        return [to_node(r[0]) for r in rows]

    async def search(self, q: str, limit: int = 20) -> list[GraphNode]:
        rows = await self.client.ro(
            f"MATCH (n:{ENTITY_LABEL}) WHERE n.tenant = $tenant AND ("
            "toLower(n.id) CONTAINS $q OR toLower(coalesce(n.name, '')) CONTAINS $q OR "
            "toLower(coalesce(n.hostname, '')) CONTAINS $q OR toLower(coalesce(n.address, '')) CONTAINS $q OR "
            "toLower(coalesce(n.username, '')) CONTAINS $q OR toLower(coalesce(n.title, '')) CONTAINS $q OR "
            "toLower(coalesce(n.value, '')) CONTAINS $q) "
            f"RETURN {node_proj('n')} ORDER BY n.id LIMIT $limit",
            {"q": q.lower(), "tenant": self.tenant, "limit": limit},
            op="search",
        )
        return [to_node(r[0]) for r in rows]

    async def direct_links(
        self, entity_id: str, as_of: datetime, limit: int = 100
    ) -> list[tuple[GraphEdge, GraphNode]]:
        rows = await self.client.ro(
            f"MATCH (n:{ENTITY_LABEL} {{id: $id}})-[r]-(m:{ENTITY_LABEL}) "
            "WHERE n.tenant = $tenant AND m.tenant = $tenant "
            f"RETURN {edge_proj('r')}, {node_proj('m')} LIMIT $limit",
            {"id": entity_id, "tenant": self.tenant, "limit": limit},
            op="direct_links",
        )
        return [(to_edge(r[0], as_of), to_node(r[1])) for r in rows]

    # ---- alerts ------------------------------------------------------------------------
    async def list_alerts(
        self,
        *,
        severity: list[str] | None,
        status: list[str] | None,
        q: str | None,
        sort: str,
        descending: bool,
        offset: int,
        limit: int,
    ) -> tuple[list[GraphNode], int]:
        where = ["a.tenant = $tenant"]
        params: dict[str, Any] = {"tenant": self.tenant, "offset": offset, "limit": limit}
        if severity:
            where.append("a.severity IN $severity")
            params["severity"] = severity
        if status:
            where.append("a.status IN $status")
            params["status"] = status
        if q:
            where.append("(toLower(a.id) CONTAINS $q OR toLower(a.title) CONTAINS $q)")
            params["q"] = q.lower()
        clause = " AND ".join(where)
        sort_expr = {
            "detected_at": "a.detected_at",
            "severity": "CASE a.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END",
            "id": "a.id",
        }[sort]
        direction = "DESC" if descending else "ASC"
        total = await self.client.ro(
            f"MATCH (a:SecurityAlert) WHERE {clause} RETURN count(a)", params, op="count_alerts"
        )
        rows = await self.client.ro(
            f"MATCH (a:SecurityAlert) WHERE {clause} RETURN {node_proj('a')} "
            f"ORDER BY {sort_expr} {direction}, a.id SKIP $offset LIMIT $limit",
            params,
            op="list_alerts",
        )
        return [to_node(r[0]) for r in rows], int(total[0][0]) if total else 0

    async def alert_counts(self) -> dict[str, dict[str, int]]:
        rows = await self.client.ro(
            "MATCH (a:SecurityAlert) WHERE a.tenant = $tenant RETURN a.severity, a.status, count(a)",
            {"tenant": self.tenant},
            op="alert_counts",
        )
        by_sev: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for sev, status, c in rows:
            by_sev[sev] = by_sev.get(sev, 0) + int(c)
            by_status[status] = by_status.get(status, 0) + int(c)
        return {"by_severity": by_sev, "by_status": by_status}

    # ---- traversals ---------------------------------------------------------------------
    async def neighborhood(
        self,
        entity_id: str,
        *,
        depth: int,
        max_nodes: int,
        as_of: datetime,
        labels: list[str] | None = None,
        rel_types: list[str] | None = None,
        include_historical: bool = False,
        max_paths: int = 2000,
    ) -> tuple[list[GraphNode], list[GraphEdge], bool]:
        rels = rel_pattern(rel_types or list(SECURITY_RELS))
        allowed = labels or list(SECURITY_LABELS)
        if ENTITY_LABEL not in allowed:
            allowed = [*allowed]
        conds = [_TENANT_PATH, "all(x IN nodes(p)[1..] WHERE any(l IN labels(x) WHERE l IN $allowed_labels))"]
        if not include_historical:
            conds.append(_CURRENT_PATH)
        rows = await self.client.ro(
            f"MATCH p=(s:{ENTITY_LABEL} {{id: $id}})-[{rels}*1..{int(depth)}]-(x) WHERE {' AND '.join(conds)} "
            f"WITH p ORDER BY length(p) LIMIT $max_paths RETURN {path_proj('p')}",
            {
                "id": entity_id,
                "tenant": self.tenant,
                "allowed_labels": allowed,
                "as_of": to_iso(as_of),
                "max_paths": max_paths,
            },
            op="neighborhood",
        )
        nodes: dict[str, GraphNode] = {}
        edges: dict[str, GraphEdge] = {}
        truncated = len(rows) >= max_paths
        root = await self.get_entity(entity_id)
        if root:
            nodes[root.id] = root
        for pnodes, pedges in rows:
            _, pn, pe = to_path(pnodes, pedges, as_of)
            new_nodes = [n for n in pn if n.id not in nodes]
            if len(nodes) + len(new_nodes) > max_nodes:
                truncated = True
                continue
            for n in new_nodes:
                nodes[n.id] = n
            for e in pe:
                edges[e.id] = e
        return list(nodes.values()), list(edges.values()), truncated

    async def paths_from(
        self,
        source_id: str,
        *,
        target_labels: list[str],
        max_hops: int,
        as_of: datetime,
        limit: int,
        include_historical: bool = False,
        target_ids: list[str] | None = None,
        rel_types: list[str] | None = None,
    ) -> list[PathResult]:
        """Bounded simple paths over propagation relationships, shortest first."""
        rels = rel_pattern(rel_types or list(PROPAGATION_RELS))
        conds = [_TENANT_PATH, _SECURITY_NODES, _NO_TERMINAL_INTERIOR]
        params: dict[str, Any] = {
            "id": source_id,
            "tenant": self.tenant,
            "as_of": to_iso(as_of),
            "allowed_labels": list(SECURITY_LABELS),
            "raw_limit": max(limit * 25, 200),
            "terminal_labels": TERMINAL_LABELS,
        }
        if not include_historical:
            conds.append(_CURRENT_PATH)
        if target_ids:
            conds.append("t.id IN $target_ids")
            params["target_ids"] = target_ids
        else:
            conds.append("any(l IN labels(t) WHERE l IN $target_labels)")
            params["target_labels"] = target_labels
        conds.append("t.id <> $id")
        rows = await self.client.ro(
            f"MATCH p=(s:{ENTITY_LABEL} {{id: $id}})-[{rels}*1..{int(max_hops)}]-(t) "
            f"WHERE {' AND '.join(conds)} WITH p ORDER BY length(p) LIMIT $raw_limit RETURN {path_proj('p')}",
            params,
            op="paths_from",
        )
        results: list[PathResult] = []
        per_target: dict[str, int] = {}
        seen: set[str] = set()
        for pnodes, pedges in rows:
            path, nodes, edges = to_path(pnodes, pedges, as_of)
            if len(set(path.node_ids)) != len(path.node_ids):  # keep simple paths only
                continue
            if path.id in seen or per_target.get(path.end_id, 0) >= 2:
                continue
            seen.add(path.id)
            per_target[path.end_id] = per_target.get(path.end_id, 0) + 1
            results.append(PathResult(path, nodes, edges))
            if len(results) >= limit:
                break
        return results

    async def directed_reach(
        self,
        source_ids: list[str],
        *,
        rel_types: list[str],
        max_hops: int,
        as_of: datetime,
        include_historical: bool = False,
        limit: int = 300,
    ) -> list[PathResult]:
        conds = [_TENANT_PATH, _SECURITY_NODES, _NO_TERMINAL_INTERIOR]
        if not include_historical:
            conds.append(_CURRENT_PATH)
        rows = await self.client.ro(
            f"MATCH p=(s:{ENTITY_LABEL})-[{rel_pattern(rel_types)}*1..{int(max_hops)}]->(t) "
            f"WHERE s.id IN $ids AND {' AND '.join(conds)} "
            f"WITH p ORDER BY length(p) LIMIT $limit RETURN {path_proj('p')}",
            {
                "ids": source_ids,
                "tenant": self.tenant,
                "as_of": to_iso(as_of),
                "allowed_labels": list(SECURITY_LABELS),
                "limit": limit,
                "terminal_labels": TERMINAL_LABELS,
            },
            op="directed_reach",
        )
        return [PathResult(*to_path(pn, pe, as_of)) for pn, pe in rows]

    async def upstream_dependents(self, service_ids: list[str], max_hops: int, as_of: datetime) -> list[PathResult]:
        if not service_ids:
            return []
        rows = await self.client.ro(
            f"MATCH p=(u:Service)-[:DEPENDS_ON*1..{int(max_hops)}]->(s:Service) "
            f"WHERE s.id IN $ids AND {_TENANT_PATH} WITH p ORDER BY length(p) LIMIT 100 RETURN {path_proj('p')}",
            {"ids": service_ids, "tenant": self.tenant},
            op="upstream",
        )
        return [PathResult(*to_path(pn, pe, as_of)) for pn, pe in rows]

    async def vulnerabilities_of(
        self, asset_ids: list[str], as_of: datetime
    ) -> list[tuple[GraphEdge, GraphNode, GraphNode]]:
        if not asset_ids:
            return []
        rows = await self.client.ro(
            "MATCH (a:Entity)-[h:HAS_VULNERABILITY]->(v:Vulnerability) WHERE a.id IN $ids AND a.tenant = $tenant "
            f"RETURN {edge_proj('h')}, {node_proj('v')}, {node_proj('a')}",
            {"ids": asset_ids, "tenant": self.tenant},
            op="vulns",
        )
        return [(to_edge(r[0], as_of), to_node(r[1]), to_node(r[2])) for r in rows]

    async def owners_of(self, asset_ids: list[str], as_of: datetime) -> list[tuple[GraphEdge, GraphNode]]:
        if not asset_ids:
            return []
        rows = await self.client.ro(
            "MATCH (t:Team)-[o:OWNS]->(a:Entity) WHERE a.id IN $ids AND t.tenant = $tenant "
            f"RETURN {edge_proj('o')}, {node_proj('t')}",
            {"ids": asset_ids, "tenant": self.tenant},
            op="owners",
        )
        return [(to_edge(r[0], as_of), to_node(r[1])) for r in rows]

    async def evidence_for(self, entity_ids: list[str]) -> list[EvidenceRow]:
        if not entity_ids:
            return []
        rows = await self.client.ro(
            "MATCH (e:Evidence)-[r:SUPPORTS|CONTRADICTS]->(t:Entity) "
            "WHERE t.id IN $ids AND e.tenant = $tenant AND t.tenant = $tenant "
            f"RETURN {node_proj('e')}, type(r), r.claim, {node_proj('t')} ORDER BY e.id LIMIT 200",
            {"ids": entity_ids[:300], "tenant": self.tenant},
            op="evidence",
        )
        return [
            EvidenceRow(
                node=to_node(r[0]),
                stance="supports" if r[1] == "SUPPORTS" else "contradicts",
                claim=r[2],
                target=to_node(r[3]),
            )
            for r in rows
        ]

    async def prior_investigations(self, entity_ids: list[str], exclude_id: str | None) -> list[dict[str, Any]]:
        if not entity_ids:
            return []
        rows = await self.client.ro(
            "MATCH (i:Investigation)-[l:INVESTIGATED|FLAGGED]->(t:Entity) "
            "WHERE t.id IN $ids AND i.tenant = $tenant AND i.id <> $exclude "
            "RETURN i.id, i.verdict, i.risk_score, i.risk_band, i.completed_at, i.target_id, "
            "collect(DISTINCT t.id) ORDER BY i.completed_at DESC LIMIT 20",
            {"ids": entity_ids[:300], "tenant": self.tenant, "exclude": exclude_id or ""},
            op="prior_investigations",
        )
        return [
            {
                "investigation_id": r[0],
                "verdict": r[1],
                "risk_score": r[2],
                "risk_band": r[3],
                "completed_at": r[4],
                "target_id": r[5],
                "shared_entities": sorted(r[6]),
            }
            for r in rows
        ]

    # ---- algorithms (executed inside FalkorDB) ------------------------------------------
    async def shortest_path(
        self, source_id: str, target_id: str, max_hops: int, as_of: datetime, include_historical: bool = False
    ) -> PathResult | None:
        # FalkorDB's shortestPath() is directed-only; an undirected, bounded variable-length
        # match ordered by hop count returns the minimum-hop path and runs in FalkorDB.
        res = await self.paths_from(
            source_id,
            target_labels=[],
            target_ids=[target_id],
            max_hops=max_hops,
            as_of=as_of,
            limit=1,
            include_historical=include_historical,
        )
        return res[0] if res else None

    async def degree(self, entity_ids: list[str]) -> dict[str, dict[str, int]]:
        rows = await self.client.ro(
            f"MATCH (n:{ENTITY_LABEL}) WHERE n.id IN $ids AND n.tenant = $tenant "
            f"OPTIONAL MATCH (n)-[r{rel_pattern(list(PROPAGATION_RELS))}]-() "
            "RETURN n.id, count(r)",
            {"ids": entity_ids[:300], "tenant": self.tenant},
            op="degree",
        )
        all_rows = await self.client.ro(
            f"MATCH (n:{ENTITY_LABEL}) WHERE n.id IN $ids AND n.tenant = $tenant "
            "OPTIONAL MATCH (n)-[r]-() RETURN n.id, count(r)",
            {"ids": entity_ids[:300], "tenant": self.tenant},
            op="degree_all",
        )
        total = {r[0]: int(r[1]) for r in all_rows}
        return {r[0]: {"propagation_degree": int(r[1]), "total_degree": total.get(r[0], 0)} for r in rows}

    async def betweenness(self, limit: int = 15) -> list[tuple[GraphNode, float]]:
        rels = ", ".join(f"'{t}'" for t in PROPAGATION_RELS)  # whitelisted constants
        rows = await self.client.ro(
            f"CALL algo.betweenness({{nodeLabels: ['{ENTITY_LABEL}'], relationshipTypes: [{rels}]}}) "
            "YIELD node, score WITH node, score WHERE node.tenant = $tenant AND score > 0 "
            f"RETURN {node_proj('node')}, score ORDER BY score DESC LIMIT $limit",
            {"tenant": self.tenant, "limit": limit},
            op="betweenness",
            timeout_ms=10000,
        )
        return [(to_node(r[0]), float(r[1])) for r in rows]

    async def pagerank(self, limit: int = 15) -> list[tuple[GraphNode, float]]:
        rows = await self.client.ro(
            "CALL algo.pageRank(NULL, NULL) YIELD node, score WITH node, score "
            "WHERE node.tenant = $tenant AND node:Entity AND NOT node:Evidence AND NOT node:Technique "
            f"AND NOT node:Team AND NOT node:Person RETURN {node_proj('node')}, score ORDER BY score DESC "
            "LIMIT $limit",
            {"tenant": self.tenant, "limit": limit},
            op="pagerank",
            timeout_ms=10000,
        )
        return [(to_node(r[0]), float(r[1])) for r in rows]

    async def component_of(self, entity_ids: list[str]) -> dict[str, Any]:
        rels = ", ".join(f"'{t}'" for t in PROPAGATION_RELS)
        rows = await self.client.ro(
            f"CALL algo.WCC({{nodeLabels: ['{ENTITY_LABEL}'], relationshipTypes: [{rels}]}}) "
            "YIELD node, componentId WITH node, componentId WHERE node.tenant = $tenant "
            "RETURN node.id, componentId, labels(node), node.criticality",
            {"tenant": self.tenant},
            op="wcc",
            timeout_ms=10000,
        )
        comp_of = {r[0]: r[1] for r in rows}
        members: dict[Any, list[tuple[str, list[str], Any]]] = {}
        for nid, cid, labels, crit in rows:
            members.setdefault(cid, []).append((nid, labels, crit))
        out: dict[str, Any] = {}
        for eid in entity_ids:
            cid = comp_of.get(eid)
            if cid is None:
                out[eid] = {"found": False}
                continue
            mem = members[cid]
            out[eid] = {
                "found": True,
                "component_size": len(mem),
                "critical_or_high_assets": sorted(
                    nid
                    for nid, labels, crit in mem
                    if crit in ("critical", "high") and ("Service" in labels or "Device" in labels)
                ),
                "isolated": len(mem) == 1,
            }
        return out
