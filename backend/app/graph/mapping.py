"""Convert Cypher map projections into stable API graph contracts.

Queries never return raw driver Node/Edge objects to the rest of the app. They return map
projections built with the fragments below, so the internal FalkorDB ids never leak and
edges are identified by stable `<source>|<TYPE>|<target>` ids.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from app.core.timeutil import parse_iso
from app.graph.schema import ENTITY_LABEL, LABELS
from app.schemas.graph import GraphEdge, GraphNode, GraphPath

NODE_PROJ = "{id: {v}.id, labels: labels({v}), props: properties({v})}"
EDGE_PROJ = "{type: type({v}), src: startNode({v}).id, dst: endNode({v}).id, props: properties({v})}"

MAX_STRING = 4000
_HIDDEN_PROPS = {"tenant"}


def node_proj(var: str) -> str:
    return NODE_PROJ.replace("{v}", var)


def edge_proj(var: str) -> str:
    return EDGE_PROJ.replace("{v}", var)


def path_proj(var: str) -> str:
    return f"[n IN nodes({var}) | {node_proj('n')}] AS pnodes, [r IN relationships({var}) | {edge_proj('r')}] AS pedges"


def _clean_value(value: Any) -> Any:
    if isinstance(value, str):
        return value[:MAX_STRING]
    if isinstance(value, list):
        return [_clean_value(v) for v in value[:200]]
    if isinstance(value, int | float | bool) or value is None:
        return value
    return str(value)[:MAX_STRING]


def clean_props(props: dict[str, Any] | None) -> dict[str, Any]:
    return {str(k): _clean_value(v) for k, v in (props or {}).items() if k not in _HIDDEN_PROPS}


def primary_label(labels: list[str]) -> str:
    for lbl in labels:
        if lbl != ENTITY_LABEL:
            return lbl
    return labels[0] if labels else "Unknown"


def to_node(m: dict[str, Any]) -> GraphNode:
    labels = [lbl for lbl in (m.get("labels") or []) if lbl != ENTITY_LABEL]
    label = primary_label(labels)
    props = clean_props(dict(m.get("props") or {}))
    display_prop = LABELS[label].display_property if label in LABELS else "id"
    display = props.get(display_prop) or props.get("name") or m.get("id")
    return GraphNode(id=str(m["id"]), label=label, labels=labels, display_name=str(display), properties=props)


def edge_id(src: str, rel_type: str, dst: str) -> str:
    return f"{src}|{rel_type}|{dst}"


def is_historical(props: dict[str, Any], as_of: datetime) -> bool:
    valid_to = parse_iso(props.get("valid_to")) if isinstance(props.get("valid_to"), str) else None
    return valid_to is not None and valid_to < as_of


def to_edge(m: dict[str, Any], as_of: datetime) -> GraphEdge:
    props = clean_props(dict(m.get("props") or {}))
    return GraphEdge(
        id=edge_id(str(m["src"]), str(m["type"]), str(m["dst"])),
        type=str(m["type"]),
        source=str(m["src"]),
        target=str(m["dst"]),
        properties=props,
        temporal_status="historical" if is_historical(props, as_of) else "current",
    )


def path_id(node_ids: list[str], edge_ids: list[str]) -> str:
    digest = hashlib.sha256(("/".join(node_ids) + "#" + "/".join(edge_ids)).encode()).hexdigest()[:12]
    return f"path-{digest}"


def describe_path(nodes: list[GraphNode], edges: list[GraphEdge]) -> str:
    parts = [f"{nodes[0].label}:{nodes[0].display_name}"]
    for i, edge in enumerate(edges):
        nxt = nodes[i + 1]
        arrow = f"-[{edge.type}]->" if edge.source == nodes[i].id else f"<-[{edge.type}]-"
        parts.append(f"{arrow} {nxt.label}:{nxt.display_name}")
    return " ".join(parts)


def to_path(
    pnodes: list[dict[str, Any]], pedges: list[dict[str, Any]], as_of: datetime
) -> tuple[GraphPath, list[GraphNode], list[GraphEdge]]:
    nodes = [to_node(n) for n in pnodes]
    edges = [to_edge(e, as_of) for e in pedges]
    node_ids = [n.id for n in nodes]
    edge_ids = [e.id for e in edges]
    path = GraphPath(
        id=path_id(node_ids, edge_ids),
        node_ids=node_ids,
        edge_ids=edge_ids,
        hops=len(edges),
        start_id=node_ids[0],
        end_id=node_ids[-1],
        end_label=nodes[-1].label,
        description=describe_path(nodes, edges),
        contains_historical=any(e.temporal_status == "historical" for e in edges),
    )
    return path, nodes, edges
