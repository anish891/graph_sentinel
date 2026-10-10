"""Idempotent graph initialisation and synthetic-data seeding.

* Validates the dataset against `app.graph.schema` before writing anything.
* Resolves relative timestamps ("now-2d4h") against an anchor time.
* Uses MERGE on stable ids, so re-running never duplicates nodes or edges.
* Creates range indexes and unique constraints (verified against FalkorDB v4.22).
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from app.core.timeutil import to_iso, utcnow
from app.graph.client import GraphClient
from app.graph.schema import ENTITY_LABEL, LABELS, RELATIONSHIPS
from app.observability.logging import get_logger

log = get_logger(__name__)

DATASET_FILE = "acme_security_graph.json"
_REL_TIME = re.compile(r"^now(?:-(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?)?$")
_BATCH = 200


class DatasetError(ValueError):
    pass


@dataclass
class SeedReport:
    dataset_version: str
    anchor: str
    nodes_written: int
    edges_written: int
    indexes: list[str] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)


def resolve_time(value: Any, anchor: datetime) -> Any:
    if isinstance(value, str) and value.startswith("now"):
        m = _REL_TIME.match(value)
        if not m:
            raise DatasetError(f"bad relative time: {value!r}")
        d, h, mi = (int(x) if x else 0 for x in m.groups())
        return to_iso(anchor - timedelta(days=d, hours=h, minutes=mi))
    return value


def _resolve_props(props: dict[str, Any], anchor: datetime) -> dict[str, Any]:
    return {k: resolve_time(v, anchor) for k, v in props.items()}


def load_dataset(data_dir: str | Path) -> dict[str, Any]:
    path = Path(data_dir) / DATASET_FILE
    with path.open(encoding="utf-8") as fh:
        data: dict[str, Any] = json.load(fh)
    validate_dataset(data)
    return data


def validate_dataset(data: dict[str, Any]) -> None:
    """Enforce the schema invariants FalkorDB cannot express (allowed endpoints per rel type)."""
    ids: dict[str, str] = {}
    for node in data["nodes"]:
        label, nid = node["label"], node["id"]
        if label not in LABELS or LABELS[label].operational:
            raise DatasetError(f"node {nid}: label {label!r} not allowed in seed data")
        if nid in ids:
            raise DatasetError(f"duplicate node id {nid}")
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,127}$", nid):
            raise DatasetError(f"invalid id {nid!r}")
        ids[nid] = label
    seen: set[tuple[str, str, str]] = set()
    for edge in data["edges"]:
        rtype, src, dst = edge["type"], edge["from"], edge["to"]
        rel = RELATIONSHIPS.get(rtype)
        if rel is None or rel.operational:
            raise DatasetError(f"edge {src}->{dst}: relationship {rtype!r} not allowed")
        if src not in ids or dst not in ids:
            raise DatasetError(f"edge {src}-[{rtype}]->{dst}: unknown endpoint")
        if ids[src] not in rel.from_labels or ids[dst] not in rel.to_labels:
            raise DatasetError(f"edge {src}({ids[src]})-[{rtype}]->{dst}({ids[dst]}): label pair not allowed")
        key = (src, rtype, dst)
        if key in seen:
            raise DatasetError(f"duplicate edge {key}")
        seen.add(key)


async def ensure_indexes(client: GraphClient) -> tuple[list[str], list[str]]:
    created_idx: list[str] = []
    targets: list[tuple[str, str]] = [(ENTITY_LABEL, "id")]
    for name, d in LABELS.items():
        targets.append((name, "id"))
        targets.extend((name, p) for p in d.extra_indexes)
    existing: set[tuple[str, str]] = set()
    for row in await client.list_indices():
        for prop in row[1] or []:
            existing.add((str(row[0]), str(prop)))
    for label, prop in targets:
        if (label, prop) in existing:
            continue
        # Label and property come from the static schema whitelist, never from input.
        await client.rw(f"CREATE INDEX FOR (n:{label}) ON (n.{prop})", op="create_index")
        created_idx.append(f"{label}.{prop}")
    constraints: list[str] = []
    present = {(c.get("label"), tuple(c.get("properties", []))) for c in await client.list_constraints()}
    if (ENTITY_LABEL, ("id",)) not in present:
        await client.create_unique_constraint(ENTITY_LABEL, "id")
        constraints.append(f"UNIQUE {ENTITY_LABEL}.id")
    return created_idx, constraints


async def seed(
    client: GraphClient, data_dir: str | Path, *, anchor: datetime | None = None, tenant: str | None = None
) -> SeedReport:
    data = load_dataset(data_dir)
    anchor = anchor or utcnow()
    tenant = tenant or data["dataset"]["tenant"]
    idx, cons = await ensure_indexes(client)

    by_label: dict[str, list[dict[str, Any]]] = defaultdict(list)
    label_of: dict[str, str] = {}
    for node in data["nodes"]:
        label_of[node["id"]] = node["label"]
        by_label[node["label"]].append({"id": node["id"], "props": _resolve_props(node.get("props", {}), anchor)})

    nodes_written = 0
    for label, rows in by_label.items():
        for i in range(0, len(rows), _BATCH):
            batch = rows[i : i + _BATCH]
            await client.rw(
                f"UNWIND $rows AS row MERGE (n:{ENTITY_LABEL}:{label} {{id: row.id}}) "
                "SET n += row.props, n.tenant = $tenant, n.synthetic = true",
                {"rows": batch, "tenant": tenant},
                op="seed_nodes",
            )
            nodes_written += len(batch)

    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for edge in data["edges"]:
        key = (edge["type"], label_of[edge["from"]], label_of[edge["to"]])
        groups[key].append(
            {"src": edge["from"], "dst": edge["to"], "props": _resolve_props(edge.get("props", {}), anchor)}
        )
    edges_written = 0
    for (rtype, src_label, dst_label), rows in groups.items():
        for i in range(0, len(rows), _BATCH):
            batch = rows[i : i + _BATCH]
            await client.rw(
                f"UNWIND $rows AS row MATCH (a:{src_label} {{id: row.src}}) MATCH (b:{dst_label} {{id: row.dst}}) "
                f"MERGE (a)-[r:{rtype}]->(b) SET r += row.props, r.synthetic = true",
                {"rows": batch},
                op="seed_edges",
            )
            edges_written += len(batch)

    meta = data["dataset"]
    await client.rw(
        "MERGE (m:GraphMeta {id: 'graph-meta'}) SET m.dataset = $name, m.dataset_version = $version, "
        "m.anchor = $anchor, m.seeded_at = $seeded_at, m.synthetic = true, m.tenant = $tenant",
        {
            "name": meta["name"],
            "version": meta["version"],
            "anchor": to_iso(anchor),
            "seeded_at": to_iso(utcnow()),
            "tenant": tenant,
        },
        op="seed_meta",
    )
    log.info("graph.seeded", nodes=nodes_written, edges=edges_written, anchor=to_iso(anchor))
    return SeedReport(
        dataset_version=meta["version"],
        anchor=to_iso(anchor),
        nodes_written=nodes_written,
        edges_written=edges_written,
        indexes=idx,
        constraints=cons,
    )


async def validate_graph(client: GraphClient, data_dir: str | Path) -> list[str]:
    """Compare the live graph with the dataset. Returns a list of problems (empty == valid)."""
    data = load_dataset(data_dir)
    problems: list[str] = []
    rows = await client.ro(f"MATCH (n:{ENTITY_LABEL}) WHERE n.synthetic = true RETURN n.id", op="validate")
    live_ids = {r[0] for r in rows}
    expected = {n["id"] for n in data["nodes"]}
    missing = expected - live_ids
    if missing:
        problems.append(f"{len(missing)} dataset nodes missing: {sorted(missing)[:10]}")
    dup = await client.ro(
        f"MATCH (n:{ENTITY_LABEL}) WITH n.id AS id, count(*) AS c WHERE c > 1 RETURN id, c", op="validate"
    )
    if dup:
        problems.append(f"duplicate ids: {dup[:10]}")
    dup_edges = await client.ro(
        "MATCH (a)-[r]->(b) WITH a.id AS s, type(r) AS t, b.id AS d, count(r) AS c WHERE c > 1 "
        "RETURN s, t, d, c LIMIT 10",
        op="validate",
    )
    if dup_edges:
        problems.append(f"duplicate edges: {dup_edges}")
    edge_count = await client.ro("MATCH ()-[r]->() WHERE r.synthetic = true RETURN count(r)", op="validate")
    if edge_count and edge_count[0][0] < len(data["edges"]):
        problems.append(f"expected >= {len(data['edges'])} synthetic edges, found {edge_count[0][0]}")
    return problems
