"""Graph data contracts. These are deliberately independent of FalkorDB driver types."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class GraphNode(BaseModel):
    id: str
    label: str
    labels: list[str]
    display_name: str
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str = Field(description="Stable id: '<source>|<TYPE>|<target>'")
    type: str
    source: str
    target: str
    properties: dict[str, Any] = Field(default_factory=dict)
    temporal_status: Literal["current", "historical"] = "current"


class GraphPath(BaseModel):
    id: str
    node_ids: list[str]
    edge_ids: list[str]
    hops: int
    start_id: str
    end_id: str
    end_label: str
    description: str
    contains_historical: bool = False


class Truncation(BaseModel):
    truncated: bool = False
    reason: str | None = None
    max_nodes: int | None = None
    max_depth: int | None = None


class GraphPayload(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    paths: list[GraphPath] = Field(default_factory=list)
    highlighted_path_ids: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    truncation: Truncation = Field(default_factory=Truncation)


class GraphStats(BaseModel):
    graph_name: str
    node_count: int
    edge_count: int
    nodes_by_label: dict[str, int]
    edges_by_type: dict[str, int]
    dataset: dict[str, Any] = Field(default_factory=dict)


class LabelSchema(BaseModel):
    label: str
    description: str
    key_properties: list[str]


class RelationshipSchema(BaseModel):
    type: str
    from_labels: list[str]
    to_labels: list[str]
    description: str
    temporal: bool = False


class GraphSchemaDoc(BaseModel):
    labels: list[LabelSchema]
    relationships: list[RelationshipSchema]
    indexes: list[dict[str, Any]] = Field(default_factory=list)
    constraints: list[dict[str, Any]] = Field(default_factory=list)
