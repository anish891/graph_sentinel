"""The GraphSentinel graph schema: the single source of truth for labels and relationships.

Labels and relationship types cannot be passed as Cypher parameters, so every query that
needs them interpolates values *only* from the whitelists defined here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.schemas.graph import GraphSchemaDoc, LabelSchema, RelationshipSchema

# Secondary label carried by every node. A unique constraint on Entity.id gives globally
# unique ids and an indexed lookup for id-only queries.
ENTITY_LABEL = "Entity"


@dataclass(frozen=True)
class LabelDef:
    name: str
    description: str
    key_properties: tuple[str, ...]
    display_property: str = "id"
    operational: bool = False  # created by the application, not part of the security graph
    extra_indexes: tuple[str, ...] = ()


@dataclass(frozen=True)
class RelDef:
    type: str
    from_labels: tuple[str, ...]
    to_labels: tuple[str, ...]
    description: str
    temporal: bool = False
    # Whether compromise can plausibly propagate along this relationship. Only these are used
    # for attack-path discovery; "context" relationships (ownership, membership, taxonomy) are
    # excluded so that sharing an owner team never looks like an attack path.
    propagation: bool = False
    operational: bool = False
    extra: dict[str, str] = field(default_factory=dict)


LABELS: dict[str, LabelDef] = {
    d.name: d
    for d in [
        LabelDef(
            "SecurityAlert",
            "A detection raised by a security control (SIEM, EDR, IDS).",
            ("id", "title", "severity", "status", "detected_at", "rule", "source"),
            "title",
            extra_indexes=("severity", "status"),
        ),
        LabelDef("Person", "A human in the (synthetic) organisation.", ("id", "name", "title"), "name"),
        LabelDef(
            "Identity",
            "An account (user or service) that can authenticate.",
            ("id", "username", "kind", "privileged", "mfa_enabled", "status"),
            "username",
        ),
        LabelDef(
            "IP",
            "An IP address, internal or external.",
            ("id", "address", "scope", "reputation"),
            "address",
            extra_indexes=("address",),
        ),
        LabelDef(
            "Device",
            "A workstation, server or appliance.",
            ("id", "hostname", "kind", "os", "criticality", "status"),
            "hostname",
        ),
        LabelDef(
            "Service", "A business or technical service.", ("id", "name", "criticality", "data_classification"), "name"
        ),
        LabelDef(
            "Vulnerability",
            "A (synthetic) vulnerability record.",
            ("id", "title", "cvss", "exploit_available", "known_exploited"),
            "title",
        ),
        LabelDef(
            "Incident",
            "A historical security incident.",
            ("id", "title", "status", "severity", "opened_at", "closed_at"),
            "title",
        ),
        LabelDef(
            "Indicator",
            "An indicator of compromise (IP, domain, hash).",
            ("id", "kind", "value", "confidence", "first_seen", "last_seen", "source"),
            "value",
            extra_indexes=("value",),
        ),
        LabelDef("Technique", "A MITRE ATT&CK technique (public taxonomy).", ("id", "name", "tactic"), "name"),
        LabelDef("Team", "An owning team.", ("id", "name"), "name"),
        LabelDef(
            "Evidence",
            "A source record (log, telemetry, ticket, intel) with provenance.",
            ("id", "kind", "source_system", "source_ref", "observed_at", "confidence", "summary"),
            "id",
        ),
        LabelDef(
            "ResponseAction",
            "A simulated response action proposed by an investigation.",
            ("id", "action_type", "status", "policy_version"),
            "action_type",
            operational=True,
        ),
        LabelDef(
            "Investigation",
            "A completed investigation (projection of the persisted record).",
            ("id", "verdict", "risk_score", "completed_at"),
            "id",
            operational=True,
        ),
        LabelDef("GraphMeta", "Dataset metadata (version, anchor time).", ("id",), "id", operational=True),
    ]
}

SECURITY_LABELS: tuple[str, ...] = tuple(n for n, d in LABELS.items() if not d.operational)
OPERATIONAL_LABELS: tuple[str, ...] = tuple(n for n, d in LABELS.items() if d.operational)

_ENTITY_SOURCES = ("Identity", "IP", "Device", "Service")

RELATIONSHIPS: dict[str, RelDef] = {
    r.type: r
    for r in [
        RelDef(
            "TRIGGERED",
            _ENTITY_SOURCES,
            ("SecurityAlert",),
            "The entity's activity triggered the alert. `role` = actor | source_ip | host | target.",
            propagation=True,
        ),
        RelDef(
            "AUTHENTICATED_FROM",
            ("Identity",),
            ("IP",),
            "The identity authenticated from this IP between first_seen and last_seen.",
            temporal=True,
            propagation=True,
        ),
        RelDef(
            "ACCESSED",
            ("Identity",),
            ("Device", "Service"),
            "The identity accessed the device/service (session, API use).",
            temporal=True,
            propagation=True,
        ),
        RelDef(
            "CONNECTED_TO",
            ("IP", "Device"),
            ("IP", "Device"),
            "Observed network connection (netflow/EDR) from source to destination.",
            temporal=True,
            propagation=True,
        ),
        RelDef(
            "ASSIGNED_TO",
            ("IP",),
            ("Device",),
            "IP address assignment. Historical when `valid_to` is in the past.",
            temporal=True,
            propagation=True,
        ),
        RelDef("RUNS", ("Device",), ("Service",), "The device hosts the service.", propagation=True),
        RelDef(
            "DEPENDS_ON",
            ("Service",),
            ("Service",),
            "Source service depends on (holds credentials for / calls) the target service.",
            propagation=True,
        ),
        RelDef(
            "HAS_VULNERABILITY",
            ("Device", "Service"),
            ("Vulnerability",),
            "Vulnerability present on the asset. `status` = open | remediated.",
            temporal=True,
            propagation=True,
        ),
        RelDef(
            "ASSOCIATED_WITH",
            ("Indicator", "Incident"),
            ("IP", "Device", "Identity", "Service"),
            "Indicator resolves to / incident involved this entity.",
            propagation=True,
        ),
        RelDef(
            "OBSERVED_IN",
            ("Indicator",),
            ("Incident", "SecurityAlert"),
            "The indicator was observed in this incident or alert.",
            propagation=True,
        ),
        RelDef(
            "RELATED_TO",
            ("SecurityAlert",),
            ("SecurityAlert", "Incident"),
            "Correlation produced by a detection system (with `reason`).",
            propagation=True,
        ),
        RelDef("INDICATES", ("SecurityAlert",), ("Technique",), "The alert indicates use of the technique."),
        RelDef("USES_TECHNIQUE", ("Incident",), ("Technique",), "The incident involved the technique."),
        RelDef("OWNS", ("Team",), ("Device", "Service"), "Team ownership (context only, not propagation)."),
        RelDef("MEMBER_OF", ("Person",), ("Team",), "Team membership."),
        RelDef("HAS_IDENTITY", ("Person",), ("Identity",), "The person owns this account."),
        RelDef("SUPPORTS", ("Evidence",), tuple(SECURITY_LABELS), "Evidence supports the `claim` about the target."),
        RelDef(
            "CONTRADICTS", ("Evidence",), tuple(SECURITY_LABELS), "Evidence contradicts the `claim` about the target."
        ),
        # ---- operational (written by the application) ----
        RelDef("INVESTIGATED", ("Investigation",), tuple(SECURITY_LABELS), "Investigation target.", operational=True),
        RelDef(
            "FLAGGED",
            ("Investigation",),
            tuple(SECURITY_LABELS),
            "Entity implicated by a completed investigation (`role`).",
            operational=True,
        ),
        RelDef(
            "RECORDED_IN",
            ("Evidence",),
            ("Investigation",),
            "Evidence cited by an investigation (`stance`).",
            operational=True,
        ),
        RelDef(
            "RECOMMENDED_ACTION",
            ("Investigation",),
            ("ResponseAction",),
            "Action proposed by the investigation.",
            operational=True,
        ),
        RelDef(
            "TARGETS", ("ResponseAction",), tuple(SECURITY_LABELS), "Entity the action would affect.", operational=True
        ),
        RelDef(
            "APPROVED_BY",
            ("ResponseAction",),
            ("Person",),
            "Approver of the action (synthetic SOC person).",
            operational=True,
        ),
        RelDef("REJECTED_BY", ("ResponseAction",), ("Person",), "Rejector of the action.", operational=True),
    ]
}

PROPAGATION_RELS: tuple[str, ...] = tuple(t for t, r in RELATIONSHIPS.items() if r.propagation)
CONTEXT_RELS: tuple[str, ...] = tuple(t for t, r in RELATIONSHIPS.items() if not r.propagation and not r.operational)
SECURITY_RELS: tuple[str, ...] = tuple(t for t, r in RELATIONSHIPS.items() if not r.operational)


def rel_pattern(types: tuple[str, ...] | list[str]) -> str:
    """Build a `:A|B|C` relationship type pattern from whitelisted types only."""
    bad = [t for t in types if t not in RELATIONSHIPS]
    if bad or not types:
        raise ValueError(f"unknown relationship types: {bad}")
    return ":" + "|".join(types)


def label_list(labels: tuple[str, ...] | list[str]) -> list[str]:
    bad = [lbl for lbl in labels if lbl not in LABELS]
    if bad:
        raise ValueError(f"unknown labels: {bad}")
    return list(labels)


def schema_doc() -> GraphSchemaDoc:
    return GraphSchemaDoc(
        labels=[
            LabelSchema(label=d.name, description=d.description, key_properties=list(d.key_properties))
            for d in LABELS.values()
        ],
        relationships=[
            RelationshipSchema(
                type=r.type,
                from_labels=list(r.from_labels),
                to_labels=list(r.to_labels),
                description=r.description + (" [propagation]" if r.propagation else ""),
                temporal=r.temporal,
            )
            for r in RELATIONSHIPS.values()
        ],
    )
