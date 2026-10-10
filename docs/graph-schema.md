# Graph schema

Source of truth: `backend/app/graph/schema.py` (also served at `GET /api/v1/graph/schema`).

Every security node has two labels: its type label and `:Entity`. A **unique constraint on
`Entity.id`** (FalkorDB v4.22 `GRAPH.CONSTRAINT`) guarantees globally unique ids and an indexed lookup.
Range indexes exist on `id` for every label plus `SecurityAlert.severity/status`, `IP.address`,
`Indicator.value`. Every node carries `tenant` and `synthetic`.

## Node labels

| Label | Key properties |
|---|---|
| SecurityAlert | id, title, severity, status, detected_at, rule, source, confidence |
| Person | id, name, title |
| Identity | id, username, kind (user/service), privileged, mfa_enabled, status |
| IP | id, address, scope (internal/external), reputation, asn, geo |
| Device | id, hostname, kind, os, criticality, status |
| Service | id, name, criticality, data_classification |
| Vulnerability | id, title, cvss, exploit_available, known_exploited |
| Incident | id, title, status, severity, opened_at, closed_at |
| Indicator | id, kind, value, confidence, first_seen, last_seen, source, status |
| Technique | id (ATT&CK), name, tactic |
| Team | id, name |
| Evidence | id, kind, source_system, source_ref, observed_at, confidence, summary (untrusted), assertion? |
| ResponseAction *(app)* | id, action_type, status, policy_version, policy_rule, simulated |
| Investigation *(app)* | id, target_id, verdict, risk_score, risk_band, completed_at, provider |
| GraphMeta *(app)* | dataset, dataset_version, anchor, seeded_at |

## Relationships (direction = arrow)

**Propagation** relationships (used for attack paths):

| Type | From → To | Meaning | Temporal |
|---|---|---|---|
| TRIGGERED | Identity/IP/Device/Service → SecurityAlert | activity triggered the alert; `role` | |
| AUTHENTICATED_FROM | Identity → IP | logins between first_seen/last_seen | ✓ |
| ACCESSED | Identity → Device/Service | sessions / API use | ✓ |
| CONNECTED_TO | IP/Device → IP/Device | observed network flow | ✓ |
| ASSIGNED_TO | IP → Device | address assignment; historical when `valid_to` < as_of | ✓ |
| RUNS | Device → Service | hosting | |
| DEPENDS_ON | Service → Service | source holds credentials for / calls target | |
| HAS_VULNERABILITY | Device/Service → Vulnerability | `status` open/remediated | ✓ |
| ASSOCIATED_WITH | Indicator/Incident → IP/Device/Identity/Service | IOC resolves to / incident involved | |
| OBSERVED_IN | Indicator → Incident/SecurityAlert | IOC seen in | |
| RELATED_TO | SecurityAlert → SecurityAlert/Incident | detection-system correlation (`reason`) | |

**Context** relationships (never used as propagation routes — sharing an owner team is not an attack
path): INDICATES (Alert→Technique), USES_TECHNIQUE (Incident→Technique), OWNS (Team→Device/Service),
MEMBER_OF (Person→Team), HAS_IDENTITY (Person→Identity), SUPPORTS / CONTRADICTS (Evidence→any, with
`claim`).

**Operational** (written by the app): INVESTIGATED, FLAGGED{role}, RECORDED_IN{stance} (Evidence→
Investigation), RECOMMENDED_ACTION, TARGETS, APPROVED_BY / REJECTED_BY (ResponseAction→Person).

## Query rules

* Incidents and Vulnerabilities may only be path **endpoints**, never interior hops.
* Paths must be simple (no repeated nodes), tenant-consistent, and — unless explicitly requested —
  contain no historical relationship.
* FalkorDB's `shortestPath()` is directed-only; undirected minimum-hop queries use a bounded
  variable-length match ordered by length (runs in FalkorDB).
* Labels / relationship types are interpolated only from the whitelist; all values are parameters;
  tools use `GRAPH.RO_QUERY` (writes rejected by FalkorDB).

## Invariants not enforceable by FalkorDB

The seeder validates (and fails before writing) that each relationship connects allowed label pairs,
that there are no duplicate ids/edges, and that ids match `^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`.
`graphsentinel validate` re-checks the live graph for duplicates.
