# Architecture

## Components

| Component | Responsibility | Tech |
|---|---|---|
| **frontend** | SOC console (dashboard, alerts, investigation workspace, history, approvals, graph explorer, audit, settings). Talks only to `/api`. | React 19, TS strict, Vite, Tailwind 4, React Flow, TanStack Query, Radix Dialog |
| **nginx** | Serves the SPA, reverse-proxies `/api` (single origin → no CORS), CSP + security headers, request rate limit, 64 KB body limit. | nginx-unprivileged |
| **backend** | HTTP API, auth, RBAC, agent orchestration, deterministic engines, persistence. | FastAPI, Pydantic v2, uvicorn |
| **FalkorDB** | Authoritative security relationship graph + projection of completed investigations/actions. | FalkorDB v4.22 (pinned) |
| **SQLite** | Transactional metadata: investigation documents, per-step traces, action state machine, idempotency keys, hash-chained audit log. | aiosqlite, WAL |

## Backend layering

```
api/        HTTP controllers only: validation, auth deps, status codes → services
services/   use cases: InvestigationService, ActionService, AuditService
agents/     orchestrator (bounded loop), LLM providers, prompts, context, safety, findings
tools/      typed tool registry (Pydantic args), graph + analysis tools
graph/      FalkorDB client (timeouts, metrics, error mapping), schema whitelist, repository (queries), seeding, projection
risk/       deterministic risk engine + weights config + decay
policies/   deterministic policy engine (eligibility of simulated actions)
actions/    ActionExecutor interface + SimulationActionExecutor
audit/      hash-chain primitives
auth/       principal, RBAC matrix, demo tokens, OIDC validation
persistence/ SQLite connection, migrations, stores
observability/ structured JSON logging (redaction), Prometheus metrics, OpenTelemetry tracing
mcp/        optional MCP adapter (stdio, read-only by default)
evaluation/ scenario harness + report generator
```

## Investigation lifecycle

1. `POST /investigations` → permission check → target resolution (explicit id or exactly one `ALT-…`
   in the question; ambiguous → 422; missing in graph → 404) → provider check (503 if none) →
   record `queued` + audit + trace → background task (semaphore-bounded).
2. Orchestrator loop (`agents/orchestrator.py`) with hard limits `AGENT_MAX_STEPS`,
   `AGENT_MAX_TOOL_CALLS`, `AGENT_TOKEN_BUDGET`, `AGENT_INVESTIGATION_TIMEOUT_SECONDS`, per-tool
   `AGENT_TOOL_TIMEOUT_SECONDS`, 3 consecutive invalid calls.
3. Orchestrator-enforced baseline (`get_alert`, `find_attack_paths`, `find_related_incidents`,
   `assess_impact`, `get_evidence`) for anything the model skipped — recorded as `orchestrator_baseline`.
4. Finalisation: RiskEngine → PolicyEngine → deterministic findings + validated model claims →
   narrative → graph payload → atomic SQLite transaction (result + actions + audit) → graph projection.
5. Progressive updates: each tool call updates the stored record; the UI polls every second while running.

## Data ownership

| Data | Store | Why |
|---|---|---|
| Security entities & relationships, evidence | FalkorDB | Multi-hop traversal, algorithms |
| Investigation summary, flagged entities, cited evidence, proposed actions (mirror) | FalkorDB | Graph-native memory for later investigations |
| Full investigation document, step trace | SQLite | Large JSON, hash-chained per investigation |
| Action state, approvals, idempotency | SQLite | Compare-and-set transitions in IMMEDIATE transactions |
| Audit log | SQLite | Strict ordering, append-only triggers, hash chain |
| Users | Config (demo) / IdP (OIDC) | No local password store |

SQLite is the system of record for action state; the graph mirror is updated best-effort after commit
and logged if it fails.

## Concurrency & scaling

* One backend replica (documented): in-process tasks, rate limiter and SQLite writer are per process.
* For horizontal scale: PostgreSQL (SQL is portable), a durable queue (e.g. Redis Streams/SQS) for
  investigations, ingress rate limiting, sticky nothing (stateless API otherwise).
* On restart, investigations still `queued`/`running` are marked `failed` with an explicit reason.
