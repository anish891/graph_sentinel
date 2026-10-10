# GraphSentinel AI

**Explainable, graph-native security investigation agent** — FalkorDB *Agents
That Act on Connected Data*.

GraphSentinel investigates a security alert by **traversing the relationships** between identities,
IPs, devices, services, vulnerabilities, indicators, evidence and historical incidents stored in
**FalkorDB**. An LLM agent (Azure OpenAI, or an offline deterministic planner) chooses *which* bounded
graph tools to run; **deterministic engines** compute the risk score and decide which simulated
response actions are eligible; humans approve them. Every finding cites the graph records that
support it, and every step is written to a hash-chained audit trail.

> ⚠️ All data is **synthetic** (see [data/synthetic/SEED_REPORT.md](data/synthetic/SEED_REPORT.md)).
> All response actions are **simulated**. Demo authentication is **not** production authentication.

---

## 1. What it does

Ask: *"Investigate alert ALT-1001. Is this part of a larger attack?"* The agent:

1. resolves the target and checks permissions; creates a persisted investigation record;
2. calls typed graph tools (`get_alert`, `explore_neighborhood`, `find_attack_paths`,
   `find_related_incidents`, `assess_impact`, `get_evidence`, `run_graph_algorithm`,
   `get_prior_investigations`, …) inside a bounded loop (steps, tool calls, tokens, wall clock);
3. discovers a real 5-hop chain returned by FalkorDB:
   `ALT-1001 ← jdoe → WKS-0142 → SRV-FIN-01 → Payments API → SYN-2026-1001` and links to two
   prior incidents through a shared indicator;
4. gathers supporting **and contradicting** evidence with provenance; flags a prompt-injection attempt
   hidden in a helpdesk ticket and ignores it;
5. scores risk with a documented formula (65/100, *high*, confidence *high*);
6. proposes simulated actions under policy `policy-2026.10.1` (isolate WKS-0142, rotate jdoe's
   credentials, block the indicator, patch the Payments API, escalate) — each pending approval;
7. records the investigation in SQLite and **projects it back into the graph**, so the next
   investigation of a related alert *recalls it by traversal*.

## 2. Why FalkorDB is essential (not decorative)

| Decision | Comes from |
|---|---|
| Is the alert part of a larger attack? | Variable-length, typed, tenant-scoped path queries over *propagation* relationships, with incidents/vulnerabilities only as path endpoints and historical edges filtered by `valid_to`. |
| Which assets are at risk? | Directed reachability (`CONNECTED_TO`, `ASSIGNED_TO`, `RUNS`, `DEPENDS_ON`, `ACCESSED`) — distinguishes *downstream dependencies* from *upstream dependents* and merely co-located entities. |
| Is it isolated? | `algo.WCC` connected components inside FalkorDB. |
| Chokepoints | `algo.betweenness` / `algo.pageRank` inside FalkorDB. |
| Linked history | Paths to `Incident` nodes, classified direct/indirect by hop count. |
| Memory across sessions | `Investigation`/`ResponseAction` nodes written back to the graph and found by traversal. |

Remove the graph and the risk factors (`asset_criticality`, `exploitable_vulnerability`,
`historical_incidents`, `path_proximity`, `threat_intel`) all collapse to zero — the verdict is
literally computed from graph query results.

## 3. Architecture & data flow

```
Browser ──► nginx (:8080, SPA + /api reverse proxy, CSP)
               │
               ▼
          FastAPI backend ── auth (demo cookie+CSRF | OIDC bearer) ── RBAC ── rate limit
               │
   ┌───────────┼──────────────────────────────────────────────┐
   │  InvestigationService (bounded async tasks)              │
   │    Orchestrator ──► LLMProvider (Azure OpenAI | Mock)     │
   │        │  decide → validate name+args → execute → record  │
   │        ▼                                                  │
   │    ToolRegistry (typed, read-only) ──► GraphRepository ───┼──► FalkorDB (GRAPH.RO_QUERY, params,
   │    RiskEngine (deterministic)                             │        timeouts, tenant filter)
   │    PolicyEngine (deterministic) ──► ActionService ────────┼──► SimulationActionExecutor
   │    Findings/claim validation, trace (hash chain)          │
   └───────────┬──────────────────────────────────────────────┘
               ▼
          SQLite (investigations, traces, actions, idempotency, hash-chained audit)
          + graph projection of completed investigations back into FalkorDB
```

Details: [docs/architecture.md](docs/architecture.md) · [docs/agent-design.md](docs/agent-design.md) ·
[docs/graph-schema.md](docs/graph-schema.md) · [docs/threat-model.md](docs/threat-model.md) ·
[docs/api.md](docs/api.md) · [docs/deployment.md](docs/deployment.md) ·
[docs/evaluation.md](docs/evaluation.md) · [docs/demo-script.md](docs/demo-script.md) ·
[docs/troubleshooting.md](docs/troubleshooting.md)

## 4. Prerequisites

* Docker (Desktop) with Compose v2 — for the one-command demo
* For local development: Python 3.12 + [uv](https://docs.astral.sh/uv/), Node 24 + npm
* Optional: an Azure OpenAI resource with a deployed chat model

## 5. Use a real LLM (optional, for testing)

The LLM is used **only to choose which graph tools to call and to write a summary**. Nothing is
deployed to any cloud; the app, FalkorDB and all data run locally in Docker. Without an LLM, the
offline mock planner is used.

**Groq (simplest — only a key):** put your key in `.env`:

```
GROQ_API_KEY=<your Groq key>
GROQ_MODEL=qwen/qwen3.8-27b         # any Groq chat model with tool use available to your key
```

**Azure OpenAI:** needs all three of `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`
(`https://<resource>.openai.azure.com` or `https://<resource>.cognitiveservices.azure.com`) and
`AZURE_OPENAI_DEPLOYMENT`. A key alone cannot make calls.

With `LLM_PROVIDER=auto`, Azure is used if fully configured, otherwise Groq if `GROQ_API_KEY` is set.
Verify with one tiny call (prints only OK/failed, never the key), then restart the backend:

```bash
make check-llm
docker compose up -d backend
make eval-live      # optional: run the evaluation scenarios with the real model
```

Groq's free tier has small per-minute (≈8K) and daily (≈200K) token limits — a full live investigation
uses ~10 model calls (≈45K tokens) and takes several minutes; the provider trims tool output per step
(`GROQ_TOOL_OUTPUT_MAX_CHARS`, default 1500) and retries 429s honouring `Retry-After`, so a full
investigation may take a minute. Azure uses the Responses API with automatic fallback to Chat
Completions (`AZURE_OPENAI_API_MODE=auto`); Groq uses Chat Completions with tool calling.

## 6–8. Start FalkorDB, the app, and seed the graph

```bash
make demo
```

That creates `.env` (with generated local-only secrets), builds and starts FalkorDB + backend + frontend,
and seeds the graph idempotently. Open **http://localhost:8080**. Individually:

```bash
make up          # FalkorDB (persistent volume, health check) + backend + frontend
make seed        # idempotent MERGE seeding + indexes + unique constraint
make validate    # compare live graph with dataset
make stats       # node / relationship counts
make reset-demo  # wipe & reseed (refuses outside DEMO_MODE / dev environments)
```

Local development (hot reload): `make dev-backend` (API :8000) and `make dev-frontend` (Vite :5173).

## 9. Run tests

```bash
make test        # backend unit + real-FalkorDB integration (incl. 14 eval scenarios) + frontend unit
make lint typecheck
make e2e         # Playwright (needs a running stack; E2E_BASE_URL=http://localhost:8080 for Docker)
make eval        # writes reports/evaluation-offline.{md,json} from an actual run
make eval-live   # same scenarios with Azure OpenAI (when configured)
```

Graph tests are marked `@pytest.mark.graph` and skip automatically if FalkorDB is not reachable.

## 10–12. Investigate, inspect evidence, approve

1. Sign in as **Alice Analyst** (investigator) → *Alerts* → ALT-1001 → **Investigate**.
2. Watch tool calls stream in; inspect the highlighted path (hop-by-hop chain + React Flow graph),
   click nodes for their graph properties, open *Evidence* (supporting/contradicting, timeline,
   injection flag), *Risk* (formula, factor contributions, caveats), *Tool trace* (hash-chain verified).
3. Sign out → **Bob Approver** → *Approvals* → **Approve…** → tick the review box → *Approve & run
   simulation*. Alice cannot approve her own investigation (four-eyes, enforced server-side).
4. *Audit trail* shows every event with a verified hash chain. Refresh or restart — everything persists.

API example:

```bash
curl -s -c jar -X POST localhost:8080/api/v1/auth/demo-login -H 'content-type: application/json' -d '{"user_id":"alice"}'
CSRF=$(awk '/gs_csrf/ {print $7}' jar)
curl -s -b jar -X POST localhost:8080/api/v1/investigations -H "X-CSRF-Token: $CSRF" \
     -H 'content-type: application/json' -d '{"question":"Investigate alert ALT-1001"}'
```

More in [docs/api.md](docs/api.md) (OpenAPI at `/api/docs`).

## 13. Offline demo mode

With `DEMO_MODE=true` and no Azure configuration, the **mock-deterministic-planner** chooses tools
with fixed rules over the same tool outputs a model would see. It is labelled "mock planner (not an
LLM)" everywhere (UI badges, API `provider.is_mock`, audit records). Graph queries, risk, policy,
approvals and audit are all real.

## 14. Authentication

* `AUTH_MODE=demo` — four synthetic users (viewer/investigator/approver/admin), HS256-signed httpOnly
  `SameSite=Strict` session cookie + double-submit CSRF token. **Not production authentication.**
* `AUTH_MODE=oidc` — bearer JWTs validated against your IdP's JWKS (`OIDC_ISSUER`, `OIDC_AUDIENCE`,
  `OIDC_JWKS_URL`); role from `OIDC_ROLES_CLAIM`. Required when `APP_ENV=production`.

| Operation | viewer | investigator | approver | admin |
|---|:-:|:-:|:-:|:-:|
| Read alerts, graph, investigations, actions | ✓ | ✓ | ✓ | ✓ |
| Start investigations | | ✓ | | ✓ |
| Approve / reject actions (not your own investigation) | | | ✓ | ✓ |
| Cancel actions | | ✓ | | ✓ |
| Audit trail | | ✓ | ✓ | ✓ |
| Diagnostics, metrics | | | | ✓ |

## 15. Deploy safely

See [docs/deployment.md](docs/deployment.md): production refuses to start with demo auth, demo mode,
mock LLM, wildcard CORS or multi-tenant mode; run one backend replica (SQLite + in-process tasks) or
migrate to PostgreSQL + a queue; terminate TLS at ingress; keep FalkorDB private with a password;
`make backup` / `make restore`.

## 16. Limitations & future work

* Single tenant (`acme`); multi-tenancy is explicitly disabled in production config.
* Investigations run as in-process async tasks; a durable queue is needed for multiple replicas.
* Risk weights are heuristic, **not calibrated**; the dataset is small and synthetic.
* Real response integrations are intentionally absent (simulation only).
* WCC/betweenness ignore temporal validity (documented in tool output).
* The Groq and Azure OpenAI providers are unit-tested with fake clients; run `make check-llm` /
  `make eval-live` to exercise them live with your key.
* MCP adapter is stdio-only and read-only by default.

## Repository layout

```
backend/   FastAPI app (app/{api,agents,tools,graph,risk,policies,actions,audit,auth,services,...}), tests
frontend/  React + TS + Vite + Tailwind + React Flow + TanStack Query, Vitest, Playwright
data/synthetic/  dataset + seed report
docs/      architecture, schema, threat model, agent design, API, deployment, evaluation, demo, troubleshooting
.github/workflows/ci.yml   lint, types, tests with FalkorDB service, e2e, pip/npm audit, Trivy, gitleaks
docker-compose.yml, Makefile, .env.example
```
