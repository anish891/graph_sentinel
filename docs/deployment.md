# Deployment

## Local / demo (Docker Compose)

`make demo` → FalkorDB (pinned `v4.22.0`, password, persistent volume, loopback-only port, health
check, memory limit), backend (non-root uid 10001, health check, single worker), frontend (nginx
unprivileged, health check, CSP). Only `127.0.0.1:8080` is published.

## Production checklist

The settings validator **refuses to start** with `APP_ENV=production` if any of these is wrong:
`DEMO_MODE=false`, `AUTH_MODE=oidc`, `LLM_PROVIDER≠mock`, no `*` in `CORS_ORIGINS`,
`MULTI_TENANT=false`. Additionally:

1. **Secrets** (LLM API key, FalkorDB password, auth key) from your platform's secret store, injected
   as env vars; never baked into images. Azure OpenAI is only the LLM endpoint the backend calls — the
   application does not depend on any other Azure service and can run on any Docker host.
2. **TLS** at the ingress / load balancer; set `X-Forwarded-*` (uvicorn runs with `--proxy-headers`).
   Cookies become `Secure` automatically in production.
3. **FalkorDB** on a private network, `requirepass` (or ACL user via `FALKORDB_USERNAME`), TLS if
   crossing hosts (the image supports `TLS=1`), never publicly exposed, browser UI disabled.
4. **One backend replica** with the bundled SQLite. To scale out: migrate to PostgreSQL (the SQL is
   portable; replace `persistence/db.py`), move investigations to a durable queue + workers, and
   enforce rate limits at the ingress.
5. **Rate limiting** at the ingress as well as in-app (in-app limits are per process).
6. **Observability:** set `OTEL_EXPORTER_OTLP_ENDPOINT` for traces; scrape `/api/v1/metrics` with an
   admin service token; ship JSON logs.
7. **Anchor the audit head hash** (from `/audit/verify`) to external WORM storage periodically.
8. Keep `SIMULATION_ONLY=true` — real executors are not implemented and require a separate security review.

## Persistence & backup

* FalkorDB uses **RDB snapshots** (`--save 60 1 --save 300 10`, plus a final snapshot on graceful
  shutdown). AOF is deliberately disabled: during testing FalkorDB v4.22 segfaulted while replaying an
  AOF containing repeated graph delete/re-create cycles with unique constraints. Worst case after a hard
  crash: ≤ 60 s of graph writes lost. The security graph is re-seedable/re-ingestable, and investigation
  records, approvals and audit live in SQLite.
* SQLite runs in WAL mode on the `backend-data` volume.
* `make backup` → `backups/<UTC timestamp>/{dump.rdb, graphsentinel.db}` (BGSAVE + SQLite online backup).
* `make restore BACKUP=backups/<ts>` → stops backend+FalkorDB, copies files back, restarts.
* Test restores regularly; keep backups encrypted and access-controlled (they contain evidence text).

## Resource sizing (starting point, not a benchmark)

FalkorDB 1 GB, backend 768 MB, nginx 128 MB (compose limits). The synthetic graph uses ~3 MB.
Investigations on the demo graph complete in tens of milliseconds of graph time with the mock planner;
with Azure OpenAI latency is dominated by model calls (≈ number of tool calls × model latency).

## Upgrading FalkorDB

Pin a new tag in `docker-compose.yml` and CI, run `make test-graph` and `make eval` (they exercise
indexes, constraints, `ro_query`, `algo.*`), then roll out.
