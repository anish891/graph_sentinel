# Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `set FALKORDB_PASSWORD in .env` on `docker compose up` | No `.env` | `make env` |
| `/ready` → `"graph": false` | FalkorDB not running / wrong password | `docker compose ps`; `docker compose logs falkordb`; check `FALKORDB_PASSWORD` matches |
| Alerts list empty | Graph not seeded | `make seed` (idempotent) then `make validate` |
| `503 llm_not_configured` when starting an investigation | `DEMO_MODE=false` and Azure not fully configured | Set `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_DEPLOYMENT`, or `DEMO_MODE=true` |
| Investigation error "Azure OpenAI rejected the credentials" | Wrong key / no access to the resource | Check key and endpoint pair; not retried by design |
| "endpoint, API version or deployment not found" | Deployment name typo, or region/version without the Responses API | Fix `AZURE_OPENAI_DEPLOYMENT`; keep `AZURE_OPENAI_API_MODE=auto` (falls back to Chat Completions) or set `chat` |
| Investigation `failed`: "Interrupted by a service restart" | Backend restarted mid-run | Re-run; in-process tasks are not resumable (see architecture) |
| 403 "CSRF token missing or invalid" | Cookie session POST without `X-CSRF-Token` | Send the `gs_csrf` cookie value in the header, or use a bearer token |
| 403 "Separation of duties" | Approver is also the requester | Approve with a different user |
| 409 "Stale approval" | Policy version changed | Reload the action and approve again |
| 409 "already executed_simulation" | Duplicate approval with a new key | Expected — no double execution |
| 429 | Rate limit | Wait; raise `RATE_LIMIT_PER_MINUTE` for local load tests |
| UI shows "Mock planner (not an LLM)" although Azure is set | Incomplete Azure config | Admin → Settings → configuration issues |
| FalkorDB container restarting with exit code 139 | Crash while loading persisted data (seen with AOF in v4.22) | This repo uses RDB only. If you enabled AOF: stop the stack, remove `appendonlydir` from the `falkordb-data` volume (`docker compose run --rm --no-deps --entrypoint sh falkordb -c 'rm -rf /var/lib/falkordb/data/appendonlydir'`) and restart; data is loaded from `dump.rdb` |
| Port 6379/8080 already in use | Other service | `FALKORDB_HOST_PORT=6380` / `FRONTEND_HOST_PORT=8081` in `.env` |
| Graph tests skipped | FalkorDB not reachable from the host | `docker compose up -d falkordb`; host tests use `FALKORDB_HOST=localhost` |
| Audit verify `valid: false` | Records modified outside the app | Investigate; restore from backup; see threat model |

Useful commands:

```bash
docker compose logs -f backend          # JSON logs with request_id / investigation_id
make stats validate audit-verify
docker compose exec backend graphsentinel --help
```
