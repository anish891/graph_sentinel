# API

Base path `/api/v1`. Interactive OpenAPI: `/api/docs` (schema at `/api/v1/openapi.json`).

## Conventions

* **Auth:** demo session cookie (`gs_session`, httpOnly, SameSite=Strict) + `X-CSRF-Token` header on
  POST; or `Authorization: Bearer <jwt>` (OIDC, or a demo token from `demo-login` with `as_bearer`).
* **Errors:** `{"error": {"code", "message", "request_id", "details"}}` with proper status codes
  (401, 403, 404, 409, 413, 422, 429, 502–504). Internal details are never returned.
* **Pagination:** `?page=1&page_size=25` (max 100) → `{"items", "total", "page", "page_size"}`.
* **Correlation:** every response carries `X-Request-ID` (honours a sane incoming value).
* **Idempotency:** action decisions require `Idempotency-Key`.

## Endpoints

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | /health | public | process liveness only |
| GET | /ready | public | `{"graph": bool, "metadata_db": bool}`; 503 if not ready |
| GET | /system/status | authenticated | provider (mock/azure), integration flags, policy version |
| GET | /dashboard/summary | investigations:read | counters for the overview |
| GET | /diagnostics | admin | config issues; secrets shown only as set/not set |
| GET | /metrics | admin | Prometheus text |
| GET | /auth/demo-users · POST /auth/demo-login · POST /auth/logout · GET /auth/me | — | demo mode only (404 otherwise) |
| GET | /graph/schema · /graph/stats · /graph/search?q= | graph:read | |
| GET | /entities/{id} · /entities/{id}/neighbors?depth=1..3&max_nodes&include_historical | graph:read | bounded |
| GET | /alerts?severity&status&q&sort=detected_at\|severity\|id&order | alerts:read | |
| GET | /alerts/{id} | alerts:read | links, evidence, prior investigations |
| POST | /investigations | investigations:create | 202; runs asynchronously |
| GET | /investigations?status&target_id | investigations:read | |
| GET | /investigations/{id} | investigations:read | full result (live while running) |
| GET | /investigations/{id}/trace | investigations:read | events + integrity check |
| GET | /investigations/{id}/evidence | investigations:read | evidence package |
| GET | /investigations/{id}/graph | investigations:read | `GraphPayload` |
| GET | /investigations/{id}/recommendations | investigations:read | actions + policy version |
| GET | /actions?status&investigation_id · /actions/{id} | actions:read | |
| POST | /actions/{id}/approve | actions:approve (+ four-eyes) | body below |
| POST | /actions/{id}/reject | actions:reject | `{investigation_id, policy_version, reason}` |
| POST | /actions/{id}/cancel | actions:cancel | `{reason}` |
| GET | /audit/events?event_type&resource_id · /audit/verify | audit:read | |

## Examples

```bash
B=http://localhost:8080/api/v1
TOKEN=$(curl -s -X POST $B/auth/demo-login -H 'content-type: application/json' \
  -d '{"user_id":"alice","as_bearer":true}' | jq -r .access_token)

curl -s -X POST $B/investigations -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"question":"Investigate alert ALT-1001. Is this part of a larger attack?"}'
# 202 {"id":"INV-…","status":"queued","provider":{"name":"mock-deterministic-planner","is_mock":true,…},…}

curl -s $B/investigations/INV-… -H "Authorization: Bearer $TOKEN" | jq '{status, verdict, score: .risk.score, actions: [.recommended_actions[].action_type]}'
# {"status":"completed","verdict":"likely_malicious","score":65,
#  "actions":["escalate_incident","isolate_endpoint","block_indicator","rotate_credentials","block_indicator","patch_service"]}

BOB=$(curl -s -X POST $B/auth/demo-login -H 'content-type: application/json' -d '{"user_id":"bob","as_bearer":true}' | jq -r .access_token)
curl -s -X POST $B/actions/ACT-…/approve -H "Authorization: Bearer $BOB" -H 'Idempotency-Key: 7c6c…' \
  -H 'content-type: application/json' \
  -d '{"investigation_id":"INV-…","policy_version":"policy-2026.10.1","confirm":true,"comment":"reviewed"}'
# 200 {"status":"executed_simulation","decided_by":"demo:bob",
#      "execution_result":{"simulated":true,"description":"Would request network containment of dev-wks-0142…","external_systems_contacted":[]},…}
```

Error example:

```json
{"error": {"code": "permission_denied",
           "message": "Separation of duties: the investigation requester cannot approve its actions.",
           "request_id": "1f0c…", "details": {}}}
```
