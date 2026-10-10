# Threat model

Scope: the GraphSentinel application as shipped (demo and production-oriented configuration).
Method: assets → trust boundaries → threats (STRIDE-style) → mitigations → residual risk.

## Assets

Security graph contents · investigation conclusions and evidence packages · action approvals ·
audit log integrity · Azure OpenAI key, FalkorDB password, session signing key · availability.

## Trust boundaries

1. Browser ↔ nginx/backend (untrusted client).
2. Backend ↔ LLM provider (model output is untrusted).
3. Backend ↔ graph content (evidence text and properties are untrusted data).
4. Backend ↔ FalkorDB / SQLite (trusted infrastructure, network-isolated).
5. MCP client ↔ MCP adapter (local process).

## Threats and mitigations

| Threat | Mitigation | Where |
|---|---|---|
| Prompt injection via evidence/properties | Data wrapped as untrusted; injection heuristics flag & exclude; tools fixed in code; policy/risk/approval independent of the model; claims echoing instructions rejected | `agents/safety.py`, `findings.py`, scenario S10 |
| Model hallucinating entities/links | Claims must cite retrieved ids and only mention retrieved entities; deterministic narrative | `validate_claims`, S13 |
| Arbitrary / destructive queries | No Cypher from model or user; whitelist interpolation only; parameters; `GRAPH.RO_QUERY`; timeouts; result caps | `graph/repository.py`, `client.py` |
| Resource exhaustion | Depth/node/path caps, per-query & per-tool timeouts, investigation timeout, token budget, concurrency semaphore + queue cap, rate limit (app + nginx), body size limits | config, middleware |
| Unauthorised approval / self-approval | Server-side RBAC, four-eyes, agent principal blocked, deliberate confirmation | `services/actions.py`, S11 |
| Replay / double execution | Idempotency keys, CAS on version, single transaction approve+execute | S12 |
| Stale approval | Policy version + investigation id must match; expiry | `ApprovalRequest` |
| CSRF | SameSite=Strict httpOnly session + double-submit CSRF header on unsafe methods; bearer tokens exempt | `api/deps.py` |
| XSS | React escaping, no `dangerouslySetInnerHTML`, CSP `script-src 'self'` | nginx |
| Secret leakage | `SecretStr`, redacting log processor, diagnostics show only "set/not set", no secrets in `.env.example`, `.env` git-ignored, FalkorDB container receives only its password | config, logging |
| Error-detail leakage | Central handlers return code/message/request id; driver messages logged server-side only | `main.py`, `client.py` |
| Tenant crossover | Tenant from principal (never client); every query filters `tenant`; multi-tenant disabled in production | repository, config |
| Audit tampering | Append-only triggers + SHA-256 hash chain verifiable via `/audit/verify` / CLI | below |
| Real-world harm | Only `SimulationActionExecutor` exists; `SIMULATION_ONLY=false` fails validation | `actions/executor.py` |
| Supply chain | Pinned versions + lockfiles; pip-audit, npm audit, Trivy, gitleaks in CI; pinned images | CI |

## Hash-chain limitations

`hash_n = SHA-256(hash_{n-1} || canonical(record_n))`. It detects modification, deletion or
re-ordering of individual records by someone who cannot also rewrite all subsequent hashes. It does
**not** make the database tamper-proof: an attacker with write access to the whole store can drop the
triggers and recompute the chain. Mitigate by anchoring the head hash externally (ticket, WORM bucket,
transparency log) and restricting DB file access. Trace chains per investigation have the same limits.

## Residual risks / non-goals

* Demo authentication has no credentials — never expose a demo deployment publicly.
* Injection detection is heuristic; it is defence in depth, not the primary control (the primary
  control is that model output cannot change tools, policy, scores or approvals).
* Single-process rate limiting; use ingress limits for multi-replica.
* The MCP adapter trusts its local launcher; do not expose it over a network transport without auth.
* No compliance certification is claimed.
