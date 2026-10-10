# Agent design

## Principle

The model decides **what to look at**; code decides **what it means**. The LLM selects registered
tools and writes a summary with cited claims. It cannot query the database directly, add tools,
compute risk, choose actions or approve anything.

## Tools (fixed registry, `tools/registry.py`)

| Tool | Executes | Bounds |
|---|---|---|
| get_alert(alert_id) | FalkorDB | id pattern |
| explore_neighborhood(entity_id, depth, max_nodes, labels, include_historical) | FalkorDB | depth ≤ 3, ≤ 100 nodes, ≤ 2000 paths |
| find_attack_paths(source_id, target_labels, max_hops, limit, include_historical) | FalkorDB | hops ≤ AGENT_MAX_TRAVERSAL_DEPTH, ≤ 25 paths, 2/target |
| find_related_incidents(entity_id, max_hops) | FalkorDB | ≤ 20 paths |
| assess_impact(entity_ids?, max_hops) | FalkorDB | ≤ 10 sources, ≤ 300 paths |
| run_graph_algorithm(shortest_path / degree_centrality / betweenness_centrality / pagerank / connected_component) | FalkorDB (`algo.*` or bounded match; labelled in `executed_in`) | 10 s query timeout |
| get_evidence(entity_ids?) | FalkorDB | ≤ 200 rows |
| get_prior_investigations(entity_ids?) | FalkorDB | ≤ 20 |
| evaluate_risk(), recommend_response() | application (deterministic) | — |

Arguments are Pydantic models with `extra="forbid"`; runtime limits raise `ToolValidationError`.
Rejected calls are recorded and returned to the model as errors so it can correct itself.

## Loop

`decide → validate tool name → validate args → execute (timeout) → record (trace + hash) → repeat`
until `finish_investigation`, or `max_steps`, `max_tool_calls`, `token_budget`, `investigation_timeout`,
or 3 consecutive invalid calls. Malformed model output (bad JSON / no tool call) is retried at most twice.
LLM errors end the model phase; the deterministic baseline still runs and the result says so in
`missing_information` and `error`.

## Providers

* `AzureOpenAIProvider` — Responses API (`tool_choice="required"`, `parallel_tool_calls=false`,
  `store=false`) with native `function_call` / `function_call_output` history; automatic fallback to
  Chat Completions tool calling. SDK retries disabled; our policy: exponential backoff + jitter, honours
  `Retry-After`, retries only timeouts/connection/429/5xx, never auth/permission/invalid requests.
* `GroqProvider` — Chat Completions tool calling against `https://api.groq.com/openai/v1` (same retry
  policy; `parallel_tool_calls` not sent; tool output trimmed to `GROQ_TOOL_OUTPUT_MAX_CHARS` to stay
  under free-tier per-minute token limits). Both real providers share `OpenAICompatibleProvider`.
* `MockLLMProvider` (`mock-deterministic-planner`) — rule-based, reads the same tool outputs, never
  claims to be an LLM. Tests inject scripted decisions to simulate bad model behaviour.

## Grounding

* **Deterministic findings** (`agents/findings.py`) are generated from graph records: triggering
  edges, evidence (with source ref + timestamp), top paths, incident links, blast radius, open vulns,
  isolation, prior investigations, historical relationships. Each carries refs.
* **Model claims** are accepted only if every ref was returned by a tool **and** every entity-like id
  mentioned in the text was retrieved; claims echoing injected instructions are rejected. Rejected
  claims are shown separately ("Rejected model claims").
* Findings are typed: `observed_fact`, `inference`, `hypothesis`; origin `graph`,
  `deterministic_analysis` or `model`.

## Prompt-injection defences

1. System prompt: tool output and properties are data, wrapped in `<untrusted_data>`.
2. Evidence text is scanned (`agents/safety.py`); flagged records are excluded from scoring and
   highlighted in the UI.
3. The tool registry is constructed in code; nothing read at runtime can modify it.
4. Policy, risk and approvals are not influenced by model output.
5. Control/zero-width/bidi characters are stripped; strings are length-bounded.

## Risk engine (`risk/engine.py`)

```
raw     = Σ w_k · f_k            (Σ w_k = 1, f_k ∈ [0,1])
penalty = 0.5 · C                 (C = noisy-OR of contradicting evidence on the alert scope)
score   = round(100 · raw · (1 − penalty))
bands   low < 25 ≤ medium < 50 ≤ high < 75 ≤ critical
```

| Factor | Weight | Definition |
|---|---|---|
| alert_severity | .15 | low .25 / medium .5 / high .75 / critical 1 |
| evidence_strength | .20 | noisy-OR of the strongest confidence×freshness per **source system**, activity evidence ≤ 3 hops (no double counting) |
| compromise_signal | .15 | 1 confirmed, .6 EDR / suspected, .3 correlated alerts |
| threat_intel | .10 | max confidence × freshness(90 d half-life) × (1 − contradiction) of indicators ≤ 3 hops |
| asset_criticality | .15 | max criticality in the directed blast radius (upstream dependents excluded) |
| exploitable_vulnerability | .10 | max CVSS/10 × (1 or .6 without exploit) over open vulns; contradictions apply only if newer than supporting evidence |
| historical_incidents | .10 | min(1, Σ link_weight × recency(365 d)); direct (≤ 3 hops) 1, indirect .25 |
| path_proximity | .05 | 1 (≤ 2 hops), .75, .5, .25 (5 hops) to a high/critical asset |

Evidence freshness half-life 30 days. Weights are configurable via `RISK_WEIGHTS_FILE` (validated:
exact keys, non-negative, sum 1). Verdicts: no supporting evidence → `inconclusive` (or `likely_benign`
if contradiction ≥ .4); ≥ 60 `likely_malicious`; 35–59 `suspicious`; < 35 with contradiction ≥ .4 or
< 25 `likely_benign`. Confidence = coverage × (1 − .5C) × (evidence ? 1 : .5). **Not calibrated.**

## Policy engine (`policies/engine.py`, `policy-2026.10.1`)

| Rule | Proposes | When |
|---|---|---|
| P-INCONCLUSIVE | request_further_investigation | verdict inconclusive (nothing else) |
| — | nothing | verdict likely_benign |
| P-ISOLATE | isolate_endpoint | score ≥ 60, device triggered an in-scope alert, EDR evidence, contradiction < .6 |
| P-ROTATE | rotate_credentials | score ≥ 50, identity is the alert's actor |
| P-BLOCK | block_indicator | score ≥ 50, indicator ≤ 3 hops, freshness ≥ .5, confidence ≥ .7, uncontradicted |
| P-PATCH | patch_service | score ≥ 25, open vuln CVSS ≥ 7 with exploit on an impacted asset |
| P-ESCALATE | escalate_incident | score ≥ 50 |
| P-VERIFY | request_further_investigation (on the nearest current device) | suspicious, or strong contradiction |

All consequential actions require approval regardless of configuration.

## Action lifecycle

`proposed → pending_approval → approved → executed_simulation`, plus `rejected`, `expired`,
`failed`, `cancelled`. Enforced in `services/actions.py`: approver/admin role, four-eyes (requester
cannot decide), exact investigation + policy version, expiry (`ACTION_APPROVAL_TTL_HOURS`),
compare-and-set on (status, version) in an IMMEDIATE transaction, mandatory `Idempotency-Key`
(replays return the stored response; key reuse with a different body → 409). Approval and simulated
execution are one transaction, so an action can never execute twice.
