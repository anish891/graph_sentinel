# GraphSentinel AI — developer commands. Run `make help`.
SHELL := /bin/bash
COMPOSE := docker compose
BACKEND := cd backend &&
FRONTEND := cd frontend &&

.DEFAULT_GOAL := help
.PHONY: help setup env up down logs ps seed validate stats reset-demo demo dev-backend dev-frontend \
        test test-unit test-graph test-frontend e2e lint typecheck format eval eval-live check-llm mcp audit-verify \
        backup restore security-scan clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

env: ## Create .env from the template with generated local-only secrets (never overwrites)
	@if [ -f .env ]; then echo ".env exists — leaving it untouched"; else \
	  cp .env.example .env; \
	  PW=$$(python3 -c "import secrets;print(secrets.token_urlsafe(24))"); \
	  SK=$$(python3 -c "import secrets;print(secrets.token_urlsafe(48))"); \
	  sed -i.bak -e "s|^FALKORDB_PASSWORD=.*|FALKORDB_PASSWORD=$$PW|" -e "s|^AUTH_SECRET_KEY=.*|AUTH_SECRET_KEY=$$SK|" .env && rm -f .env.bak; \
	  echo "created .env (add your Azure OpenAI settings there if you have them)"; fi

setup: env ## Install backend (uv) and frontend (npm) dependencies + Playwright browser
	$(BACKEND) uv sync
	$(FRONTEND) npm ci --no-audit --no-fund
	$(FRONTEND) npx playwright install chromium

up: env ## Build and start FalkorDB, backend and frontend (http://localhost:8080)
	$(COMPOSE) up -d --build
	@echo "Waiting for backend health..."; for i in $$(seq 1 60); do \
	  [ "$$($(COMPOSE) ps backend --format '{{.Health}}')" = "healthy" ] && break; sleep 2; done
	@$(COMPOSE) ps

down: ## Stop the stack (data volumes are kept)
	$(COMPOSE) down

logs: ## Tail logs
	$(COMPOSE) logs -f --tail=100

ps: ## Show container status
	$(COMPOSE) ps

seed: ## Idempotently create indexes and seed the synthetic graph (in the running stack)
	$(COMPOSE) exec backend graphsentinel seed

validate: ## Validate the live graph against the dataset
	$(COMPOSE) exec backend graphsentinel validate

stats: ## Graph node/relationship counts
	$(COMPOSE) exec backend graphsentinel stats

reset-demo: ## Wipe and reseed the demo graph and runtime DB (demo environments only)
	$(COMPOSE) exec backend graphsentinel reset-demo --yes

demo: up seed ## Start everything, seed, and print the demo URL
	@echo ""; echo "GraphSentinel AI is running at http://localhost:8080 (offline demo mode unless Azure is configured)"

audit-verify: ## Verify the audit hash chain
	$(COMPOSE) exec backend graphsentinel verify-audit

# ---- local development (backend + Vite on the host; FalkorDB in Docker) ---------------------------
dev-backend: ## Run FalkorDB in Docker and the API with reload on :8000
	$(COMPOSE) up -d falkordb
	$(BACKEND) uv run graphsentinel seed
	$(BACKEND) uv run uvicorn app.main:app --reload --port 8000

dev-frontend: ## Run the Vite dev server on :5173 (proxies /api to :8000)
	$(FRONTEND) npm run dev

# ---- quality ---------------------------------------------------------------------------------------
test: test-unit test-graph test-frontend ## All automated tests (graph tests need FalkorDB)

test-unit: ## Backend unit tests (no external services)
	$(BACKEND) uv run pytest tests/unit -q

test-graph: ## Backend integration tests against a real FalkorDB (isolated test graphs)
	$(COMPOSE) up -d falkordb
	$(BACKEND) uv run pytest tests/integration -q -m graph

test-frontend: ## Frontend unit tests (Vitest + RTL)
	$(FRONTEND) npm test

e2e: ## Playwright end-to-end tests (needs a running stack; E2E_BASE_URL defaults to :5173)
	$(FRONTEND) npx playwright test

lint: ## Ruff + ESLint
	$(BACKEND) uv run ruff check app tests && uv run ruff format --check app tests
	$(FRONTEND) npm run lint

typecheck: ## mypy (strict) + tsc (strict)
	$(BACKEND) uv run mypy app
	$(FRONTEND) npm run typecheck

format: ## Auto-format backend
	$(BACKEND) uv run ruff format app tests && uv run ruff check --fix app tests

eval: ## Run the evaluation suite offline (mock planner, real FalkorDB) → reports/
	$(COMPOSE) up -d falkordb
	$(BACKEND) uv run graphsentinel eval --output-dir ../reports

check-llm: ## One tiny live call to verify the configured LLM (Groq or Azure OpenAI; reads .env)
	$(BACKEND) uv run graphsentinel check-llm

eval-live: ## Live LLM evaluation; SCENARIOS=S01,S02,S05 to run a subset (Groq free tier: ~45K tokens per scenario)
	$(BACKEND) uv run graphsentinel eval --live --output-dir ../reports --scenarios "$(SCENARIOS)"

mcp: ## Run the read-only MCP server over stdio
	$(BACKEND) uv run python -m app.mcp.server

security-scan: ## Dependency audits (pip-audit, npm audit)
	$(BACKEND) uv run pip-audit --strict --progress-spinner off || true
	$(FRONTEND) npm audit --omit=dev || true

backup: ## Snapshot FalkorDB (BGSAVE) and the metadata DB into ./backups/<timestamp>
	@TS=$$(date -u +%Y%m%dT%H%M%SZ); mkdir -p backups/$$TS; \
	$(COMPOSE) exec -T falkordb sh -c 'redis-cli -a "$$FALKORDB_PASSWORD" --no-auth-warning BGSAVE && sleep 2'; \
	$(COMPOSE) cp falkordb:/var/lib/falkordb/data/dump.rdb backups/$$TS/dump.rdb; \
	$(COMPOSE) exec -T backend python -c "import sqlite3;s=sqlite3.connect('/app/runtime/graphsentinel.db');d=sqlite3.connect('/app/runtime/backup.db');s.backup(d);d.close()"; \
	$(COMPOSE) cp backend:/app/runtime/backup.db backups/$$TS/graphsentinel.db; \
	echo "backup written to backups/$$TS"

restore: ## Restore from BACKUP=backups/<timestamp> (stops the stack briefly)
	@test -n "$(BACKUP)" || (echo "usage: make restore BACKUP=backups/<timestamp>"; exit 2)
	$(COMPOSE) stop backend falkordb
	$(COMPOSE) cp $(BACKUP)/dump.rdb falkordb:/var/lib/falkordb/data/dump.rdb
	$(COMPOSE) cp $(BACKUP)/graphsentinel.db backend:/app/runtime/graphsentinel.db
	$(COMPOSE) start falkordb backend

clean: ## Remove local caches and build output (not data volumes)
	rm -rf backend/.pytest_cache backend/.mypy_cache backend/.ruff_cache frontend/dist frontend/test-results frontend/playwright-report
