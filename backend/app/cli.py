"""GraphSentinel operational CLI.

graphsentinel init-graph      create indexes and constraints
graphsentinel seed            idempotently seed the synthetic dataset
graphsentinel validate        compare the live graph with the dataset
graphsentinel stats           print node / relationship counts
graphsentinel verify-audit    verify the audit hash chain
graphsentinel reset-demo --yes   wipe and reseed (demo environments only)
graphsentinel eval            run the evaluation suite and write a report
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from app.core.config import get_settings
from app.graph.client import GraphClient
from app.graph.repository import GraphRepository
from app.graph.seed import ensure_indexes, seed, validate_graph
from app.observability.logging import configure_logging


async def _init_graph() -> int:
    s = get_settings()
    client = GraphClient(s)
    try:
        idx, cons = await ensure_indexes(client)
        print(json.dumps({"graph": client.graph_name, "indexes_created": idx, "constraints_created": cons}, indent=2))
        return 0
    finally:
        await client.close()


async def _seed() -> int:
    s = get_settings()
    client = GraphClient(s)
    try:
        report = await seed(client, s.synthetic_data_dir, tenant=s.default_tenant)
        print(json.dumps(report.__dict__, indent=2))
        return 0
    finally:
        await client.close()


async def _validate() -> int:
    s = get_settings()
    client = GraphClient(s)
    try:
        problems = await validate_graph(client, s.synthetic_data_dir)
        print(json.dumps({"valid": not problems, "problems": problems}, indent=2))
        return 0 if not problems else 1
    finally:
        await client.close()


async def _stats() -> int:
    s = get_settings()
    client = GraphClient(s)
    try:
        stats = await GraphRepository(client, s.default_tenant).stats()
        print(stats.model_dump_json(indent=2))
        return 0
    finally:
        await client.close()


async def _verify_audit() -> int:
    from app.persistence.db import Database
    from app.services.audit import AuditService

    s = get_settings()
    db = Database(s.sqlite_path)
    await db.connect()
    try:
        result = await AuditService(db).verify_chain()
        print(result.model_dump_json(indent=2))
        return 0 if result.valid else 1
    finally:
        await db.close()


async def _reset_demo(confirmed: bool) -> int:
    s = get_settings()
    if not (s.demo_mode and s.app_env in ("development", "demo", "test")):
        print(
            "refusing: reset-demo only runs with DEMO_MODE=true and APP_ENV in development|demo|test", file=sys.stderr
        )
        return 2
    if not confirmed:
        print("refusing: pass --yes to wipe the demo graph and runtime database", file=sys.stderr)
        return 2
    from app.persistence.db import Database
    from app.services.audit import AuditService

    client = GraphClient(s)
    db = Database(s.sqlite_path)
    try:
        await client.delete_graph()
        await db.connect()
        await db.reset_all()  # in place: safe while the API is running
        await AuditService(db).record(
            actor="cli",
            actor_role="admin",
            tenant=s.default_tenant,
            event_type="demo.reset",
            resource_type="system",
            resource_id=None,
        )
        report = await seed(client, s.synthetic_data_dir, tenant=s.default_tenant)
        print(json.dumps({"reset": True, "graph": client.graph_name, "seed": report.__dict__}, indent=2))
        return 0
    finally:
        await client.close()
        await db.close()


async def _check_llm() -> int:
    """One minimal live call to confirm the configured LLM (Groq or Azure OpenAI) works for tool calling."""
    from app.agents.llm.base import DecisionRequest, ToolSpec
    from app.agents.llm.factory import build_provider
    from app.core.errors import LLMError

    s = get_settings()
    choice = s.effective_llm_provider
    if choice in ("mock", "unavailable"):
        print(
            "No LLM configured. Set GROQ_API_KEY in .env (or AZURE_OPENAI_API_KEY + AZURE_OPENAI_ENDPOINT + "
            "AZURE_OPENAI_DEPLOYMENT). Values are never printed."
        )
        return 2
    provider = build_provider(s)
    ping = ToolSpec(
        name="get_alert",
        description="Retrieve a security alert by id.",
        parameters={"type": "object", "properties": {"alert_id": {"type": "string"}}, "required": ["alert_id"]},
    )
    req = DecisionRequest(
        investigation_id="check-llm",
        question="Investigate alert ALT-1001.",
        target_id="ALT-1001",
        tools=[ping],
        history=[],
        remaining_tool_calls=1,
        remaining_steps=1,
    )
    try:
        decision = await provider.decide(req)
    except LLMError as exc:
        print(f"FAILED ({provider.name}, model '{provider.model}', {provider.api} API): {exc.message}")
        list_models = getattr(provider, "list_models", None)
        if list_models is not None and "not found" in exc.message:
            try:
                print("Models available to this key:", ", ".join(await list_models()))
            except Exception as list_exc:
                print(f"(could not list models: {type(list_exc).__name__})")
        return 1
    finally:
        await provider.aclose()
    print(
        f"OK — {provider.name} model '{provider.model}' answered via the {provider.api} API with a "
        f"{decision.kind} ({decision.tool_name or 'finish'}); tokens in/out "
        f"{decision.usage.input_tokens}/{decision.usage.output_tokens}."
    )
    return 0


async def _eval(output_dir: str, live: bool, only: list[str] | None = None) -> int:
    from app.evaluation.runner import run_evaluation

    return await run_evaluation(output_dir=output_dir, live=live, only=only)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="graphsentinel", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-graph")
    sub.add_parser("seed")
    sub.add_parser("validate")
    sub.add_parser("stats")
    sub.add_parser("verify-audit")
    sub.add_parser("check-llm", help="one tiny live call to verify the LLM settings")
    reset = sub.add_parser("reset-demo")
    reset.add_argument("--yes", action="store_true")
    ev = sub.add_parser("eval")
    ev.add_argument("--output-dir", default="../reports")
    ev.add_argument("--live", action="store_true", help="use the configured LLM (Groq or Azure OpenAI)")
    ev.add_argument("--scenarios", default="", help="comma-separated subset, e.g. S01,S02,S05")
    args = parser.parse_args()
    configure_logging(get_settings().log_level if args.cmd != "eval" else "WARNING")
    handlers = {
        "init-graph": _init_graph,
        "seed": _seed,
        "validate": _validate,
        "stats": _stats,
        "verify-audit": _verify_audit,
        "check-llm": _check_llm,
    }
    if args.cmd == "reset-demo":
        code = asyncio.run(_reset_demo(args.yes))
    elif args.cmd == "eval":
        code = asyncio.run(
            _eval(
                args.output_dir, args.live, [x.strip().upper() for x in args.scenarios.split(",") if x.strip()] or None
            )
        )
    else:
        code = asyncio.run(handlers[args.cmd]())
    sys.exit(code)


if __name__ == "__main__":
    main()
