"""Shared provider for OpenAI-compatible APIs (Azure OpenAI, Groq) using the official `openai` SDK.

* mode "auto" → Responses API first; if unsupported (HTTP 404, or 400 saying unsupported), fall back
  to Chat Completions with tool calling. Mode "chat" uses Chat Completions only.
* Bounded retries with exponential backoff + jitter for timeouts, connection errors, 429 and 5xx,
  honouring Retry-After. Authentication / permission / invalid-request errors are never retried.
* Nothing secret is logged: no headers, no key, no prompt bodies.
"""

from __future__ import annotations

import asyncio
import json
import random
import re
import time
from collections.abc import Awaitable, Callable
from typing import Any

import openai
from openai import AsyncOpenAI

from app.agents.llm.base import (
    FINISH_TOOL_NAME,
    AgentDecision,
    DecisionRequest,
    FinishPayload,
    LLMProvider,
    ToolSpec,
    Usage,
    finish_tool_spec,
)
from app.agents.prompts import SYSTEM_PROMPT, tool_output_text, user_message
from app.core.config import Settings
from app.core.errors import LLMError
from app.observability.logging import get_logger
from app.observability.metrics import LLM_LATENCY, LLM_TOKENS
from app.observability.tracing import tracer

log = get_logger(__name__)

_RETRYABLE = (openai.APITimeoutError, openai.APIConnectionError, openai.RateLimitError, openai.InternalServerError)


class OpenAICompatibleProvider(LLMProvider):
    """Agent decisions via function calling on any OpenAI-compatible endpoint."""

    is_mock = False
    label = "LLM provider"
    key_setting = "API key"
    # Whether to send parallel_tool_calls=false (some models reject the parameter).
    send_parallel_flag = True

    def __init__(
        self,
        settings: Settings,
        *,
        client: AsyncOpenAI,
        model: str,
        mode: str = "auto",
        tool_output_max_chars: int = 7000,
        max_output_tokens: int | None = None,
        chat_extra: dict[str, Any] | None = None,
    ) -> None:
        self.settings = settings
        self.model = model
        self._client = client
        self._mode = mode
        self._max_chars = tool_output_max_chars
        self._max_output = max_output_tokens or settings.llm_max_output_tokens
        self._chat_extra = dict(chat_extra or {})
        self._allowed_tools: set[str] = set()
        self.api = "responses" if mode in ("auto", "responses") else "chat"

    async def aclose(self) -> None:
        await self._client.close()

    # ---- public ----------------------------------------------------------------------------
    async def decide(self, request: DecisionRequest) -> AgentDecision:
        tools = [*request.tools, finish_tool_spec()]
        self._allowed_tools = {t.name for t in tools}
        if self.api == "responses":
            try:
                return await self._with_retries("responses", lambda: self._responses(request, tools))
            except LLMError as exc:
                if self._mode == "auto" and exc.details.get("unsupported_api"):
                    log.warning("llm.responses_unsupported_fallback_to_chat")
                    self.api = "chat"
                else:
                    raise
        try:
            return await self._with_retries("chat", lambda: self._chat(request, tools))
        except LLMError as exc:
            if not exc.details.get("no_tool_call"):
                raise
            # The model insisted on answering in prose although a tool call was required. Ask once more
            # allowing text; prose is accepted only as a final, claim-free summary (it is untrusted text).
            log.warning("llm.no_tool_call_retry_with_auto")
            return await self._with_retries("chat", lambda: self._chat(request, tools, tool_choice="auto"))

    # ---- retries -----------------------------------------------------------------------------
    async def _with_retries(self, api: str, fn: Callable[[], Awaitable[AgentDecision]]) -> AgentDecision:
        # Transient failures (timeouts, 5xx) and rate limits have separate budgets: rate limits are
        # expected on small free tiers and resolve once the per-minute window resets.
        max_transient = self.settings.llm_max_retries
        max_rate_limited = self.settings.llm_rate_limit_max_retries
        transient = rate_limited = 0
        attempt = 0
        while True:
            attempt += 1
            started = time.perf_counter()
            outcome = "ok"
            try:
                with tracer.start_as_current_span("llm.call", attributes={"llm.api": api, "llm.attempt": attempt}):
                    return await fn()
            except _RETRYABLE as exc:
                outcome = type(exc).__name__
                is_rate_limit = isinstance(exc, openai.RateLimitError)
                if is_rate_limit:
                    rate_limited += 1
                else:
                    transient += 1
                if (is_rate_limit and rate_limited > max_rate_limited) or (
                    not is_rate_limit and transient > max_transient
                ):
                    raise LLMError(
                        f"{self.label} unavailable after {attempt} attempts ({outcome}"
                        + ("; per-minute rate limit kept being exceeded" if is_rate_limit else "")
                        + ").",
                        retryable=True,
                    ) from exc
                n = rate_limited if is_rate_limit else transient
                delay = min(20.0, 0.5 * 2 ** (n - 1)) + random.uniform(0, 0.5)  # noqa: S311 - jitter
                hinted = _retry_after(exc)
                if hinted:
                    jitter = random.uniform(0, 0.5)  # noqa: S311 - jitter, not cryptographic
                    delay = max(delay, min(hinted + jitter, self.settings.llm_rate_limit_max_wait_seconds))
                log.warning("llm.retry", api=api, attempt=attempt, error=outcome, delay_s=round(delay, 2))
                await asyncio.sleep(delay)
            except (openai.AuthenticationError, openai.PermissionDeniedError) as exc:
                outcome = "auth"
                raise LLMError(
                    f"{self.label} rejected the credentials (check {self.key_setting}).", retryable=False
                ) from exc
            except openai.NotFoundError as exc:
                outcome = "not_found"
                raise LLMError(
                    f"{self.label}: endpoint, API version or model/deployment '{self.model}' not found.",
                    retryable=False,
                    details={"unsupported_api": api == "responses"},
                ) from exc
            except openai.BadRequestError as exc:
                outcome = "bad_request"
                msg = str(getattr(exc, "message", "")).lower()
                body = getattr(exc, "body", None)
                code = str(body.get("code", "")) if isinstance(body, dict) else ""
                # The message describes the request/model output, never credentials; log it for diagnosis.
                log.warning("llm.bad_request", api=api, code=code, message=msg[:300])
                failed = body.get("failed_generation") if isinstance(body, dict) else None
                salvaged = salvage_xml_tool_call(failed, self._allowed_tools) if isinstance(failed, str) else None
                if salvaged is not None:
                    # Some models (e.g. Qwen3) occasionally emit their native XML tool-call syntax, which
                    # the provider fails to parse. Recover it; the result is validated exactly like any
                    # other tool call (registered names only, strict args / lenient finish, claim checks).
                    log.warning("llm.salvaged_xml_tool_call", tool=salvaged[0])
                    return _decision(f"salvaged-{attempt}", salvaged[0], json.dumps(salvaged[1]), Usage())
                if (
                    code == "tool_use_failed"
                    or "tool call validation failed" in msg
                    or "failed to call a function" in msg
                ):
                    # The provider rejected the *model's* tool call (e.g. arguments not matching the schema).
                    # Treat as malformed output so the orchestrator asks again instead of aborting.
                    raise LLMError(
                        f"{self.label}: the model produced an invalid tool call ({code or 'tool validation'}).",
                        retryable=False,
                        details={"malformed": True, "no_tool_call": "did not call a tool" in msg},
                    ) from exc
                unsupported = api == "responses" and any(
                    k in msg for k in ("not supported", "unsupported", "unrecognized", "unknown url")
                )
                raise LLMError(
                    f"{self.label} rejected the request (invalid request or content filter).",
                    retryable=False,
                    details={"unsupported_api": unsupported},
                ) from exc
            except openai.APIStatusError as exc:
                outcome = f"status_{exc.status_code}"
                hint = (
                    " (request larger than the account's per-minute token limit; lower the tool output size)"
                    if exc.status_code == 413
                    else ""
                )
                raise LLMError(f"{self.label} returned HTTP {exc.status_code}{hint}.", retryable=False) from exc
            finally:
                LLM_LATENCY.labels(provider=self.name, api=api, outcome=outcome).observe(time.perf_counter() - started)
        raise LLMError("unreachable")  # pragma: no cover

    # ---- Responses API ---------------------------------------------------------------------------
    async def _responses(self, req: DecisionRequest, tools: list[ToolSpec]) -> AgentDecision:
        items: list[dict[str, Any]] = [{"role": "user", "content": user_message(req)}]
        for step in req.history:
            items.append(
                {
                    "type": "function_call",
                    "call_id": step.call_id,
                    "name": step.tool,
                    "arguments": json.dumps(step.arguments),
                }
            )
            items.append(
                {
                    "type": "function_call_output",
                    "call_id": step.call_id,
                    "output": tool_output_text({"status": step.status, **step.output}, self._max_chars),
                }
            )
        resp = await self._client.responses.create(  # type: ignore[call-overload]
            model=self.model,
            instructions=SYSTEM_PROMPT,
            input=items,
            tools=[
                {
                    "type": "function",
                    "name": t.name,
                    "description": t.description,
                    "parameters": compact_schema(t.parameters),
                    "strict": False,
                }
                for t in tools
            ],
            tool_choice="required",
            parallel_tool_calls=False,
            store=False,
            max_output_tokens=self._max_output,
        )
        usage = Usage(
            input_tokens=getattr(resp.usage, "input_tokens", 0) or 0,
            output_tokens=getattr(resp.usage, "output_tokens", 0) or 0,
        )
        self._count(usage)
        for item in resp.output or []:
            if getattr(item, "type", None) == "function_call":
                return _decision(item.call_id, item.name, item.arguments, usage)
        raise LLMError("Model returned no tool call.", retryable=False, details={"malformed": True})

    # ---- Chat Completions fallback ----------------------------------------------------------------
    async def _chat(self, req: DecisionRequest, tools: list[ToolSpec], tool_choice: str = "required") -> AgentDecision:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message(req)},
        ]
        for step in req.history:
            messages.append(
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": step.call_id,
                            "type": "function",
                            "function": {"name": step.tool, "arguments": json.dumps(step.arguments)},
                        }
                    ],
                }
            )
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": step.call_id,
                    "content": tool_output_text({"status": step.status, **step.output}, self._max_chars),
                }
            )
        extra: dict[str, Any] = {"parallel_tool_calls": False} if self.send_parallel_flag else {}
        extra.update(self._chat_extra)
        resp = await self._client.chat.completions.create(  # type: ignore[call-overload]
            model=self.model,
            messages=messages,
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": compact_schema(t.parameters),
                    },
                }
                for t in tools
            ],
            tool_choice=tool_choice,
            max_completion_tokens=self._max_output,
            **extra,
        )
        usage = Usage(
            input_tokens=getattr(resp.usage, "prompt_tokens", 0) or 0,
            output_tokens=getattr(resp.usage, "completion_tokens", 0) or 0,
        )
        self._count(usage)
        choice = resp.choices[0] if resp.choices else None
        calls = (choice.message.tool_calls or []) if choice else []
        for call in calls:
            fn = getattr(call, "function", None)
            if fn is not None:
                return _decision(call.id, fn.name, fn.arguments, usage)
        text = (getattr(choice.message, "content", None) or "").strip() if choice else ""
        if tool_choice == "auto" and len(text) >= 10:
            return AgentDecision(
                kind="finish", call_id="text-finish", finish=FinishPayload(summary=text[:2500]), usage=usage
            )
        raise LLMError("Model returned no tool call.", retryable=False, details={"malformed": True})

    def _count(self, usage: Usage) -> None:
        LLM_TOKENS.labels(provider=self.name, kind="input").inc(usage.input_tokens)
        LLM_TOKENS.labels(provider=self.name, kind="output").inc(usage.output_tokens)


_DURATION = re.compile(r"^(?:(\d+(?:\.\d+)?)h)?(?:(\d+(?:\.\d+)?)m(?!s))?(?:(\d+(?:\.\d+)?)s)?(?:(\d+(?:\.\d+)?)ms)?$")


def parse_duration(value: str | None) -> float | None:
    """Parse '2', '7.66s', '1m2.5s' or '250ms' into seconds."""
    if not value:
        return None
    value = value.strip()
    try:
        return float(value)
    except ValueError:
        pass
    m = _DURATION.match(value)
    if not m or not any(m.groups()):
        return None
    h, mi, s, ms = (float(x) if x else 0.0 for x in m.groups())
    return h * 3600 + mi * 60 + s + ms / 1000


_XML_FUNCTION = re.compile(r"<function=([A-Za-z0-9_]+)>(.*?)(?:</function>|$)", re.S)
_XML_PARAM = re.compile(r"<parameter=([A-Za-z0-9_]+)>\s*(.*?)\s*</parameter>", re.S)


def salvage_xml_tool_call(text: str | None, allowed: set[str]) -> tuple[str, dict[str, Any]] | None:
    """Recover `<function=NAME><parameter=K>V</parameter>...` tool calls (Qwen3 native format).

    Only registered tool names are accepted. Parameter values are JSON-decoded when possible, otherwise
    kept as strings. Returns None when nothing usable is found (incl. truncated output).
    """
    if not text:
        return None
    m = _XML_FUNCTION.search(text)
    if not m or m.group(1) not in allowed:
        return None
    args: dict[str, Any] = {}
    for pm in _XML_PARAM.finditer(m.group(2)):
        raw = pm.group(2)
        try:
            args[pm.group(1)] = json.loads(raw)
        except json.JSONDecodeError:
            args[pm.group(1)] = raw
    return (m.group(1), args) if args or "<parameter=" not in m.group(2) else None


def compact_schema(schema: Any, defs: dict[str, Any] | None = None) -> Any:
    """Model-friendly schema: inline `$ref`s to `$defs` and drop 'title' noise.

    Models follow nested `$ref`s poorly (observed: claim objects with invented field names), and some
    providers validate tool arguments server-side, so the expected shape must be explicit.
    """
    if isinstance(schema, dict):
        if defs is None:
            defs = schema.get("$defs", {})
        ref = schema.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/$defs/") and ref[8:] in defs:
            return compact_schema(defs[ref[8:]], defs)
        return {k: compact_schema(v, defs) for k, v in schema.items() if k not in ("title", "$defs")}
    if isinstance(schema, list):
        return [compact_schema(v, defs) for v in schema]
    return schema


def _retry_after(exc: Exception) -> float | None:
    """Server-provided wait: Retry-After, or the time until the token-per-minute window resets (Groq)."""
    response = getattr(exc, "response", None)
    headers = getattr(response, "headers", None)
    if not headers:
        return None
    # Retry-After is the minimal wait the server asks for. x-ratelimit-reset-tokens is the time until the
    # token bucket is *completely* refilled (much longer), so it is only a fallback.
    retry_after = parse_duration(headers.get("retry-after"))
    if retry_after is not None:
        return retry_after
    return parse_duration(headers.get("x-ratelimit-reset-tokens"))


def _decision(call_id: str, name: str, raw_args: str | None, usage: Usage) -> AgentDecision:
    try:
        args = json.loads(raw_args or "{}")
    except json.JSONDecodeError as exc:
        raise LLMError(
            "Model produced malformed tool arguments (invalid JSON).", retryable=False, details={"malformed": True}
        ) from exc
    if not isinstance(args, dict):
        raise LLMError("Model produced non-object tool arguments.", retryable=False, details={"malformed": True})
    if name == FINISH_TOOL_NAME:
        try:
            finish = FinishPayload.lenient(args)
        except Exception as exc:
            raise LLMError(
                "Model produced an invalid finish payload.", retryable=False, details={"malformed": True}
            ) from exc
        return AgentDecision(kind="finish", call_id=call_id, finish=finish, usage=usage)
    rationale = args.pop("rationale", None) if isinstance(args.get("rationale"), str) else None
    return AgentDecision(
        kind="tool_call", call_id=call_id, tool_name=name, arguments=args, rationale=rationale, usage=usage
    )
