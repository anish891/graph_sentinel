"""GroqProvider with a fake SDK client (no network, no real key)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import openai
import pytest

from app.agents.llm.base import DecisionRequest, StepRecord
from app.agents.llm.factory import build_provider
from app.agents.llm.groq import GroqProvider
from app.core.config import Settings
from app.core.errors import LLMError


def _exc(cls: type[Exception], status: int = 0) -> Exception:
    e = cls.__new__(cls)
    Exception.__init__(e, "x")
    e.message = "x"  # type: ignore[attr-defined]
    e.response = None  # type: ignore[attr-defined]
    e.status_code = status  # type: ignore[attr-defined]
    return e


def settings(**kw: Any) -> Settings:
    base: dict[str, Any] = {
        "groq_api_key": "gsk_test_not_real",
        "_env_file": None,
        "llm_max_retries": 1,
        "azure_openai_api_key": None,
        "azure_openai_endpoint": None,
        "azure_openai_deployment": None,
    }
    base.update(kw)
    return Settings(**base)


class FakeCompletions:
    def __init__(self, outcomes: list[Any]) -> None:
        self.outcomes, self.calls = outcomes, []

    async def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        out = self.outcomes.pop(0)
        if isinstance(out, Exception):
            raise out
        return out


def tool_call(name: str, args: str) -> Any:
    fn = SimpleNamespace(name=name, arguments=args)
    msg = SimpleNamespace(tool_calls=[SimpleNamespace(id="c1", function=fn)])
    return SimpleNamespace(
        usage=SimpleNamespace(prompt_tokens=40, completion_tokens=8), choices=[SimpleNamespace(message=msg)]
    )


def make(outcomes: list[Any], **kw: Any) -> tuple[GroqProvider, FakeCompletions]:
    p = GroqProvider(settings(**kw))
    c = FakeCompletions(outcomes)
    p._client = SimpleNamespace(chat=SimpleNamespace(completions=c), close=None)  # type: ignore[assignment]
    return p, c


def request() -> DecisionRequest:
    big = {"found": True, "blob": "x" * 5000}
    return DecisionRequest(
        investigation_id="i",
        question="Investigate ALT-1001",
        target_id="ALT-1001",
        tools=[],
        remaining_tool_calls=5,
        remaining_steps=5,
        history=[
            StepRecord(call_id="h1", tool="get_alert", arguments={"alert_id": "ALT-1001"}, status="ok", output=big)
        ],
    )


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fast(_: float) -> None:
        return None

    monkeypatch.setattr("app.agents.llm.openai_compat.asyncio.sleep", fast)


def test_selected_automatically_when_only_groq_key_set() -> None:
    s = settings()
    assert s.effective_llm_provider == "groq"
    assert isinstance(build_provider(s), GroqProvider)
    assert "/openai/v1" in str(build_provider(s)._client.base_url)


def test_azure_preferred_when_fully_configured() -> None:
    s = settings(
        azure_openai_api_key="k",
        azure_openai_endpoint="https://x.cognitiveservices.azure.com",
        azure_openai_deployment="d",
    )
    assert s.effective_llm_provider == "azure"
    assert (
        settings(
            llm_provider="groq",
            azure_openai_api_key="k",
            azure_openai_endpoint="https://x",
            azure_openai_deployment="d",
        ).effective_llm_provider
        == "groq"
    )


async def test_chat_tool_call_and_request_shape() -> None:
    p, c = make([tool_call("get_alert", '{"alert_id": "ALT-1001"}')])
    d = await p.decide(request())
    assert p.api == "chat" and d.tool_name == "get_alert" and d.usage.input_tokens == 40
    sent = c.calls[0]
    assert sent["model"] == "qwen/qwen3.8-27b" and sent["tool_choice"] == "required"
    assert "parallel_tool_calls" not in sent  # gpt-oss models do not support parallel tool use
    tool_msg = sent["messages"][3]
    assert tool_msg["role"] == "tool" and len(tool_msg["content"]) <= 1500 + 20  # trimmed for free tier


async def test_rate_limit_retried_then_auth_error_not() -> None:
    p, c = make([_exc(openai.RateLimitError), tool_call("get_alert", "{}")])
    assert (await p.decide(request())).tool_name == "get_alert" and len(c.calls) == 2
    p2, c2 = make([_exc(openai.AuthenticationError)])
    with pytest.raises(LLMError) as ei:
        await p2.decide(request())
    assert "GROQ_API_KEY" in ei.value.message and len(c2.calls) == 1
    assert "gsk_test_not_real" not in ei.value.message


async def test_request_too_large_explained() -> None:
    p, _ = make([_exc(openai.APIStatusError, status=413)])
    with pytest.raises(LLMError) as ei:
        await p.decide(request())
    assert "413" in ei.value.message and "token limit" in ei.value.message


def test_parse_duration_formats() -> None:
    from app.agents.llm.openai_compat import parse_duration

    assert parse_duration("2") == 2
    assert parse_duration("7.66s") == pytest.approx(7.66)
    assert parse_duration("1m2.5s") == pytest.approx(62.5)
    assert parse_duration("250ms") == pytest.approx(0.25)
    assert parse_duration("bogus") is None


async def test_rate_limits_have_their_own_larger_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    waits: list[float] = []

    async def record(d: float) -> None:
        waits.append(d)

    monkeypatch.setattr("app.agents.llm.openai_compat.asyncio.sleep", record)
    rl = _exc(openai.RateLimitError)
    rl.response = SimpleNamespace(headers={"x-ratelimit-reset-tokens": "12.5s"})  # type: ignore[attr-defined]
    # (only the reset header present → it is used as the wait)
    # llm_max_retries=1 for transient errors, but 5 rate limits in a row still succeed.
    p, c = make([rl, rl, rl, rl, rl, tool_call("get_alert", "{}")])
    assert (await p.decide(request())).tool_name == "get_alert" and len(c.calls) == 6
    assert all(w >= 12.5 for w in waits)


async def test_rate_limit_budget_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    p, c = make([_exc(openai.RateLimitError)] * 20, llm_rate_limit_max_retries=3)
    with pytest.raises(LLMError) as ei:
        await p.decide(request())
    assert len(c.calls) == 4 and "rate limit" in ei.value.message


def test_tool_schemas_are_compacted() -> None:
    from app.agents.llm.openai_compat import compact_schema

    out = compact_schema({"title": "X", "properties": {"a": {"title": "A", "type": "string"}}})
    assert out == {"properties": {"a": {"type": "string"}}}
    from app.agents.llm.base import finish_tool_spec

    finish = compact_schema(finish_tool_spec().parameters)
    assert "$defs" not in str(finish) and "$ref" not in str(finish)
    assert set(finish["properties"]["claims"]["items"]["properties"]) == {"statement", "kind", "refs"}


async def test_groq_request_budget_and_reasoning_effort() -> None:
    p, c = make([tool_call("get_alert", "{}")], groq_model="openai/gpt-oss-120b")
    await p.decide(request())
    sent = c.calls[0]
    assert sent["max_completion_tokens"] == 1000 and sent["reasoning_effort"] == "low"
    p2, c2 = make([tool_call("get_alert", "{}")])
    await p2.decide(request())
    assert "reasoning_effort" not in c2.calls[0]  # only sent to gpt-oss reasoning models


def test_retry_after_preferred_over_full_bucket_reset() -> None:
    from app.agents.llm.openai_compat import _retry_after

    e = _exc(openai.RateLimitError)
    e.response = SimpleNamespace(headers={"retry-after": "3", "x-ratelimit-reset-tokens": "52.1s"})  # type: ignore[attr-defined]
    assert _retry_after(e) == 3


async def test_tool_use_failed_is_malformed_not_fatal() -> None:
    bad = _exc(openai.BadRequestError, status=400)
    bad.body = {"code": "tool_use_failed", "message": "Failed to call a function"}  # type: ignore[attr-defined]
    p, _ = make([bad])
    with pytest.raises(LLMError) as ei:
        await p.decide(request())
    assert ei.value.details.get("malformed") is True


async def test_prose_answer_is_retried_with_auto_and_accepted_as_summary() -> None:
    no_call = _exc(openai.BadRequestError, status=400)
    no_call.body = {"code": "tool_use_failed"}  # type: ignore[attr-defined]
    no_call.message = "tool choice is required, but model did not call a tool"  # type: ignore[attr-defined]
    msg = SimpleNamespace(tool_calls=None, content="ALT-1001 looks malicious.")
    text = SimpleNamespace(
        usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5), choices=[SimpleNamespace(message=msg)]
    )
    p, c = make([no_call, text])
    d = await p.decide(request())
    assert d.kind == "finish" and d.finish is not None and d.finish.claims == []
    assert c.calls[1]["tool_choice"] == "auto"


def test_salvage_qwen_xml_tool_call() -> None:
    from app.agents.llm.openai_compat import salvage_xml_tool_call

    text = (
        "<tool_call>\n<function=finish_investigation>\n<parameter=claims>\n"
        '[{"kind": "observed_fact", "statement": "ALT-1001 is high severity", "refs": ["ALT-1001"]}]\n'
        "</parameter>\n<parameter=summary>\nLikely part of a larger attack.\n</parameter>\n</function>\n</tool_call>"
    )
    name, args = salvage_xml_tool_call(text, {"finish_investigation", "get_alert"})  # type: ignore[misc]
    assert name == "finish_investigation" and args["summary"] == "Likely part of a larger attack."
    assert args["claims"][0]["refs"] == ["ALT-1001"]
    assert salvage_xml_tool_call(text, {"get_alert"}) is None  # unregistered tool names are never accepted
    assert (
        salvage_xml_tool_call("<function=finish_investigation>\n<parameter=claims>\n[{", {"finish_investigation"})
        is None
    )


async def test_failed_generation_is_salvaged_into_a_finish() -> None:
    bad = _exc(openai.BadRequestError, status=400)
    bad.body = {  # type: ignore[attr-defined]
        "code": "tool_use_failed",
        "failed_generation": "<function=finish_investigation>\n<parameter=summary>\nA concise summary here.\n"
        "</parameter>\n<parameter=claims>\n[]\n</parameter>\n</function>",
    }
    p, c = make([bad])
    d = await p.decide(request())
    assert d.kind == "finish" and d.finish is not None and d.finish.summary == "A concise summary here."
    assert len(c.calls) == 1
