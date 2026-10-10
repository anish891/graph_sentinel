"""AzureOpenAIProvider behaviour with a fake SDK client (no network, no credentials)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import openai
import pytest

from app.agents.llm.azure import AzureOpenAIProvider
from app.agents.llm.base import DecisionRequest, StepRecord
from app.core.config import Settings
from app.core.errors import LLMError


def _exc(cls: type[Exception], message: str = "x") -> Exception:
    e = cls.__new__(cls)
    Exception.__init__(e, message)
    e.message = message  # type: ignore[attr-defined]
    e.response = None  # type: ignore[attr-defined]
    e.status_code = 0  # type: ignore[attr-defined]
    return e


def settings(**kw: Any) -> Settings:
    base = {
        "azure_openai_api_key": "test-key-not-real",
        "azure_openai_endpoint": "https://example.openai.azure.com",
        "azure_openai_deployment": "gpt-test",
        "llm_max_retries": 2,
        "_env_file": None,
    }
    base.update(kw)
    return Settings(**base)


def request() -> DecisionRequest:
    return DecisionRequest(
        investigation_id="inv",
        question="Investigate ALT-1001",
        target_id="ALT-1001",
        tools=[],
        remaining_tool_calls=5,
        remaining_steps=5,
        history=[
            StepRecord(
                call_id="c1", tool="get_alert", arguments={"alert_id": "ALT-1001"}, status="ok", output={"found": True}
            )
        ],
    )


class FakeResponses:
    def __init__(self, outcomes: list[Any]) -> None:
        self.outcomes = outcomes
        self.calls: list[dict[str, Any]] = []

    async def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        out = self.outcomes.pop(0)
        if isinstance(out, Exception):
            raise out
        return out


def resp_function_call(name: str, args: str) -> Any:
    return SimpleNamespace(
        usage=SimpleNamespace(input_tokens=100, output_tokens=20),
        output=[
            SimpleNamespace(type="reasoning"),
            SimpleNamespace(type="function_call", call_id="call_1", name=name, arguments=args),
        ],
    )


def chat_tool_call(name: str, args: str) -> Any:
    fn = SimpleNamespace(name=name, arguments=args)
    msg = SimpleNamespace(tool_calls=[SimpleNamespace(id="tc1", function=fn)])
    return SimpleNamespace(
        usage=SimpleNamespace(prompt_tokens=50, completion_tokens=10), choices=[SimpleNamespace(message=msg)]
    )


def make(outcomes_resp: list[Any], outcomes_chat: list[Any] | None = None, **kw: Any) -> tuple[Any, Any, Any]:
    p = AzureOpenAIProvider(settings(**kw))
    r, c = FakeResponses(outcomes_resp), FakeResponses(outcomes_chat or [])
    p._client = SimpleNamespace(responses=r, chat=SimpleNamespace(completions=c), close=None)  # type: ignore[assignment]
    return p, r, c


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fast(_: float) -> None:
        return None

    monkeypatch.setattr("app.agents.llm.openai_compat.asyncio.sleep", fast)


async def test_responses_tool_call_parsed() -> None:
    p, r, _ = make([resp_function_call("find_attack_paths", '{"source_id": "ALT-1001"}')])
    d = await p.decide(request())
    assert d.kind == "tool_call" and d.tool_name == "find_attack_paths" and d.arguments == {"source_id": "ALT-1001"}
    assert d.usage.input_tokens == 100
    sent = r.calls[0]
    assert sent["model"] == "gpt-test" and sent["tool_choice"] == "required" and sent["store"] is False
    assert any(t["name"] == "finish_investigation" for t in sent["tools"])
    assert sent["input"][1]["type"] == "function_call" and sent["input"][2]["type"] == "function_call_output"


async def test_finish_payload_validated() -> None:
    args = (
        '{"summary": "A concise summary.", "claims": [{"statement": "x links y", "kind": "inference", "refs": ["p"]}]}'
    )
    p, _, _ = make([resp_function_call("finish_investigation", args)])
    d = await p.decide(request())
    assert d.kind == "finish" and d.finish is not None and d.finish.claims[0].refs == ["p"]


async def test_malformed_json_is_reported_not_retried() -> None:
    p, r, _ = make([resp_function_call("get_alert", "{not json")])
    with pytest.raises(LLMError) as ei:
        await p.decide(request())
    assert ei.value.details.get("malformed") and len(r.calls) == 1


async def test_retries_transient_then_succeeds() -> None:
    p, r, _ = make(
        [
            _exc(openai.RateLimitError),
            _exc(openai.APITimeoutError),
            resp_function_call("get_alert", '{"alert_id": "ALT-1001"}'),
        ]
    )
    d = await p.decide(request())
    assert d.tool_name == "get_alert" and len(r.calls) == 3


async def test_retries_are_bounded() -> None:
    p, r, _ = make([_exc(openai.InternalServerError)] * 5)
    with pytest.raises(LLMError) as ei:
        await p.decide(request())
    assert ei.value.retryable and len(r.calls) == 3  # 1 + llm_max_retries(2)


async def test_auth_errors_never_retried() -> None:
    p, r, _ = make([_exc(openai.AuthenticationError)])
    with pytest.raises(LLMError) as ei:
        await p.decide(request())
    assert not ei.value.retryable and len(r.calls) == 1
    assert "test-key-not-real" not in str(ei.value)


async def test_auto_mode_falls_back_to_chat_completions() -> None:
    p, _r, c = make([_exc(openai.NotFoundError)], [chat_tool_call("get_alert", '{"alert_id": "ALT-1001"}')])
    d = await p.decide(request())
    assert d.tool_name == "get_alert" and p.api == "chat" and len(c.calls) == 1
    msgs = c.calls[0]["messages"]
    assert msgs[0]["role"] == "system" and msgs[2]["tool_calls"][0]["id"] == "c1" and msgs[3]["role"] == "tool"


async def test_explicit_responses_mode_does_not_fall_back() -> None:
    p, _, c = make([_exc(openai.NotFoundError)], [], azure_openai_api_mode="responses")
    with pytest.raises(LLMError):
        await p.decide(request())
    assert c.calls == []


def test_requires_full_configuration() -> None:
    with pytest.raises(LLMError):
        AzureOpenAIProvider(
            Settings(_env_file=None, azure_openai_api_key="k", azure_openai_endpoint=None, azure_openai_deployment="d")
        )


def test_dated_api_version_uses_azure_client() -> None:
    p = AzureOpenAIProvider(settings(azure_openai_api_version="2025-04-01-preview"))
    assert isinstance(p._client, openai.AsyncAzureOpenAI)
    p2 = AzureOpenAIProvider(settings())
    assert "/openai/v1/" in str(p2._client.base_url)
