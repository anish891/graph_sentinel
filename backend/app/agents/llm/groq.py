"""Groq provider (OpenAI-compatible API at https://api.groq.com/openai/v1).

Uses Chat Completions with tool calling. Groq's free tier has small per-minute token limits and
rejects any single request above them (HTTP 413), so tool outputs sent back to the model are trimmed
to GROQ_TOOL_OUTPUT_MAX_CHARS. `parallel_tool_calls` is not sent (gpt-oss models do not support
parallel tool use); the orchestrator executes only the first tool call per turn anyway.
"""

from __future__ import annotations

from openai import AsyncOpenAI

from app.agents.llm.openai_compat import OpenAICompatibleProvider
from app.core.config import Settings
from app.core.errors import LLMConfigurationError


class GroqProvider(OpenAICompatibleProvider):
    name = "groq"
    label = "Groq"
    key_setting = "GROQ_API_KEY"
    send_parallel_flag = False

    def __init__(self, settings: Settings) -> None:
        if settings.groq_api_key is None:
            raise LLMConfigurationError("GROQ_API_KEY is not set.")
        client = AsyncOpenAI(
            base_url=settings.groq_base_url,
            api_key=settings.groq_api_key.get_secret_value(),
            timeout=settings.llm_timeout_seconds,
            max_retries=0,  # retries are handled by OpenAICompatibleProvider
        )
        chat_extra = (
            {"reasoning_effort": settings.groq_reasoning_effort}
            if settings.groq_model.startswith("openai/gpt-oss")
            else {}
        )
        super().__init__(
            settings,
            client=client,
            model=settings.groq_model,
            mode="chat",
            tool_output_max_chars=settings.groq_tool_output_max_chars,
            max_output_tokens=settings.groq_max_output_tokens,
            chat_extra=chat_extra,
        )

    async def list_models(self) -> list[str]:
        page = await self._client.models.list()
        return sorted(m.id for m in page.data)
