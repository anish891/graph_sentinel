"""Azure OpenAI provider.

* AZURE_OPENAI_API_VERSION=v1 (default) → GA `/openai/v1/` surface via `AsyncOpenAI(base_url=...)`.
  Any dated version (e.g. 2025-04-01-preview) → `AsyncAzureOpenAI(api_version=...)`.
* AZURE_OPENAI_API_MODE=auto → Responses API first, falling back to Chat Completions.
Azure is used only as the LLM endpoint; nothing else in the app depends on Azure.
"""

from __future__ import annotations

from typing import Any

from openai import AsyncAzureOpenAI, AsyncOpenAI

from app.agents.llm.openai_compat import OpenAICompatibleProvider
from app.core.config import Settings
from app.core.errors import LLMConfigurationError


class AzureOpenAIProvider(OpenAICompatibleProvider):
    name = "azure-openai"
    label = "Azure OpenAI"
    key_setting = "AZURE_OPENAI_API_KEY / endpoint access"

    def __init__(self, settings: Settings) -> None:
        if not settings.azure_configured:
            raise LLMConfigurationError("Azure OpenAI is not fully configured (key, endpoint, deployment).")
        assert settings.azure_openai_api_key and settings.azure_openai_endpoint and settings.azure_openai_deployment
        endpoint = settings.azure_openai_endpoint.rstrip("/")
        common: dict[str, Any] = {
            "api_key": settings.azure_openai_api_key.get_secret_value(),
            "timeout": settings.llm_timeout_seconds,
            "max_retries": 0,  # retries are handled by OpenAICompatibleProvider
        }
        client: AsyncOpenAI
        if settings.azure_openai_api_version.lower() == "v1":
            client = AsyncOpenAI(base_url=f"{endpoint}/openai/v1/", **common)
        else:
            client = AsyncAzureOpenAI(azure_endpoint=endpoint, api_version=settings.azure_openai_api_version, **common)
        super().__init__(
            settings, client=client, model=settings.azure_openai_deployment, mode=settings.azure_openai_api_mode
        )
