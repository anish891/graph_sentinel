from __future__ import annotations

from app.agents.llm.base import LLMProvider
from app.agents.llm.mock import MockLLMProvider
from app.core.config import Settings
from app.core.errors import LLMConfigurationError


def build_provider(settings: Settings) -> LLMProvider:
    choice = settings.effective_llm_provider
    if choice == "azure":
        from app.agents.llm.azure import AzureOpenAIProvider

        return AzureOpenAIProvider(settings)
    if choice == "groq":
        from app.agents.llm.groq import GroqProvider

        return GroqProvider(settings)
    if choice == "mock":
        return MockLLMProvider()
    raise LLMConfigurationError(
        "No LLM provider available: set GROQ_API_KEY, or AZURE_OPENAI_API_KEY + AZURE_OPENAI_ENDPOINT + "
        "AZURE_OPENAI_DEPLOYMENT, or enable DEMO_MODE to use the deterministic mock planner."
    )
