"""Unit tests must not depend on the developer's shell or CI environment.

CI sets e.g. LLM_PROVIDER=mock and a developer may have GROQ_API_KEY exported; Settings reads env vars
before defaults, so tests that build Settings would silently change behaviour. Clear them here.
"""

from __future__ import annotations

import os

import pytest

_PREFIXES = ("LLM_", "GROQ_", "AZURE_OPENAI_", "AGENT_", "DEMO_MODE", "APP_ENV", "AUTH_")


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.upper().startswith(_PREFIXES):
            monkeypatch.delenv(key, raising=False)
