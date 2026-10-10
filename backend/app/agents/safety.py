"""Untrusted-content handling.

Graph properties, evidence text and imported documents are DATA. They are never executed,
never change the tool registry, and never alter policy. This module:

* flags text that looks like an instruction aimed at an AI agent (prompt injection), so such
  evidence is excluded from scoring and highlighted for an analyst;
* wraps untrusted text before it is shown to the model;
* sanitises control characters and bounds sizes.
"""

from __future__ import annotations

import re
import unicodedata

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ignore_instructions", re.compile(r"\b(ignore|disregard|forget)\b.{0,40}\b(instruction|polic|rule|prompt)", re.I)),
    (
        "addresses_ai",
        re.compile(r"\b(note|message|instruction)s?\s+(to|for)\s+(the\s+)?(ai|assistant|agent|llm|model)\b", re.I),
    ),
    ("role_override", re.compile(r"\byou are (now|no longer)\b|\bact as\b|\bnew instructions?\b", re.I)),
    (
        "secret_exfiltration",
        re.compile(
            r"\b(system prompt|api[\s_-]?key|password|secret|credential)s?\b.{0,30}\b(print|reveal|show|send|output)"
            r"|\b(print|reveal|show|send|output)\b.{0,40}\b(system prompt|api[\s_-]?key|secret)",
            re.I,
        ),
    ),
    (
        "action_coercion",
        re.compile(
            r"\b(approve|execute|close|disable|delete)\b.{0,20}\ball\b.{0,30}\b(action|alert|investigation|account)",
            re.I,
        ),
    ),
    (
        "verdict_coercion",
        re.compile(
            r"\b(mark|classify|treat)\b.{0,30}\b(as\s+)?(benign|false positive|safe)\b|\bthis alert is (benign|safe)\b",
            re.I,
        ),
    ),
    ("chat_markup", re.compile(r"<\|im_(start|end)\|>|\[/?INST\]|</?system>|BEGIN SYSTEM", re.I)),
]

# C0 controls (except tab/newline/CR), DEL, zero-width and bidirectional override characters.
_CONTROL = re.compile("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\u200b-\\u200f\\u202a-\\u202e\\u2066-\\u2069]")


def sanitize_text(text: str | None, max_len: int = 2000) -> str:
    if not text:
        return ""
    text = unicodedata.normalize("NFKC", str(text))
    text = _CONTROL.sub("", text)
    return text[:max_len]


def injection_signals(text: str | None) -> list[str]:
    if not text:
        return []
    clean = sanitize_text(text, 10000)
    return [name for name, pattern in _INJECTION_PATTERNS if pattern.search(clean)]


def wrap_untrusted(text: str | None, max_len: int = 600) -> str:
    """Delimit untrusted text so the model can see where data starts and ends."""
    return f"<untrusted_data>{sanitize_text(text, max_len)}</untrusted_data>"
