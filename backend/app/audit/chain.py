"""Tamper-evident hash chaining for audit and trace events.

hash_n = SHA-256( prev_hash_n || canonical_json(record_n) )

Threat model (see docs/threat-model.md): detects modification, deletion or re-ordering of
individual records by anyone who cannot also rewrite every subsequent record. It does NOT stop
an attacker with full write access who recomputes the chain; anchoring the head hash in an
external system (ticket, WORM storage, transparency log) is required for that.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS_HASH = "0" * 64


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def chain_hash(prev_hash: str, record: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + canonical_json(record)).encode("utf-8")).hexdigest()


def content_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
