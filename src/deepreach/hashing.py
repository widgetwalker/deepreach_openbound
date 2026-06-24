"""Deterministic hashing for scan IDs and report fingerprints."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def stable_hash(data: Any) -> str:
    """Produce a SHA-256 hex digest that is deterministic across runs."""
    normalised = _normalise(data)
    json_str = json.dumps(normalised, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(json_str.encode("utf-8")).hexdigest()


def _normalise(data: Any) -> Any:
    if isinstance(data, dict):
        return {k: _normalise(v) for k, v in sorted(data.items())}
    if isinstance(data, list):
        return [_normalise(item) for item in data]
    if isinstance(data, (str, int, float, bool)) or data is None:
        return data
    return str(data)
