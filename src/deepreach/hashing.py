"""Deterministic hashing for DeepReach."""

import hashlib
import json
from typing import Any


def stable_hash(data: Any) -> str:
    """Generate stable hash from data structure."""
    if isinstance(data, dict):
        # Sort keys for deterministic ordering
        data = {k: stable_hash(v) for k, v in sorted(data.items())}
    elif isinstance(data, list):
        # Preserve list order but hash elements stably
        data = [stable_hash(item) for item in data]
    elif isinstance(data, (str, int, float, bool)) or data is None:
        # Primitives are hashable as-is
        pass
    else:
        # For other types, convert to string
        data = str(data)

    # JSON serialize with sorted keys and no whitespace
    json_str = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(json_str.encode("utf-8")).hexdigest()
