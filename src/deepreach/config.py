"""XDG-compliant cache path configuration."""

from __future__ import annotations

import os
from pathlib import Path


def get_cache_dir() -> Path:
    """Return (and lazily create) the DeepReach cache directory."""
    xdg = os.getenv("XDG_CACHE_HOME")
    cache_dir = Path(xdg) / "deepreach" if xdg else Path.home() / ".cache" / "deepreach"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def get_vulns_db_path() -> Path:
    """Path to the SQLite advisory cache."""
    return get_cache_dir() / "vulns.db"


def get_config_value(key: str, default: str | None = None) -> str | None:
    """Read a DEEPREACH_* environment variable."""
    return os.getenv(f"DEEPREACH_{key.upper()}", default)
