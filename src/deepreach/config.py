"""Configuration management for DeepReach."""

import os
from pathlib import Path
from typing import Optional


def get_cache_dir() -> Path:
    """Get DeepReach cache directory following XDG spec."""
    xdg_cache = os.getenv("XDG_CACHE_HOME")
    if xdg_cache:
        cache_dir = Path(xdg_cache) / "deepreach"
    else:
        cache_dir = Path.home() / ".cache" / "deepreach"
    
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def get_vulns_db_path() -> Path:
    """Get path to vulnerabilities SQLite database."""
    return get_cache_dir() / "vulns.db"


def get_config_value(key: str, default: Optional[str] = None) -> Optional[str]:
    """Get configuration value from environment."""
    return os.getenv(f"DEEPREACH_{key.upper()}", default)