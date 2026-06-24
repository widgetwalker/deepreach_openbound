"""GitHub Security Advisories adapter for vulnerability federation."""

from __future__ import annotations

from datetime import timedelta

from ..models import Advisory
from .base import SourceAdapter
from ..log import get_logger

logger = get_logger(__name__)

_ECOSYSTEM_MAP: dict[str, str] = {
    "npm": "npm",
    "pip": "pip",
}


class GHSAAdapter(SourceAdapter):
    """Adapter for GitHub Security Advisories (GHSA)."""

    def __init__(self) -> None:
        self.base_url = "https://api.github.com/advisories"
        self.cache_timeout = timedelta(hours=6)
        self.headers = {
            "User-Agent": "DeepReach/0.1.0 (+https://github.com/widgetwalker/deepreach_openbound)"
        }

    def get_name(self) -> str:
        return "GHSA"

    def fetch_advisories(
        self, ecosystem: str, package: str, version: str
    ) -> list[Advisory]:
        """Fetch advisories for a specific package version from GHSA."""
        try:
            ghsa_ecosystem = _ECOSYSTEM_MAP.get(ecosystem)
            if not ghsa_ecosystem:
                logger.warning(f"Unsupported ecosystem for GHSA: {ecosystem}")
                return []

            # GraphQL endpoint required for package-level filtering
            logger.warning(
                "GHSA adapter fetch_advisories not fully implemented - "
                "returning empty list"
            )
            return []

        except Exception as e:
            logger.error(f"Error fetching from GHSA: {e}")
            return []

    def update_cache(self) -> bool:
        """Update GHSA cache."""
        logger.info("GHSA adapter update_cache called")
        return True
