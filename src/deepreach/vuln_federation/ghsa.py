"""GitHub Security Advisories adapter for vulnerability federation."""

from typing import List
from datetime import timedelta


from ..models import Advisory
from .base import SourceAdapter
from ..log import get_logger


logger = get_logger(__name__)


class GHSAAdapter(SourceAdapter):
    """Adapter for GitHub Security Advisories (GHSA)."""

    def __init__(self):
        self.base_url = "https://api.github.com/advisories"
        self.cache_timeout = timedelta(hours=6)  # Cache for 6 hours
        # GitHub API requires a User-Agent header
        self.headers = {
            "User-Agent": "DeepReach/0.1.0 (+https://github.com/widgetwalker/deepreach_openbound)"
        }

    def get_name(self) -> str:
        return "GHSA"

    def fetch_advisories(self, ecosystem: str, package: str, version: str) -> List[Advisory]:  # noqa: E501
        """Fetch advisories for a specific package version from GHSA."""
        try:
            # Map our ecosystem names to GHSA format
            ghsa_ecosystem = {
                "npm": "npm",
                "pip": "pip"
            }.get(ecosystem)

            if not ghsa_ecosystem:
                logger.warning(f"Unsupported ecosystem for GHSA: {ecosystem}")
                return []

            # Query GHSA for advisories affecting this package
            # Note: GHSA API doesn't have a direct package/version
            # endpoint for filtering. We need to fetch recent
            # advisories and filter locally (not ideal but works for demo).
            # In production, we'd want to use the GraphQL endpoint
            # or maintain a local cache.

            # GitHub API doesn't support filtering by package in REST API easily
            # We would need to use GraphQL or fetch and filter
            # For this implementation, we'll note this limitation and return empty
            # A full implementation would use GraphQL or maintain periodic sync

            logger.warning("GHSA adapter fetch_advisories not fully implemented - returning empty list")  # noqa: E501
            return []

        except Exception as e:
            logger.error(f"Error fetching from GHSA: {e}")
            return []

    def update_cache(self) -> bool:
        """Update GHSA cache."""
        logger.info("GHSA adapter update_cache called")
        return True
