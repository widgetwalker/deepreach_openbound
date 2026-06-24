"""NVD adapter for vulnerability federation (feature-flagged)."""

from __future__ import annotations

from ..models import Advisory
from .base import SourceAdapter
from ..log import get_logger

logger = get_logger(__name__)


class NVDAdapter(SourceAdapter):
    """Adapter for the National Vulnerability Database."""

    def get_name(self) -> str:
        return "NVD"

    def fetch_advisories(
        self, ecosystem: str, package: str, version: str
    ) -> list[Advisory]:
        """Fetch advisories from NVD (feature-flagged, not active in v1)."""
        logger.info("NVD adapter is feature-flagged and not implemented in v1")
        return []

    def update_cache(self) -> bool:
        """Update NVD cache."""
        logger.info("NVD adapter update_cache called (not implemented)")
        return True
