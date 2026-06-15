"""NVD adapter for vulnerability federation (feature-flagged)."""

from typing import List
from ..models import Advisory
from .base import SourceAdapter
from ..log import get_logger


logger = get_logger(__name__)


class NVDAdapter(SourceAdapter):
    """Adapter for NVD (National Vulnerability Database)."""

    def __init__(self):
        # In a full implementation, we would configure API key, etc.
        pass

    def get_name(self) -> str:
        return "NVD"

    def fetch_advisories(self, ecosystem: str, package: str, version: str) -> List[Advisory]:  # noqa: E501
        """Fetch advisories for a specific package version from NVD."""
        # NVD integration is feature-flagged and not implemented in v1
        # This is a placeholder for future implementation
        logger.info("NVD adapter is feature-flagged and not implemented in v1")
        return []

    def update_cache(self) -> bool:
        """Update NVD cache."""
        logger.info("NVD adapter update_cache called (not implemented)")
        return True
