"""Base protocol for vulnerability federation adapters."""

from __future__ import annotations

from typing import Protocol, List, runtime_checkable

from ..models import Advisory


@runtime_checkable
class SourceAdapter(Protocol):
    """Protocol for vulnerability source adapters."""

    def fetch_advisories(
        self, ecosystem: str, package: str, version: str
    ) -> List[Advisory]:  # noqa: E501
        """
        Fetch advisories for a specific package version.

        Returns:
            List of Advisory objects
        """
        ...

    def update_cache(self) -> bool:
        """
        Update the local cache with latest advisories from the source.

        Returns:
            True if update was successful, False otherwise
        """
        ...

    def get_name(self) -> str:
        """Get the name of this adapter (e.g., 'OSV', 'GHSA')."""
        ...
