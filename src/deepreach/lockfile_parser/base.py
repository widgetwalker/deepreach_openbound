"""Base protocol for lockfile parsers."""

from __future__ import annotations

from typing import Protocol, List, Tuple, runtime_checkable, Optional


@runtime_checkable
class EcosystemAdapter(Protocol):
    """Protocol for lockfile ecosystem adapters."""

    def parse(self, content: str) -> List[Tuple[str, str, str, Optional[str], List[str]]]:  # noqa: E501
        """
        Parse lockfile content and return dependency tuples.

        Returns:
            List of (ecosystem, name, version, parent_name, dep_path) tuples
        """
        ...

    def detect(self, content: str) -> bool:
        """
        Detect if this adapter can parse the given lockfile content.

        Returns:
            True if adapter can parse the content, False otherwise
        """
        ...
