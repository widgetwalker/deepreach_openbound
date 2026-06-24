"""Base protocol for lockfile parsers."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class EcosystemAdapter(Protocol):
    """Protocol for lockfile ecosystem adapters."""

    def parse(
        self, content: str
    ) -> list[tuple[str, str, str, str | None, list[str]]]:
        """Parse lockfile content and return dependency tuples."""
        ...

    def detect(self, content: str) -> bool:
        """Detect if this adapter can parse the given lockfile content."""
        ...
