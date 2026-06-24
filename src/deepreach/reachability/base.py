"""Base protocol for language-specific reachability analyzers."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..models import DefSite, Edge


@runtime_checkable
class LanguageAdapter(Protocol):
    """Protocol for language-specific reachability adapters."""

    def parse_file(
        self, file_path: str, content: str
    ) -> tuple[list[DefSite], list[Edge]]:
        """Parse a source file and extract definitions and edges."""
        ...

    def get_file_extensions(self) -> list[str]:
        """Return file extensions this adapter handles."""
        ...

    def is_ignored_path(self, file_path: str) -> bool:
        """Check if a file path should be ignored during analysis."""
        ...
