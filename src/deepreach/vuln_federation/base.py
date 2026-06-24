"""Base protocol for vulnerability federation adapters."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..models import Advisory


@runtime_checkable
class SourceAdapter(Protocol):
    """Protocol that all vulnerability source adapters must satisfy."""

    def fetch_advisories(
        self, ecosystem: str, package: str, version: str
    ) -> list[Advisory]: ...

    def update_cache(self) -> bool: ...

    def get_name(self) -> str: ...
