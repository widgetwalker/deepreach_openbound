"""Data models for DeepReach."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class Advisory:
    """Normalized vulnerability advisory."""
    cve_id: str
    ecosystem: str  # npm or pypi
    package: str
    vulnerable_version_range: str
    vulnerable_functions: Optional[List[str]]
    fix_version: Optional[str]
    severity: str  # critical, high, medium, low


@dataclass(frozen=True)
class ResolvedDep:
    """Resolved dependency with version."""
    ecosystem: str
    name: str
    version: str
    parent_name: Optional[str]
    dep_path: List[str]


@dataclass(frozen=True)
class DefSite:
    """Function or method definition site."""
    file: str
    line: int
    name: str
    exported: bool


@dataclass(frozen=True)
class Edge:
    """Call expression edge in call graph."""
    caller: DefSite
    callee_ref: str  # ImportPath resolved to string for simplicity
    line: int


@dataclass(frozen=True)
class Finding:
    """Vulnerability finding with reachability info."""
    advisory: Advisory
    reachable: bool
    confidence: str  # high, medium, low
    call_path: List[DefSite]
    fix_version: Optional[str]


@dataclass(frozen=True)
class ScanResult:
    """Complete scan result."""
    meta: dict
    summary: dict
    findings: List[Finding]
