"""Domain models shared across every DeepReach module."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Maps directly to CVSS qualitative buckets used by OSV, GHSA, and NVD."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class Confidence(str, Enum):
    """Reflects how precisely the reachability analysis could trace the call path."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class Advisory:
    """Normalised vulnerability advisory from any federated source."""

    cve_id: str
    ecosystem: str
    package: str
    vulnerable_version_range: str
    vulnerable_functions: list[str] | None
    fix_version: str | None
    severity: Severity
    summary: str | None = None
    details: str | None = None


@dataclass(frozen=True)
class ResolvedDep:
    """A concrete dependency pinned to a specific version."""

    ecosystem: str
    name: str
    version: str
    parent_name: str | None
    dep_path: list[str]


@dataclass(frozen=True)
class DefSite:
    """A function or class definition location in source code."""

    file: str
    line: int
    name: str
    exported: bool


@dataclass(frozen=True)
class Edge:
    """A call expression linking a caller to a callee reference."""

    caller: DefSite
    callee_ref: str
    line: int


@dataclass(frozen=True)
class Finding:
    """A single vulnerability verdict with reachability evidence."""

    advisory: Advisory
    reachable: bool
    confidence: Confidence
    call_path: list[DefSite]
    fix_version: str | None


@dataclass(frozen=True)
class ScanMetrics:
    """Resource usage captured during a scan."""

    duration_ms: float = 0.0
    peak_rss_bytes: int = 0


@dataclass(frozen=True)
class ScanResult:
    """Complete output of a scan run."""

    meta: dict[str, object]
    summary: dict[str, object]
    findings: list[Finding]
    metrics: ScanMetrics = field(default_factory=ScanMetrics)
