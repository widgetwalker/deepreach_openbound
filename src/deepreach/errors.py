"""Exception hierarchy for DeepReach."""


class DepReachError(Exception):
    """Base exception for all DeepReach errors."""


class LockfileParseError(DepReachError):
    """Raised when a lockfile cannot be parsed."""

    def __init__(self, message: str, suggestion: str = ""):
        super().__init__(f"{message}. {suggestion}".strip())
        self.suggestion = suggestion


class OSVFetchError(DepReachError):
    """Raised when an OSV.dev advisory fetch fails."""


class GHSAFetchError(DepReachError):
    """Raised when a GitHub Security Advisory fetch fails."""


class NVDFetchError(DepReachError):
    """Raised when an NVD advisory fetch fails."""


class AdvisoryFetchError(DepReachError):
    """Raised when advisory federation fails across all sources."""


class ResolverError(DepReachError):
    """Raised when dependency resolution fails."""


class CallGraphError(DepReachError):
    """Raised when call graph construction fails."""


class ReportError(DepReachError):
    """Raised when report generation fails."""
