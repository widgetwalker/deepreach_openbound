"""Exception hierarchy for DeepReach."""


class DepReachError(Exception):
    """Base exception for DeepReach."""


class LockfileParseError(DepReachError):
    """Raised when lockfile cannot be parsed."""

    def __init__(self, message: str, suggestion: str = ""):
        super().__init__(f"{message}. {suggestion}".strip())
        self.suggestion = suggestion


class OSVFetchError(DepReachError):
    """Raised when OSV.dev advisory fetch fails."""


class GHSAFetchError(DepReachError):
    """Raised when GitHub Security Advisory fetch fails."""


class NVDFetchError(DepReachError):
    """Raised when NVD advisory fetch fails."""


class AdvisoryFetchError(DepReachError):
    """Raised when advisory federation fails."""


class ResolverError(DepReachError):
    """Raised when dependency resolution fails."""


class CallGraphError(DepReachError):
    """Raised when call graph construction fails."""


class ReportError(DepReachError):
    """Raised when report generation fails."""
