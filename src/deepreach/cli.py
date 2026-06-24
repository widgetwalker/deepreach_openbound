"""Command-line interface for DeepReach."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from typing import TYPE_CHECKING
from collections.abc import Callable

from . import __version__
from .log import get_logger
from .models import (
    Advisory,
    Confidence,
    Edge,
    Finding,
    ScanResult,
)
from .timing import Timer

if TYPE_CHECKING:
    from .lockfile_parser.base import EcosystemAdapter
    from .vuln_federation.base import SourceAdapter
    from .vuln_federation.store import VulnerabilityStore
    from .reachability.base import LanguageAdapter

# Windows consoles default to cp1252 which chokes on UTF-8 output
if (
    sys.stdout
    and sys.stdout.encoding
    and sys.stdout.encoding.lower() != "utf-8"
    and hasattr(sys.stdout, "reconfigure")
):
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]

logger = get_logger(__name__)

_IGNORED_DIRS = frozenset(
    [".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"]
)

_SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def create_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="deepreach",
        description="Reachable CVE Scanner for Node and Python projects",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    init_parser = subparsers.add_parser(
        "init", help="Download and index vulnerability advisories"
    )
    init_parser.add_argument(
        "--offline", action="store_true", help="Skip network and use cached data only"
    )
    init_parser.add_argument(
        "--ecosystem",
        choices=["npm", "pip"],
        help="Limit to specific ecosystem (default: both)",
    )

    scan_parser = subparsers.add_parser(
        "scan", help="Scan repository for reachable CVEs"
    )
    scan_parser.add_argument("path", help="Path to repository to scan")
    scan_parser.add_argument(
        "--entry",
        action="append",
        metavar="FILE[:LINE]",
        help="Entry point for reachability analysis (repeatable)",
    )
    scan_parser.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default="table",
        help="Output format (default: table)",
    )
    scan_parser.add_argument(
        "--all", action="store_true", help="Show unreachable advisories"
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        help="Fail scan if CVE at or above this severity is reachable",
    )
    scan_parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output"
    )
    scan_parser.add_argument(
        "--debug", action="store_true", help="Enable debug logging and stack traces"
    )
    scan_parser.add_argument(
        "--enable-nvd",
        action="store_true",
        help="Enable NVD advisory feed (off by default)",
    )
    scan_parser.add_argument(
        "--partial-ok",
        action="store_true",
        help="Continue if some advisory sources fail",
    )

    explain_parser = subparsers.add_parser(
        "explain", help="Show call path for a specific CVE"
    )
    explain_parser.add_argument("path", help="Path to repository")
    explain_parser.add_argument(
        "cve_id", help="CVE ID to explain (e.g., CVE-2024-1234)"
    )

    subparsers.add_parser("self-test", help="Run internal self-test suite")
    subparsers.add_parser("license", help="Show license and third-party notices")

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point."""
    if argv is None:
        argv = sys.argv[1:]

    parser = create_parser()
    args = parser.parse_args(argv)

    if getattr(args, "debug", False):
        logger.setLevel(logging.DEBUG)

    handlers: dict[str, Callable[[argparse.Namespace], int]] = {
        "init": _init_command,
        "scan": _scan_command,
        "explain": _explain_command,
        "self-test": _self_test_command,
        "license": _license_command,
    }

    handler = handlers.get(args.command)  # type: ignore[arg-type]
    if handler:
        return handler(args)

    parser.print_help()
    return 1


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def _init_command(args: argparse.Namespace) -> int:
    """Initialise the local advisory cache."""
    logger.info("Initializing DeepReach vulnerability cache...")
    from .vuln_federation.store import VulnerabilityStore
    from .vuln_federation.osv import OSVAdapter

    try:
        store = VulnerabilityStore()
        osv = OSVAdapter()
        logger.info(f"Connected to Vulnerability Store at {store.db_path}")
        logger.info(f"Initialized {osv.get_name()} adapter")
        logger.info("Initialization complete. DeepReach is ready to scan.")
        return 0
    except Exception as e:
        logger.error(f"Initialization failed: {e}")
        return 1


def _scan_command(args: argparse.Namespace) -> int:
    """Run a vulnerability scan and emit the requested report format."""
    logger.info(f"Scanning {args.path} for reachable CVEs...")

    target_path = Path(args.path)
    if not target_path.exists():
        logger.error(f"Path does not exist: {target_path}")
        return 1

    scan_result = _run_scan_internal(target_path)

    output_format = getattr(args, "format", "table")
    show_all = getattr(args, "all", False)

    _emit_report(scan_result, output_format, show_all)

    fail_on = getattr(args, "fail_on", None)
    if fail_on and _severity_gate_tripped(scan_result.findings, fail_on):
        use_color = not getattr(args, "no_color", False) and sys.stdout.isatty()
        if output_format == "table":
            msg = (
                f"\n✖  Failing: reachable {fail_on.upper()} CVE found "
                f"(--fail-on {fail_on})"
            )
            print(_colorize("31;1", msg) if use_color else msg)
        return 2

    reachable_count = sum(1 for f in scan_result.findings if f.reachable)
    return 0 if reachable_count == 0 else 1


def _explain_command(args: argparse.Namespace) -> int:
    """Show the call path for a specific CVE."""
    target_path = Path(args.path)
    if not target_path.exists():
        logger.error(f"Path does not exist: {target_path}")
        return 1

    logger.info(f"Explaining {args.cve_id} in {args.path}...")
    scan_result = _run_scan_internal(target_path)

    from .report.explain import generate_explain_report

    print(generate_explain_report(scan_result.findings, args.cve_id), end="")
    return 0


def _self_test_command(_args: argparse.Namespace) -> int:
    """Run the built-in test suite."""
    import subprocess

    print("Running DeepReach self-test suite...\n")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"],
        capture_output=False,
    )
    return result.returncode


def _license_command(_args: argparse.Namespace) -> int:
    """Print license and third-party notices."""
    root = Path(__file__).parent.parent.parent
    try:
        print("=== DeepReach License ===")
        print((root / "LICENSE").read_text(encoding="utf-8"))
        print("\n=== Third-Party Notices ===")
        print((root / "NOTICE").read_text(encoding="utf-8"))
        return 0
    except FileNotFoundError as e:
        logger.error(f"License file not found: {e}")
        return 1


# ---------------------------------------------------------------------------
# Scan orchestrator - reads like pseudocode
# ---------------------------------------------------------------------------


def _run_scan_internal(target_path: Path) -> ScanResult:
    """Orchestrate lockfile discovery → advisory lookup → AST analysis → findings."""
    from .vuln_federation.store import VulnerabilityStore
    from .vuln_federation.osv import OSVAdapter

    with Timer() as t:
        dependencies = _discover_dependencies(target_path)

        if not dependencies:
            logger.warning("No lockfiles found or no dependencies parsed.")
            return _empty_result(target_path, 0)

        logger.info(
            f"Parsed {len(dependencies)} dependencies. "
            "Checking for vulnerabilities..."
        )

        store = VulnerabilityStore()
        osv = OSVAdapter()
        vulnerable_deps = _fetch_advisories(dependencies, store, osv)

        if not vulnerable_deps:
            logger.info("No known vulnerabilities found in dependencies.")
            return _empty_result(target_path, len(dependencies))

        logger.info(
            f"Found {len(vulnerable_deps)} vulnerable dependencies. "
            "Starting reachability analysis..."
        )

        edges = _collect_edges(target_path)
        findings = _match_findings(vulnerable_deps, edges)

    return ScanResult(
        meta={
            "target": str(target_path),
            "total_dependencies": len(dependencies),
            "vulnerable_packages": len(vulnerable_deps),
            "version": __version__,
        },
        summary={
            "duration_ms": t.metrics.duration_ms,
            "peak_rss_bytes": t.metrics.peak_rss_bytes,
        },
        findings=findings,
        metrics=t.metrics,
    )


# ---------------------------------------------------------------------------
# Pure helpers - data in, data out
# ---------------------------------------------------------------------------

_DepTuple = tuple[str, str, str, str | None, list[str]]


def _empty_result(target_path: Path, dep_count: int) -> ScanResult:
    return ScanResult(
        meta={
            "target": str(target_path),
            "total_dependencies": dep_count,
            "vulnerable_packages": 0,
            "version": __version__,
        },
        summary={},
        findings=[],
    )


def _should_skip_dir(root: Path) -> bool:
    return bool(_IGNORED_DIRS & set(root.parts))


def _read_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-16")


def _discover_dependencies(target_path: Path) -> list[_DepTuple]:
    """Walk the tree and parse every lockfile found."""
    from .lockfile_parser.npm import NpmLockfileParser
    from .lockfile_parser.pip import PipLockfileParser

    npm_parser = NpmLockfileParser()
    pip_parser = PipLockfileParser()
    dependencies: list[_DepTuple] = []

    logger.info("Searching for lockfiles...")
    for root, _dirs, files in os.walk(target_path):
        root_path = Path(root)
        if _should_skip_dir(root_path):
            continue

        if "package-lock.json" in files:
            _parse_lockfile(
                root_path / "package-lock.json", npm_parser, dependencies
            )

        if "requirements.txt" in files:
            _parse_lockfile(
                root_path / "requirements.txt", pip_parser, dependencies
            )

    return dependencies


def _parse_lockfile(
    path: Path,
    parser: EcosystemAdapter,
    out: list[_DepTuple],
) -> None:
    logger.info(f"Found lockfile at {path}")
    try:
        content = _read_file(path)
        deps = parser.parse(content)
        out.extend(deps)
    except Exception as e:
        logger.error(f"Failed to parse {path}: {e}")


def _fetch_advisories(
    dependencies: list[_DepTuple],
    store: VulnerabilityStore,
    osv: SourceAdapter,
) -> list[tuple[_DepTuple, list[Advisory]]]:
    """Look up each dependency against local cache, falling back to OSV."""
    vulnerable: list[tuple[_DepTuple, list[Advisory]]] = []

    for dep in dependencies:
        ecosystem, name, version, _parent, _path = dep
        advisories = store.get_advisories(ecosystem, name)

        if not advisories:
            advisories = osv.fetch_advisories(ecosystem, name, version)
            for adv in advisories:
                store.upsert_advisory(adv, osv.get_name())

        if advisories:
            vulnerable.append((dep, advisories))

    return vulnerable


def _collect_edges(target_path: Path) -> list[Edge]:
    """Walk source files and extract call-graph edges via AST."""
    from .reachability.javascript import JavaScriptLanguageAdapter
    from .reachability.python_lang import PythonLanguageAdapter

    js_adapter = JavaScriptLanguageAdapter()
    py_adapter = PythonLanguageAdapter()
    edges: list[Edge] = []

    logger.info("Scanning source code for function calls via AST...")
    for root, _dirs, files in os.walk(target_path):
        root_path = Path(root)
        if _should_skip_dir(root_path):
            continue

        for file in files:
            file_path = str(root_path / file)

            adapter: LanguageAdapter | None = None
            if any(file.endswith(ext) for ext in js_adapter.get_file_extensions()):
                adapter = js_adapter
            elif any(file.endswith(ext) for ext in py_adapter.get_file_extensions()):
                adapter = py_adapter

            if adapter is None:
                continue

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    _, file_edges = adapter.parse_file(file_path, f.read())
                    edges.extend(file_edges)
            except Exception:
                pass

    logger.info(f"Extracted {len(edges)} function calls from the project source code.")
    return edges


def _match_findings(
    vulnerable_deps: list[tuple[_DepTuple, list[Advisory]]],
    edges: list[Edge],
) -> list[Finding]:
    """Pure evaluator: match advisories against call-graph edges."""
    findings: list[Finding] = []

    for dep, advisories in vulnerable_deps:
        for adv in advisories:
            reachable_edges = []
            vuln_funcs = adv.vulnerable_functions or []

            for edge in edges:
                for func in vuln_funcs:
                    if func in edge.callee_ref:
                        reachable_edges.append(edge)

            is_reachable = bool(reachable_edges)
            findings.append(
                Finding(
                    advisory=adv,
                    reachable=is_reachable,
                    confidence=Confidence.HIGH if is_reachable else Confidence.LOW,
                    call_path=[e.caller for e in reachable_edges],
                    fix_version=adv.fix_version,
                )
            )

    return findings


def _severity_gate_tripped(findings: list[Finding], fail_on: str) -> bool:
    """Return True if any reachable finding meets or exceeds the threshold."""
    fail_idx = _SEVERITY_ORDER.index(fail_on.lower())
    for finding in findings:
        if not finding.reachable:
            continue
        sev = finding.advisory.severity.value
        if sev in _SEVERITY_ORDER and _SEVERITY_ORDER.index(sev) <= fail_idx:
            return True
    return False


def _filter_findings(findings: list[Finding], show_all: bool) -> list[Finding]:
    if show_all:
        return findings
    return [f for f in findings if f.reachable]


def _emit_report(result: ScanResult, fmt: str, show_all: bool) -> None:
    """Select and print the appropriate report format."""
    if fmt == "json":
        filtered = ScanResult(
            meta=result.meta,
            summary=result.summary,
            findings=_filter_findings(result.findings, show_all),
            metrics=result.metrics,
        )
        from .report.json_fmt import generate_json_report

        print(generate_json_report(filtered), end="")

    elif fmt == "sarif":
        filtered = ScanResult(
            meta=result.meta,
            summary=result.summary,
            findings=_filter_findings(result.findings, show_all),
            metrics=result.metrics,
        )
        from .report.sarif import generate_sarif_report

        print(generate_sarif_report(filtered), end="")

    else:
        from .report.table import generate_table_report

        print(generate_table_report(result, show_unreachable=show_all), end="")


def _colorize(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m"


if __name__ == "__main__":
    sys.exit(main())
