"""Command-line interface for DeepReach."""

import argparse
import logging
from pathlib import Path
import sys
from typing import List, Optional

from . import __version__
from .log import get_logger
from .models import ScanResult


# Ensure stdout uses UTF-8 to prevent charmap UnicodeEncodeErrors on Windows
if (
    sys.stdout
    and sys.stdout.encoding
    and sys.stdout.encoding.lower() != "utf-8"
    and hasattr(sys.stdout, "reconfigure")
):
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]

logger = get_logger(__name__)


def create_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="deepreach",
        description="Reachable CVE Scanner for Node and Python projects",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # init command
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

    # scan command
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

    # explain command
    explain_parser = subparsers.add_parser(
        "explain", help="Show call path for a specific CVE"
    )
    explain_parser.add_argument("path", help="Path to repository")
    explain_parser.add_argument(
        "cve_id", help="CVE ID to explain (e.g., CVE-2024-1234)"
    )

    # self-test command
    subparsers.add_parser("self-test", help="Run internal self-test suite")

    # license command
    subparsers.add_parser("license", help="Show license and third-party notices")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point."""
    if argv is None:
        argv = sys.argv[1:]

    parser = create_parser()
    args = parser.parse_args(argv)

    # Configure logging
    if getattr(args, "debug", False):
        logger.setLevel(logging.DEBUG)

    # Handle commands
    if args.command == "init":
        return _init_command(args)
    elif args.command == "scan":
        return _scan_command(args)
    elif args.command == "explain":
        return _explain_command(args)
    elif args.command == "self-test":
        return _self_test_command(args)
    elif args.command == "license":
        return _license_command(args)
    elif args.command == "version":
        print(f"deepreach {__version__}")
        return 0
    else:
        # No command specified
        parser.print_help()
        return 1


def _init_command(args) -> int:
    """Handle init command."""
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



def _run_scan_internal(target_path: Path) -> ScanResult:  # noqa: C901
    """Run vulnerability reachability scan and return ScanResult."""

    import os
    from .vuln_federation.store import VulnerabilityStore
    from .vuln_federation.osv import OSVAdapter
    from .lockfile_parser.npm import NpmLockfileParser
    from .lockfile_parser.pip import PipLockfileParser
    from .reachability.javascript import JavaScriptLanguageAdapter
    from .reachability.python_lang import PythonLanguageAdapter
    from .models import Finding, ScanResult

    store = VulnerabilityStore()
    osv = OSVAdapter()

    dependencies = []
    npm_parser = NpmLockfileParser()
    pip_parser = PipLockfileParser()

    logger.info("Searching for lockfiles...")
    for root, dirs, files in os.walk(target_path):
        if any(
            ignored in Path(root).parts
            for ignored in [
                ".git",
                "node_modules",
                ".venv",
                "venv",
                "dist",
                "build",
                "__pycache__",
            ]
        ):
            continue

        root_path = Path(root)

        if "package-lock.json" in files:
            npm_lock = root_path / "package-lock.json"
            logger.info(f"Found npm lockfile at {npm_lock}")
            try:
                try:
                    with open(npm_lock, "r", encoding="utf-8") as f:
                        content = f.read()
                except UnicodeDecodeError:
                    with open(npm_lock, "r", encoding="utf-16") as f:
                        content = f.read()
                deps = npm_parser.parse(content)
                dependencies.extend(deps)
            except Exception as e:
                logger.error(f"Failed to parse {npm_lock}: {e}")

        if "requirements.txt" in files:
            pip_lock = root_path / "requirements.txt"
            logger.info(f"Found pip lockfile at {pip_lock}")
            try:
                try:
                    with open(pip_lock, "r", encoding="utf-8") as f:
                        content = f.read()
                except UnicodeDecodeError:
                    with open(pip_lock, "r", encoding="utf-16") as f:
                        content = f.read()
                deps = pip_parser.parse(content)
                dependencies.extend(deps)
            except Exception as e:
                logger.error(f"Failed to parse {pip_lock}: {e}")

    if not dependencies:
        logger.warning("No lockfiles found or no dependencies parsed.")
        return ScanResult(
            meta={
                "target": str(target_path),
                "total_dependencies": 0,
                "vulnerable_packages": 0,
                "version": __version__,
            },
            summary={},
            findings=[],
        )

    logger.info(
        f"Parsed {len(dependencies)} dependencies. Checking for vulnerabilities..."
    )

    vulnerable_deps = []
    for dep in dependencies:
        ecosystem, name, version, parent, dep_path = dep
        advisories = store.get_advisories(ecosystem, name)

        if not advisories:
            advisories = osv.fetch_advisories(ecosystem, name, version)
            for adv in advisories:
                store.upsert_advisory(adv, osv.get_name())

        if advisories:
            vulnerable_deps.append((dep, advisories))

    if not vulnerable_deps:
        logger.info("No known vulnerabilities found in dependencies.")
        return ScanResult(
            meta={
                "target": str(target_path),
                "total_dependencies": len(dependencies),
                "vulnerable_packages": 0,
                "version": __version__,
            },
            summary={},
            findings=[],
        )

    logger.info(
        f"Found {len(vulnerable_deps)} vulnerable dependencies. "
        "Starting reachability analysis..."
    )

    js_adapter = JavaScriptLanguageAdapter()
    py_adapter = PythonLanguageAdapter()
    all_edges = []

    logger.info("Scanning source code for function calls via AST...")
    for root, dirs, files in os.walk(target_path):
        if any(
            ignored in Path(root).parts
            for ignored in [
                ".git",
                "node_modules",
                ".venv",
                "venv",
                "dist",
                "build",
                "__pycache__",
            ]
        ):
            continue

        for file in files:
            file_path = str(Path(root) / file)

            if any(file.endswith(ext) for ext in js_adapter.get_file_extensions()):
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        _, edges = js_adapter.parse_file(file_path, f.read())
                        all_edges.extend(edges)
                except Exception:
                    pass

            if any(file.endswith(ext) for ext in py_adapter.get_file_extensions()):
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        _, edges = py_adapter.parse_file(file_path, f.read())
                        all_edges.extend(edges)
                except Exception:
                    pass

    logger.info(
        f"Extracted {len(all_edges)} function calls from the project source code."
    )

    scan_findings: List[Finding] = []
    for dep, advisories in vulnerable_deps:
        ecosystem, name, version, parent, dep_path = dep
        for adv in advisories:
            is_reachable = False
            reachable_edges = []
            vulnerable_funcs = adv.vulnerable_functions or []
            for edge in all_edges:
                for func in vulnerable_funcs:
                    if func in edge.callee_ref:
                        is_reachable = True
                        reachable_edges.append(edge)

            call_path = [edge.caller for edge in reachable_edges]
            finding_obj = Finding(
                advisory=adv,
                reachable=is_reachable,
                confidence="high" if is_reachable else "low",
                call_path=call_path,
                fix_version=adv.fix_version,
            )
            scan_findings.append(finding_obj)

    return ScanResult(
        meta={
            "target": str(target_path),
            "total_dependencies": len(dependencies),
            "vulnerable_packages": len(vulnerable_deps),
            "version": __version__,
        },
        summary={},
        findings=scan_findings,
    )


def _scan_command(args) -> int:  # noqa: C901
    """Handle scan command."""
    logger.info(f"Scanning {args.path} for reachable CVEs...")

    from pathlib import Path
    target_path = Path(args.path)
    if not target_path.exists():
        logger.error(f"Path does not exist: {target_path}")
        return 1

    scan_result = _run_scan_internal(target_path)

    reachable_count = sum(1 for f in scan_result.findings if f.reachable)

    # ── Output: JSON ──────────────────────────────────────────────────────────
    output_format = getattr(args, "format", "table")
    show_all = getattr(args, "all", False)

    if output_format == "json":
        # Filter findings if --all / show_all is False
        if not show_all:
            filtered_findings = [f for f in scan_result.findings if f.reachable]
            json_scan_result = ScanResult(
                meta=scan_result.meta,
                summary=scan_result.summary,
                findings=filtered_findings,
            )
        else:
            json_scan_result = scan_result

        from .report.json_fmt import generate_json_report
        print(generate_json_report(json_scan_result), end="")

    elif output_format == "sarif":
        # Filter findings if --all / show_all is False
        if not show_all:
            filtered_findings = [f for f in scan_result.findings if f.reachable]
            sarif_scan_result = ScanResult(
                meta=scan_result.meta,
                summary=scan_result.summary,
                findings=filtered_findings,
            )
        else:
            sarif_scan_result = scan_result

        from .report.sarif import generate_sarif_report
        print(generate_sarif_report(sarif_scan_result), end="")

    else:
        # ── Output: Table (default) ───────────────────────────────────────────
        from .report.table import generate_table_report
        print(generate_table_report(scan_result, show_unreachable=show_all), end="")

    # ── --fail-on gate ────────────────────────────────────────────────────────
    fail_on = getattr(args, "fail_on", None)
    if fail_on:
        severity_order = ["critical", "high", "medium", "low"]
        use_color = not getattr(args, "no_color", False) and sys.stdout.isatty()

        def c(code: str, text: str) -> str:
            return f"\033[{code}m{text}\033[0m" if use_color else text

        RED = "31;1"
        fail_idx = severity_order.index(fail_on.lower())
        for finding in scan_result.findings:
            if not finding.reachable:
                continue
            sev = finding.advisory.severity.lower()
            if sev in severity_order and severity_order.index(sev) <= fail_idx:
                if output_format == "table":
                    print(
                        c(RED, f"\n✖  Failing: reachable {sev.upper()} CVE found "
                          f"(--fail-on {fail_on})")
                    )
                return 2  # distinct exit code for severity gate

    return 0 if reachable_count == 0 else 1


def _explain_command(args) -> int:
    """Handle explain command."""
    from pathlib import Path
    target_path = Path(args.path)
    cve_id = args.cve_id

    if not target_path.exists():
        logger.error(f"Path does not exist: {target_path}")
        return 1

    logger.info(f"Explaining {cve_id} in {args.path}...")
    scan_result = _run_scan_internal(target_path)

    from .report.explain import generate_explain_report
    print(generate_explain_report(scan_result.findings, cve_id), end="")
    return 0



def _self_test_command(args) -> int:
    """Handle self-test command."""
    import subprocess

    print("Running DeepReach self-test suite...\n")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"],
        capture_output=False,
    )
    return result.returncode


def _license_command(args) -> int:
    """Handle license command."""
    from pathlib import Path

    # Try relative to the package root
    root = Path(__file__).parent.parent.parent
    try:
        license_path = root / "LICENSE"
        notice_path = root / "NOTICE"
        print("=== DeepReach License ===")
        print(license_path.read_text(encoding="utf-8"))
        print("\n=== Third-Party Notices ===")
        print(notice_path.read_text(encoding="utf-8"))
        return 0
    except FileNotFoundError as e:
        logger.error(f"License file not found: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

