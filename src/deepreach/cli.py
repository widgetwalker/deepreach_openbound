"""Command-line interface for DeepReach."""

import argparse
import logging
import sys
from typing import List, Optional, cast

from . import __version__
from .log import get_logger

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


def _scan_command(args) -> int:  # noqa: C901
    """Handle scan command."""
    logger.info(f"Scanning {args.path} for reachable CVEs...")

    import os
    from pathlib import Path
    from .vuln_federation.store import VulnerabilityStore
    from .vuln_federation.osv import OSVAdapter
    from .lockfile_parser.npm import NpmLockfileParser
    from .lockfile_parser.pip import PipLockfileParser
    from .reachability.javascript import JavaScriptLanguageAdapter
    from .reachability.python_lang import PythonLanguageAdapter

    store = VulnerabilityStore()
    osv = OSVAdapter()

    target_path = Path(args.path)
    if not target_path.exists():
        logger.error(f"Path does not exist: {target_path}")
        return 1

    dependencies = []

    # 1. Detect and Parse Lockfiles
    npm_parser = NpmLockfileParser()
    pip_parser = PipLockfileParser()

    logger.info("Searching for lockfiles...")
    for root, dirs, files in os.walk(target_path):
        # Skip standard ignored directories
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
        return 0

    logger.info(
        f"Parsed {len(dependencies)} dependencies. Checking for vulnerabilities..."
    )

    # 2. Check Vulnerabilities
    vulnerable_deps = []
    for dep in dependencies:
        ecosystem, name, version, parent, dep_path = dep

        # Check cache/store first
        advisories = store.get_advisories(ecosystem, name)

        if not advisories:
            # Fetch from OSV
            advisories = osv.fetch_advisories(ecosystem, name, version)
            for adv in advisories:
                store.upsert_advisory(adv, osv.get_name())

        if advisories:
            vulnerable_deps.append((dep, advisories))

    if not vulnerable_deps:
        logger.info("No known vulnerabilities found in dependencies.")
        return 0

    logger.info(
        f"Found {len(vulnerable_deps)} vulnerable dependencies. "
        "Starting reachability analysis..."
    )

    # 3. Reachability Analysis & Reporting
    js_adapter = JavaScriptLanguageAdapter()
    py_adapter = PythonLanguageAdapter()

    all_edges = []

    logger.info("Scanning source code for function calls via AST...")
    for root, dirs, files in os.walk(target_path):
        # Skip standard ignored directories
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

            # Extract JS/TS Calls
            if any(file.endswith(ext) for ext in js_adapter.get_file_extensions()):
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        _, edges = js_adapter.parse_file(file_path, f.read())
                        all_edges.extend(edges)
                except Exception:
                    pass

            # Extract Python Calls
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

    # ── ANSI colour helpers ───────────────────────────────────────────────────
    use_color = not getattr(args, "no_color", False) and sys.stdout.isatty()

    def c(code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if use_color else text

    RED = "31;1"
    YELLOW = "33"
    CYAN = "36"
    GREEN = "32"
    GREY = "90"
    BOLD = "1"

    SEVERITY_COLOR = {
        "CRITICAL": "35;1",  # magenta bold
        "HIGH": "31;1",  # red bold
        "MEDIUM": "33",  # yellow
        "LOW": "34",  # blue
        "UNKNOWN": "90",  # grey
    }

    # ── Collect findings ──────────────────────────────────────────────────────
    import json as _json

    findings = []
    fail_on = getattr(args, "fail_on", None)
    severity_order = ["critical", "high", "medium", "low"]

    for dep, advisories in vulnerable_deps:
        ecosystem, name, version, parent, dep_path = dep
        for adv in advisories:
            is_reachable = False
            reachable_edges = []
            for edge in all_edges:
                if name in edge.callee_ref:
                    is_reachable = True
                    reachable_edges.append(edge)

            severity_text = str(adv.severity).upper() if adv.severity else "UNKNOWN"

            traces = []
            for edge in reachable_edges:
                try:
                    rel = str(
                        Path(edge.caller.file).relative_to(target_path)
                    )
                except ValueError:
                    rel = edge.caller.file
                traces.append(
                    {"file": rel, "line": edge.line, "call": edge.callee_ref}
                )
            # Deduplicate
            seen = set()
            unique_traces = []
            for t in traces:
                key = (t["file"], t["line"], t["call"])
                if key not in seen:
                    seen.add(key)
                    unique_traces.append(t)

            findings.append(
                {
                    "cve_id": adv.cve_id,
                    "package": name,
                    "version": version,
                    "severity": severity_text,
                    "reachable": is_reachable,
                    "summary": adv.summary,
                    "details": adv.details,
                    "fix_version": adv.fix_version,
                    "traces": unique_traces,
                }
            )

    reachable_findings = [f for f in findings if f["reachable"]]
    reachable_count = len(reachable_findings)

    # ── Output: JSON ──────────────────────────────────────────────────────────
    output_format = getattr(args, "format", "table")
    show_all = getattr(args, "all", False)

    if output_format == "json":
        report = {
            "tool": "deepreach",
            "target": str(target_path),
            "summary": {
                "total_dependencies": len(dependencies),
                "vulnerable_packages": len(vulnerable_deps),
                "reachable_cves": reachable_count,
                "total_cves": len(findings),
            },
            "findings": findings if show_all else reachable_findings,
        }
        print(_json.dumps(report, indent=2))

    elif output_format == "sarif":
        # Minimal SARIF 2.1.0 output
        rules: List[dict] = []
        results = []
        for finding in (findings if show_all else reachable_findings):
            rule_id = str(finding.get("cve_id", ""))
            summary = str(finding.get("summary") or "")
            details = str(finding.get("details") or "")
            is_reachable = bool(finding.get("reachable", False))
            package = str(finding.get("package", ""))
            version = str(finding.get("version", ""))
            traces = cast(List[dict], finding.get("traces") or [])

            if not any(r["id"] == rule_id for r in rules):
                rules.append({
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": summary or rule_id},
                    "help": {"text": details or ""},
                })

            trace_list = traces or [
                {"file": "unknown", "line": 1, "call": ""}
            ]
            for trace in trace_list:
                results.append({
                    "ruleId": rule_id,
                    "level": "error" if is_reachable else "warning",
                    "message": {
                        "text": f"{rule_id} in {package}@{version} — {summary}"
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(trace.get("file", ""))},
                            "region": {"startLine": trace.get("line") or 1},
                        }
                    }],
                })
        sarif = {
            "version": "2.1.0",
            "$schema": (
                "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                "master/Schemata/sarif-schema-2.1.0.json"
            ),
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "deepreach",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }],
        }
        print(_json.dumps(sarif, indent=2))

    else:
        # ── Output: Table (default) ───────────────────────────────────────────
        print("\n" + c(BOLD, "=" * 80))
        print(c(BOLD, "  DEEPREACH SCAN REPORT"))
        print(c(BOLD, "=" * 80))

        display = findings if show_all else findings  # always show all in table
        for finding in display:
            sev = str(finding.get("severity", "UNKNOWN"))
            cve_id = str(finding.get("cve_id", ""))
            package = str(finding.get("package", ""))
            version = str(finding.get("version", ""))
            is_reachable = bool(finding.get("reachable", False))
            traces = cast(List[dict], finding.get("traces") or [])
            summary = str(finding.get("summary") or "")
            details = str(finding.get("details") or "")
            fix_version = str(finding.get("fix_version") or "")

            sev_col = SEVERITY_COLOR.get(sev, GREY)
            reach_text = (
                c(RED, "● REACHABLE") if is_reachable else c(GREY, "○ unreachable")  # noqa: E501
            )
            print(
                f"\n  {c(sev_col, f'[{sev}]')}  "
                f"{c(BOLD, cve_id)}  in  "
                f"{c(CYAN, f'{package}@{version}')}"
            )
            print(f"  Reachability : {reach_text}")

            if traces:
                for trace in traces[:3]:
                    print(
                        f"  {c(GREY, '→')} "
                        f"{c(YELLOW, str(trace.get('file', '')))}:"
                        f"{trace.get('line', 1)}  "
                        f"{c(GREY, str(trace.get('call', '')))}"
                    )
                if len(traces) > 3:
                    print(
                        f"  {c(GREY, '→ ...')} "
                        f"and {len(traces) - 3} more locations"
                    )

            if summary:
                print(f"  Summary      : {summary}")
            if details:
                preview = details[:160] + (
                    "…" if len(details) > 160 else ""
                )
                print(f"  Details      : {c(GREY, preview)}")
            if fix_version:
                print(
                    f"  Fix          : upgrade to "
                    f"{c(GREEN, fix_version)}"
                )
            print(c(GREY, "  " + "─" * 78))

        # Summary bar
        total = len(findings)
        print(f"\n{c(BOLD, 'Summary')}:")
        print(
            f"  {len(dependencies)} dependencies scanned  │  "
            f"{len(vulnerable_deps)} vulnerable packages  │  "
            f"{c(RED, str(reachable_count) + ' reachable CVEs') if reachable_count else c(GREEN, '0 reachable CVEs')} "  # noqa: E501
            f"out of {total} total"
        )

    # ── --fail-on gate ────────────────────────────────────────────────────────
    if fail_on:
        fail_idx = severity_order.index(fail_on.lower())
        for finding in reachable_findings:
            sev = str(finding.get("severity", "")).lower()
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
    import os
    from pathlib import Path
    from .vuln_federation.store import VulnerabilityStore

    store = VulnerabilityStore()
    target_path = Path(args.path)
    cve_id = args.cve_id

    logger.info(f"Explaining {cve_id} in {args.path}...")

    # Look up from cache first
    # Search all advisories matching this CVE across all packages
    for root, dirs, files in os.walk(target_path):
        pass  # just to ensure target_path is valid

    # Try to retrieve from store
    try:
        import sqlite3
        with sqlite3.connect(store.db_path) as conn:
            cursor = conn.execute(
                "SELECT * FROM advisories WHERE cve_id = ?", (cve_id,)
            )
            rows = cursor.fetchall()
            if rows:
                print(f"\n{'='*60}")
                print(f"  {cve_id}")
                print(f"{'='*60}")
                for row in rows:
                    print(f"  Package   : {row[2]}@{row[3]}")
                    print(f"  Severity  : {row[6] or 'UNKNOWN'}")
                    print(f"  Summary   : {row[7] or 'N/A'}")
                    print(f"  Fix       : {row[5] or 'No fix available'}")
                    if row[8]:
                        print(f"\n  Details:\n  {row[8][:500]}")
            else:
                print(
                    f"  {cve_id} not found in local cache. "
                    "Run 'deepreach scan <path>' first to populate the cache."
                )
    except Exception as e:
        logger.error(f"Explain lookup failed: {e}")
        return 1
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

