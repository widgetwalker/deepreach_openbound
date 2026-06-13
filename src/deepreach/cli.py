"""Command-line interface for DeepReach."""

import argparse
import logging
import sys
from typing import List, Optional

from . import __version__
from .log import get_logger


logger = get_logger(__name__)


def create_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="deepreach",
        description="Reachable CVE Scanner for Node and Python projects"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # init command
    init_parser = subparsers.add_parser(
        "init",
        help="Download and index vulnerability advisories"
    )
    init_parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip network and use cached data only"
    )
    init_parser.add_argument(
        "--ecosystem",
        choices=["npm", "pip"],
        help="Limit to specific ecosystem (default: both)"
    )

    # scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan repository for reachable CVEs"
    )
    scan_parser.add_argument(
        "path",
        help="Path to repository to scan"
    )
    scan_parser.add_argument(
        "--entry",
        action="append",
        metavar="FILE[:LINE]",
        help="Entry point for reachability analysis (repeatable)"
    )
    scan_parser.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default="table",
        help="Output format (default: table)"
    )
    scan_parser.add_argument(
        "--all",
        action="store_true",
        help="Show unreachable advisories"
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        help="Fail scan if CVE at or above this severity is reachable"
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    scan_parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging and stack traces"
    )
    scan_parser.add_argument(
        "--enable-nvd",
        action="store_true",
        help="Enable NVD advisory feed (off by default)"
    )
    scan_parser.add_argument(
        "--partial-ok",
        action="store_true",
        help="Continue if some advisory sources fail"
    )

    # explain command
    explain_parser = subparsers.add_parser(
        "explain",
        help="Show call path for a specific CVE"
    )
    explain_parser.add_argument(
        "path",
        help="Path to repository"
    )
    explain_parser.add_argument(
        "cve_id",
        help="CVE ID to explain (e.g., CVE-2024-1234)"
    )

    # self-test command
    subparsers.add_parser(
        "self-test",
        help="Run internal self-test suite"
    )

    # license command
    subparsers.add_parser(
        "license",
        help="Show license and third-party notices"
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point."""
    if argv is None:
        argv = sys.argv[1:]

    parser = create_parser()
    args = parser.parse_args(argv)

    # Configure logging
    if getattr(args, 'debug', False):
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
    # TODO: Implement vulnerability federation
    logger.info("Init command not yet implemented")
    return 0


def _scan_command(args) -> int:
    """Handle scan command."""
    logger.info(f"Scanning {args.path} for reachable CVEs...")
    # TODO: Implement reachability analysis
    logger.info("Scan command not yet implemented")
    return 0


def _explain_command(args) -> int:
    """Handle explain command."""
    logger.info(f"Explaining {args.cve_id} in {args.path}...")
    # TODO: Implement explain functionality
    logger.info("Explain command not yet implemented")
    return 0


def _self_test_command(args) -> int:
    """Handle self-test command."""
    logger.info("Running DeepReach self-test...")
    # TODO: Implement self-test
    logger.info("Self-test command not yet implemented")
    return 0


def _license_command(args) -> int:
    """Handle license command."""
    try:
        with open("LICENSE", "r", encoding="utf-8") as f:
            license_content = f.read()
        with open("NOTICE", "r", encoding="utf-8") as f:
            notice_content = f.read()

        print("=== DeepReach License ===")
        print(license_content)
        print("\n=== Third-Party Notices ===")
        print(notice_content)
        return 0
    except FileNotFoundError as e:
        logger.error(f"License file not found: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
