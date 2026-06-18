"""Table format report generator for DeepReach."""

from ..models import ScanResult
from ..hashing import stable_hash


def generate_table_report(result: ScanResult, show_unreachable: bool = False) -> str:
    """Generate a colorized table report."""
    # Filter findings based on show_unreachable flag
    findings = result.findings
    if not show_unreachable:
        findings = [f for f in findings if f.reachable]

    if not findings:
        return "No reachable vulnerabilities found.\n"

    # Build table
    lines = []

    # Header
    header = (
        f"{'CVE':<20} {'Package':<25} {'Range':<20} "
        f"{'Reachable':<12} {'Path':<40} {'Fix':<15}"
    )
    lines.append(header)
    lines.append("-" * len(header))

    # Rows
    for finding in findings:
        cve_id = finding.advisory.cve_id[:19]  # Truncate if too long
        package = finding.advisory.package[:24]
        version_range = finding.advisory.vulnerable_version_range[:19]
        reachable = "YES" if finding.reachable else "NO"

        # Simplify call path for display
        call_path_str = ""
        if finding.call_path:
            # Show first few functions in the path
            func_names = [ds.name for ds in finding.call_path[:3]]
            call_path_str = " → ".join(func_names)[:39]

        fix_version = finding.fix_version or "-"
        fix_version = fix_version[:14]  # Truncate if too long

        row = (
            f"{cve_id:<20} {package:<25} {version_range:<20} {reachable:<12} "
            f"{call_path_str:<40} {fix_version:<15}"
        )
        lines.append(row)

    # Summary footer
    total_reachable = sum(1 for f in result.findings if f.reachable)
    total_unreachable = sum(1 for f in result.findings if not f.reachable)

    lines.append("")
    lines.append(
        f"Summary: {total_reachable} reachable, "
        f"{total_unreachable} unreachable vulnerabilities"
    )
    lines.append(
        f"Scan ID: {stable_hash(result.meta)}"
    )

    return "\n".join(lines) + "\n"
