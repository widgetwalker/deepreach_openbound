"""Table-format report for DeepReach scan results."""

from __future__ import annotations

from ..hashing import stable_hash
from ..models import ScanResult


def generate_table_report(result: ScanResult, show_unreachable: bool = False) -> str:
    """Render findings as a fixed-width text table."""
    findings = result.findings
    if not show_unreachable:
        findings = [f for f in findings if f.reachable]

    if not findings:
        return "No reachable vulnerabilities found.\n"

    lines: list[str] = []

    header = (
        f"{'CVE':<20} {'Package':<25} {'Range':<20} "
        f"{'Reachable':<12} {'Path':<40} {'Fix':<15}"
    )
    lines.append(header)
    lines.append("-" * len(header))

    for finding in findings:
        cve_id = finding.advisory.cve_id[:19]
        package = finding.advisory.package[:24]
        version_range = finding.advisory.vulnerable_version_range[:19]
        reachable = "YES" if finding.reachable else "NO"

        call_path_str = ""
        if finding.call_path:
            func_names = [ds.name for ds in finding.call_path[:3]]
            call_path_str = " → ".join(func_names)[:39]

        fix_version = (finding.fix_version or "-")[:14]

        row = (
            f"{cve_id:<20} {package:<25} {version_range:<20} {reachable:<12} "
            f"{call_path_str:<40} {fix_version:<15}"
        )
        lines.append(row)

    total_reachable = sum(1 for f in result.findings if f.reachable)
    total_unreachable = sum(1 for f in result.findings if not f.reachable)

    lines.append("")
    lines.append(
        f"Summary: {total_reachable} reachable, "
        f"{total_unreachable} unreachable vulnerabilities"
    )
    lines.append(f"Scan ID: {stable_hash(result.meta)}")

    return "\n".join(lines) + "\n"
