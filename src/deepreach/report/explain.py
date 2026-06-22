"""Explain format report generator for DeepReach."""

from typing import List
from ..models import Finding


def generate_explain_report(findings: List[Finding], cve_id: str) -> str:
    """Generate a detailed explanation of a specific CVE finding."""
    # Find the specific CVE
    target_finding = None
    for finding in findings:
        if finding.advisory.cve_id == cve_id:
            target_finding = finding
            break

    if not target_finding:
        return f"CVE {cve_id} not found in scan results.\n"

    lines = []
    lines.append(f"Explanation for {target_finding.advisory.cve_id}")
    lines.append("=" * 50)
    lines.append("")
    lines.append(f"Package: {target_finding.advisory.package}")
    lines.append(f"Ecosystem: {target_finding.advisory.ecosystem}")
    lines.append(
        f"Affected versions: "
        f"{target_finding.advisory.vulnerable_version_range}"
    )
    lines.append(
        f"Fix version: "
        f"{target_finding.advisory.fix_version or 'Not available'}"
    )
    lines.append(
        f"Severity: "
        f"{getattr(target_finding.advisory, 'severity', 'unknown')}"
    )
    lines.append(f"Reachable: {'YES' if target_finding.reachable else 'NO'}")
    lines.append(f"Confidence: {target_finding.confidence}")
    lines.append("")

    if target_finding.reachable and target_finding.call_path:
        lines.append("Call path to vulnerable function:")
        lines.append("-" * 30)
        for i, ds in enumerate(target_finding.call_path):
            indent = "  " * i
            export_marker = " [EXPORTED]" if ds.exported else ""
            lines.append(f"{indent}{i+1}. {ds.name}()")
            lines.append(f"{indent}   File: {ds.file}:{ds.line}{export_marker}")
        lines.append("")
        lines.append(f"Total functions in path: {len(target_finding.call_path)}")
    elif not target_finding.reachable:
        lines.append("This vulnerability is not reachable from any entry point.")
        lines.append("No call path to display.")
    else:
        lines.append(
            "Vulnerability is reachable but call path information "
            "is not available."
        )

    lines.append("")

    return "\n".join(lines) + "\n"
