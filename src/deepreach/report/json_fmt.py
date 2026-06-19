"""JSON format report generator for DeepReach."""

import json
from typing import Dict, Any
from ..models import ScanResult
from ..hashing import stable_hash


def generate_json_report(result: ScanResult) -> str:
    """Generate a deterministic JSON report."""
    # Convert findings to dictionaries
    findings_data = []
    for finding in result.findings:
        finding_dict = {
            "cve_id": finding.advisory.cve_id,
            "package": finding.advisory.package,
            "ecosystem": finding.advisory.ecosystem,
            "vulnerable_version_range": finding.advisory.vulnerable_version_range,
            "vulnerable_functions": finding.advisory.vulnerable_functions,
            "fix_version": finding.advisory.fix_version,
            "severity": getattr(finding.advisory, 'severity', 'unknown'),
            "reachable": finding.reachable,
            "confidence": finding.confidence,
            "call_path": [
                {
                    "file": ds.file,
                    "line": ds.line,
                    "name": ds.name,
                    "exported": ds.exported
                }
                for ds in finding.call_path
            ]
        }
        findings_data.append(finding_dict)

    # Build the final result
    report: Dict[str, Any] = {
        "meta": {
            "tool": "deepreach",
            "version": result.meta.get("version", "0.1.0"),
            "schema_version": result.meta.get("schema_version", "1.0.0"),
            "repo": result.meta.get("repo", "unknown"),
            "scanned_at_utc": result.meta.get("scanned_at_utc", ""),
            "scan_id": stable_hash(result.meta)
        },
        "summary": {
            "reachable": sum(1 for f in result.findings if f.reachable),
            "unreachable": sum(1 for f in result.findings if not f.reachable),
            "by_severity": result.summary.get("by_severity", {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }),
            "duration_ms": result.summary.get("duration_ms", 0),
            "peak_rss_bytes": result.summary.get("peak_rss_bytes", 0)
        },
        "findings": findings_data
    }

    # Generate deterministic JSON with sorted keys and no whitespace
    return json.dumps(report, sort_keys=True, separators=(',', ':')) + "\n"
