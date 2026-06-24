"""SARIF 2.1.0 report for DeepReach scan results."""

from __future__ import annotations

import json

from ..models import ScanResult, Severity


def _severity_to_level(severity: Severity) -> str:
    """Map advisory severity to SARIF result level."""
    sev = severity.value
    if sev in ("critical", "high"):
        return "error"
    if sev == "medium":
        return "warning"
    return "note"


def generate_sarif_report(result: ScanResult) -> str:
    """Render findings as a SARIF 2.1.0 JSON document."""
    sarif: dict[str, object] = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "deepreach",
                        "version": result.meta.get("version", "0.1.0"),
                        "informationUri": "https://github.com/widgetwalker/deepreach_openbound",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }

    rules_seen: set[str] = set()
    for finding in result.findings:
        rule_id = f"{finding.advisory.cve_id}-{finding.advisory.package}"

        if rule_id not in rules_seen:
            level = _severity_to_level(finding.advisory.severity)
            rule = {
                "id": rule_id,
                "name": f"Reachable CVE in {finding.advisory.package}",
                "shortDescription": {
                    "text": (
                        f"Reachable vulnerability {finding.advisory.cve_id} "
                        f"in {finding.advisory.package}"
                    )
                },
                "fullDescription": {
                    "text": (
                        f"CVE {finding.advisory.cve_id} affects "
                        f"{finding.advisory.package} versions "
                        f"{finding.advisory.vulnerable_version_range}. "
                        f"Reachable from application entry points."
                    )
                },
                "defaultConfiguration": {"level": level},
                "properties": {
                    "cve_id": finding.advisory.cve_id,
                    "package": finding.advisory.package,
                    "ecosystem": finding.advisory.ecosystem,
                },
            }
            sarif["runs"][0]["tool"]["driver"]["rules"].append(rule)  # type: ignore[index]
            rules_seen.add(rule_id)

        if finding.call_path:
            primary = finding.call_path[0]
            level = _severity_to_level(finding.advisory.severity)
            result_obj = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": (
                        f"Reachable CVE {finding.advisory.cve_id} "
                        f"in {finding.advisory.package}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": primary.file,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": primary.line},
                        }
                    }
                ],
                "properties": {
                    "cve_id": finding.advisory.cve_id,
                    "package": finding.advisory.package,
                    "confidence": finding.confidence.value,
                    "call_path": [
                        {
                            "file": ds.file,
                            "line": ds.line,
                            "name": ds.name,
                            "exported": ds.exported,
                        }
                        for ds in finding.call_path
                    ],
                },
            }
            sarif["runs"][0]["results"].append(result_obj)  # type: ignore[index]

    return json.dumps(sarif, sort_keys=True, separators=(",", ":")) + "\n"
