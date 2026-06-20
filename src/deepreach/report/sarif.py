"""SARIF 2.1.0 format report generator for DeepReach."""

import json
from typing import Dict, Any
from ..models import ScanResult


def generate_sarif_report(result: ScanResult) -> str:
    """Generate a SARIF 2.1.0 compliant report."""
    # Build SARIF structure
    sarif: Dict[str, Any] = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "deepreach",
                        "version": result.meta.get("version", "0.1.0"),
                        "informationUri": "https://github.com/widgetwalker/deepreach_openbound",
                        "rules": []
                    }
                },
                "results": []
            }
        ]
    }

    # Add rules for each finding
    rules_seen = set()
    for finding in result.findings:
        rule_id = f"{finding.advisory.cve_id}-{finding.advisory.package}"
        if rule_id not in rules_seen:
            sev_lower = finding.advisory.severity.lower()
            level = (
                "error"
                if sev_lower in ["critical", "high"]
                else "warning"
                if sev_lower == "medium"
                else "note"
            )
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
                "defaultConfiguration": {
                    "level": level
                },
                "properties": {
                    "cve_id": finding.advisory.cve_id,
                    "package": finding.advisory.package,
                    "ecosystem": finding.advisory.ecosystem
                }
            }
            sarif["runs"][0]["tool"]["driver"]["rules"].append(rule)
            rules_seen.add(rule_id)

        # Add result for this finding
        if finding.call_path:
            # Use the first location in the call path as the primary location
            primary_location = finding.call_path[0]
            sev_lower = finding.advisory.severity.lower()
            level = (
                "error"
                if sev_lower in ["critical", "high"]
                else "warning"
                if sev_lower == "medium"
                else "note"
            )
            result_obj = {
                "ruleId": f"{finding.advisory.cve_id}-{finding.advisory.package}",
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
                                "uri": primary_location.file,
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": primary_location.line
                            }
                        }
                    }
                ],
                "properties": {
                    "cve_id": finding.advisory.cve_id,
                    "package": finding.advisory.package,
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
            }
            sarif["runs"][0]["results"].append(result_obj)

    # Generate deterministic JSON with sorted keys
    return json.dumps(sarif, sort_keys=True, separators=(',', ':')) + "\n"
