import sys
import os
import json

sys.path.insert(0, os.path.abspath("src"))
import unittest
from deepreach.models import (
    Advisory,
    Confidence,
    DefSite,
    Finding,
    ScanResult,
    Severity,
)
from deepreach.report.sarif import generate_sarif_report


class TestSarifReport(unittest.TestCase):
    def setUp(self):
        self.advisory_critical = Advisory(
            cve_id="CVE-2026-critical",
            ecosystem="pip",
            package="requests",
            vulnerable_version_range="<2.31.0",
            vulnerable_functions=["send"],
            fix_version="2.31.0",
            severity=Severity.CRITICAL,
        )
        self.def_site = DefSite(
            file="main.py", line=42, name="run_scan", exported=False
        )
        self.finding_critical = Finding(
            advisory=self.advisory_critical,
            reachable=True,
            confidence=Confidence.HIGH,
            call_path=[self.def_site],
            fix_version="2.31.0",
        )
        self.scan_result = ScanResult(
            meta={
                "target": "req_proj",
                "total_dependencies": 10,
                "vulnerable_packages": 1,
            },
            summary={},
            findings=[self.finding_critical],
        )

    def test_generate_sarif_report_structure(self):
        report_str = generate_sarif_report(self.scan_result)
        report = json.loads(report_str)

        self.assertEqual(report["version"], "2.1.0")
        self.assertEqual(len(report["runs"]), 1)
        run = report["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "deepreach")

        self.assertEqual(len(run["tool"]["driver"]["rules"]), 1)
        rule = run["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["id"], "CVE-2026-critical-requests")
        self.assertEqual(rule["defaultConfiguration"]["level"], "error")

        self.assertEqual(len(run["results"]), 1)
        res = run["results"][0]
        self.assertEqual(res["ruleId"], "CVE-2026-critical-requests")
        self.assertEqual(res["level"], "error")

        loc = res["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "main.py")
        self.assertEqual(loc["region"]["startLine"], 42)

    def test_sarif_report_determinism(self):
        report_str_1 = generate_sarif_report(self.scan_result)
        report_str_2 = generate_sarif_report(self.scan_result)
        self.assertEqual(report_str_1, report_str_2)
