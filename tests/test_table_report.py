import sys
import os

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
from deepreach.report.table import generate_table_report


class TestTableReport(unittest.TestCase):
    def setUp(self):
        self.advisory_reachable = Advisory(
            cve_id="CVE-2026-1111",
            ecosystem="pip",
            package="requests",
            vulnerable_version_range="<2.31.0",
            vulnerable_functions=["send"],
            fix_version="2.31.0",
            severity=Severity.CRITICAL,
        )
        self.advisory_unreachable = Advisory(
            cve_id="CVE-2026-2222",
            ecosystem="npm",
            package="express",
            vulnerable_version_range="<4.19.0",
            vulnerable_functions=["serve"],
            fix_version="4.19.0",
            severity=Severity.HIGH,
        )
        self.def_site1 = DefSite(file="app.py", line=10, name="main", exported=False)
        self.def_site2 = DefSite(file="lib.py", line=20, name="helper", exported=False)

        self.finding_reachable = Finding(
            advisory=self.advisory_reachable,
            reachable=True,
            confidence=Confidence.HIGH,
            call_path=[self.def_site1, self.def_site2],
            fix_version="2.31.0",
        )
        self.finding_unreachable = Finding(
            advisory=self.advisory_unreachable,
            reachable=False,
            confidence=Confidence.LOW,
            call_path=[],
            fix_version="4.19.0",
        )

        self.scan_result = ScanResult(
            meta={
                "target": "test_project",
                "total_dependencies": 10,
                "vulnerable_packages": 2,
            },
            summary={},
            findings=[self.finding_reachable, self.finding_unreachable],
        )

    def test_generate_table_report_reachable_only(self):
        report = generate_table_report(self.scan_result, show_unreachable=False)
        self.assertIn("CVE-2026-1111", report)
        self.assertIn("requests", report)
        self.assertIn("main → helper", report)

        self.assertNotIn("CVE-2026-2222", report)
        self.assertNotIn("express", report)

        self.assertIn("Summary: 1 reachable, 1 unreachable vulnerabilities", report)

    def test_generate_table_report_show_all(self):
        report = generate_table_report(self.scan_result, show_unreachable=True)
        self.assertIn("CVE-2026-1111", report)
        self.assertIn("requests", report)
        self.assertIn("CVE-2026-2222", report)
        self.assertIn("express", report)

        self.assertIn("Summary: 1 reachable, 1 unreachable vulnerabilities", report)

    def test_generate_table_report_no_findings(self):
        empty_result = ScanResult(
            meta={
                "target": "test_project",
                "total_dependencies": 10,
                "vulnerable_packages": 0,
            },
            summary={},
            findings=[],
        )
        report = generate_table_report(empty_result, show_unreachable=False)
        self.assertEqual(report, "No reachable vulnerabilities found.\n")
