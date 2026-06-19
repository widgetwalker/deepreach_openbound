import sys
import os
import json

sys.path.insert(0, os.path.abspath("src"))
import unittest
from deepreach.models import Advisory, Finding, ScanResult, DefSite
from deepreach.report.json_fmt import generate_json_report


class TestJsonReport(unittest.TestCase):
    def setUp(self):
        self.advisory = Advisory(
            cve_id="CVE-2026-3333",
            ecosystem="pip",
            package="django",
            vulnerable_version_range="<4.2.11",
            vulnerable_functions=["query"],
            fix_version="4.2.11",
            severity="high",
        )
        self.def_site = DefSite(
            file="views.py", line=15, name="index", exported=True
        )
        self.finding = Finding(
            advisory=self.advisory,
            reachable=True,
            confidence="high",
            call_path=[self.def_site],
            fix_version="4.2.11",
        )
        self.scan_result = ScanResult(
            meta={
                "target": "django_proj",
                "total_dependencies": 5,
                "vulnerable_packages": 1,
            },
            summary={
                "by_severity": {
                    "critical": 0,
                    "high": 1,
                    "medium": 0,
                    "low": 0,
                },
                "duration_ms": 150,
                "peak_rss_bytes": 1024,
            },
            findings=[self.finding],
        )

    def test_generate_json_report_deterministic(self):
        report_str = generate_json_report(self.scan_result)
        # Parse it back to check structure
        report = json.loads(report_str)

        # Check meta
        self.assertEqual(report["meta"]["tool"], "deepreach")
        self.assertEqual(report["meta"]["version"], "0.1.0")

        # Check summary
        self.assertEqual(report["summary"]["reachable"], 1)
        self.assertEqual(report["summary"]["unreachable"], 0)
        self.assertEqual(report["summary"]["by_severity"]["high"], 1)

        # Check findings
        self.assertEqual(len(report["findings"]), 1)
        finding_data = report["findings"][0]
        self.assertEqual(finding_data["cve_id"], "CVE-2026-3333")
        self.assertEqual(finding_data["package"], "django")
        self.assertEqual(finding_data["reachable"], True)
        self.assertEqual(len(finding_data["call_path"]), 1)
        self.assertEqual(finding_data["call_path"][0]["name"], "index")

    def test_json_report_deterministic_output(self):
        # Deterministic check (no whitespace, sorted keys)
        report_str_1 = generate_json_report(self.scan_result)
        report_str_2 = generate_json_report(self.scan_result)
        self.assertEqual(report_str_1, report_str_2)
        # Ensure no pretty-printed spaces or newlines in the middle
        self.assertNotIn("  ", report_str_1)
        self.assertTrue(report_str_1.endswith("\n"))
