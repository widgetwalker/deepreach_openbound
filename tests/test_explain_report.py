import sys
import os

sys.path.insert(0, os.path.abspath("src"))
import unittest
from deepreach.models import Advisory, Finding, DefSite, Severity, Confidence
from deepreach.report.explain import generate_explain_report


class TestExplainReport(unittest.TestCase):
    def setUp(self):
        self.advisory_reachable = Advisory(
            cve_id="CVE-2026-explain-reachable",
            ecosystem="pip",
            package="flask",
            vulnerable_version_range="<2.3.3",
            vulnerable_functions=["render_template"],
            fix_version="2.3.3",
            severity=Severity.HIGH,
        )
        self.def_site = DefSite(
            file="app.py", line=12, name="home", exported=False
        )
        self.finding_reachable = Finding(
            advisory=self.advisory_reachable,
            reachable=True,
            confidence=Confidence.HIGH,
            call_path=[self.def_site],
            fix_version="2.3.3",
        )

        self.advisory_unreachable = Advisory(
            cve_id="CVE-2026-explain-unreachable",
            ecosystem="npm",
            package="express",
            vulnerable_version_range="<4.19.0",
            vulnerable_functions=["serve"],
            fix_version="4.19.0",
            severity=Severity.MEDIUM,
        )
        self.finding_unreachable = Finding(
            advisory=self.advisory_unreachable,
            reachable=False,
            confidence=Confidence.LOW,
            call_path=[],
            fix_version="4.19.0",
        )

        self.findings = [self.finding_reachable, self.finding_unreachable]

    def test_generate_explain_report_reachable(self):
        report = generate_explain_report(
            self.findings, "CVE-2026-explain-reachable"
        )
        self.assertIn("Explanation for CVE-2026-explain-reachable", report)
        self.assertIn("Package: flask", report)
        self.assertIn("Reachable: YES", report)
        self.assertIn("Call path to vulnerable function:", report)
        self.assertIn("1. home()", report)
        self.assertIn("   File: app.py:12", report)

    def test_generate_explain_report_unreachable(self):
        report = generate_explain_report(
            self.findings, "CVE-2026-explain-unreachable"
        )
        self.assertIn("Explanation for CVE-2026-explain-unreachable", report)
        self.assertIn("Package: express", report)
        self.assertIn("Reachable: NO", report)
        self.assertIn(
            "This vulnerability is not reachable from any entry point.",
            report
        )

    def test_generate_explain_report_not_found(self):
        report = generate_explain_report(self.findings, "CVE-2026-nonexistent")
        self.assertEqual(
            report, "CVE CVE-2026-nonexistent not found in scan results.\n"
        )
