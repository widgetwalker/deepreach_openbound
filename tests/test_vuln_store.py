import sys
import os
sys.path.insert(0, os.path.abspath('src'))
import unittest
import tempfile
from pathlib import Path
from deepreach.models import Advisory
from deepreach.vuln_federation.store import VulnerabilityStore

class TestVulnerabilityStore(unittest.TestCase):
    def setUp(self):
        # Create a temp file for the db
        self.db_fd, self.db_path = tempfile.mkstemp()
        self.store = VulnerabilityStore(db_path=Path(self.db_path))

    def tearDown(self):
        del self.store
        import gc
        gc.collect()
        try:
            os.close(self.db_fd)
        except OSError:
            pass
        try:
            os.unlink(self.db_path)
        except OSError:
            pass

    def test_upsert_and_retrieve_advisory(self):
        advisory = Advisory(
            cve_id="CVE-2026-9999",
            ecosystem="pip",
            package="flask",
            vulnerable_version_range="<2.3.3",
            vulnerable_functions=["render_template"],
            fix_version="2.3.3",
            severity="high"
        )
        self.store.upsert_advisory(advisory, source="OSV")

        advisories = self.store.get_advisories("pip", "flask")
        self.assertEqual(len(advisories), 1)
        retrieved = advisories[0]
        self.assertEqual(retrieved.cve_id, "CVE-2026-9999")
        self.assertEqual(retrieved.ecosystem, "pip")
        self.assertEqual(retrieved.package, "flask")
        self.assertEqual(retrieved.vulnerable_version_range, "<2.3.3")
        self.assertEqual(retrieved.vulnerable_functions, ["render_template"])
        self.assertEqual(retrieved.fix_version, "2.3.3")
        self.assertEqual(retrieved.severity, "high")

        # Test retrieve by CVE ID
        retrieved_by_cve = self.store.get_advisory_by_cve("CVE-2026-9999")
        self.assertIsNotNone(retrieved_by_cve)
        self.assertEqual(retrieved_by_cve.cve_id, "CVE-2026-9999")

    def test_cache_stats_and_clear(self):
        advisory = Advisory(
            cve_id="CVE-2026-9999",
            ecosystem="pip",
            package="flask",
            vulnerable_version_range="<2.3.3",
            vulnerable_functions=["render_template"],
            fix_version="2.3.3",
            severity="high"
        )
        self.store.upsert_advisory(advisory, source="OSV")

        stats = self.store.get_cache_stats()
        self.assertEqual(stats["total_advisories"], 1)
        self.assertEqual(stats["unique_packages"], 1)

        self.store.clear_cache()
        stats_cleared = self.store.get_cache_stats()
        self.assertEqual(stats_cleared["total_advisories"], 0)

if __name__ == '__main__':
    unittest.main()
