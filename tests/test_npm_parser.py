import sys
import os

sys.path.insert(0, os.path.abspath("src"))
import unittest
from deepreach.lockfile_parser.npm import NpmLockfileParser


class TestNpmParser(unittest.TestCase):
    def test_parse_lockfile(self):
        lockfile_path = os.path.join(
            "examples", "vulnerable-app", "nodejs", "package-lock.json"
        )
        with open(lockfile_path, "r") as f:
            lockdata = f.read()
        parser = NpmLockfileParser()
        deps = parser.parse(lockdata)
        self.assertIsInstance(deps, list)
        # We expect at least one dependency
        self.assertGreaterEqual(len(deps), 1)
        # Check structure of a tuple: (ecosystem, name, version, parent_name, dep_path)
        for dep in deps:
            self.assertEqual(len(dep), 5)
            self.assertEqual(dep[0], "npm")  # ecosystem
            self.assertIsInstance(dep[1], str)  # name
            self.assertIsInstance(dep[2], str)  # version
            self.assertIsInstance(dep[3], (str, type(None)))  # parent_name
            self.assertIsInstance(dep[4], list)  # dep_path


if __name__ == "__main__":
    unittest.main()
