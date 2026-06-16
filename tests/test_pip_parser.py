import sys
import os

sys.path.insert(0, os.path.abspath("src"))
import unittest
from deepreach.lockfile_parser.pip import PipLockfileParser


class TestPipParser(unittest.TestCase):
    def test_parse_requirements(self):
        req_path = os.path.join(
            "examples", "vulnerable-app", "python", "requirements.txt"
        )
        with open(req_path, "r") as f:
            reqdata = f.read()
        parser = PipLockfileParser()
        deps = parser.parse(reqdata)
        self.assertIsInstance(deps, list)
        # We expect at least two dependencies: requests and flask
        self.assertGreaterEqual(len(deps), 2)
        # Check structure of a tuple: (ecosystem, name, version, parent_name, dep_path)
        for dep in deps:
            self.assertEqual(len(dep), 5)
            self.assertEqual(dep[0], "pip")  # ecosystem
            self.assertIsInstance(dep[1], str)  # name
            self.assertIsInstance(dep[2], str)  # version
            self.assertIsInstance(dep[3], (str, type(None)))  # parent_name
            self.assertIsInstance(dep[4], list)  # dep_path
        # Check that we have requests and flask
        dep_names = [dep[1] for dep in deps]
        self.assertIn("requests", dep_names)
        self.assertIn("flask", dep_names)
        # Check versions
        for dep in deps:
            if dep[1] == "requests":
                self.assertEqual(dep[2], "2.28.1")
            elif dep[1] == "flask":
                self.assertEqual(dep[2], "2.3.2")


if __name__ == "__main__":
    unittest.main()
