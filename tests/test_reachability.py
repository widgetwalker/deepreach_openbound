import sys
import os

sys.path.insert(0, os.path.abspath("src"))
import unittest
from deepreach.reachability.python_lang import PythonLanguageAdapter
from deepreach.reachability.javascript import JavaScriptLanguageAdapter
from deepreach.reachability.typescript import TypeScriptLanguageAdapter


class TestReachability(unittest.TestCase):
    def test_python_language_adapter(self):
        adapter = PythonLanguageAdapter()
        if not adapter.parser:
            self.skipTest("tree-sitter-python not available")

        code = """
def hello_world():
    print("hello")

class Greeter:
    def greet(self):
        hello_world()
"""
        defs, edges = adapter.parse_file("test.py", code)

        # Verify definitions
        def_names = [d.name for d in defs]
        self.assertIn("hello_world", def_names)
        self.assertIn("Greeter", def_names)
        self.assertIn("greet", def_names)

        # Verify get_file_extensions
        self.assertEqual(adapter.get_file_extensions(), [".py"])

    def test_javascript_language_adapter(self):
        adapter = JavaScriptLanguageAdapter()
        if not adapter.parser:
            self.skipTest("tree-sitter-javascript not available")

        code = """
function calculate(x) {
    return x * 2;
}

const format = (val) => {
    return `Val: ${val}`;
};

class Logger {
    log(msg) {
        console.log(msg);
    }
}
"""
        defs, edges = adapter.parse_file("test.js", code)

        # Verify definitions
        def_names = [d.name for d in defs]
        self.assertIn("calculate", def_names)
        self.assertIn("format", def_names)
        self.assertIn("log", def_names)

        # Verify extensions
        self.assertEqual(adapter.get_file_extensions(), [".js", ".jsx", ".ts", ".tsx"])

    def test_typescript_language_adapter(self):
        adapter = TypeScriptLanguageAdapter()
        self.assertEqual(adapter.get_file_extensions(), [".ts", ".tsx"])


if __name__ == "__main__":
    unittest.main()
