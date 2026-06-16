"""Python reachability analyzer using tree-sitter."""

try:
    from tree_sitter import Language, Parser
    import tree_sitter_python as tspython

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

from typing import List
from ..models import DefSite, Edge
from .base import LanguageAdapter
from ..log import get_logger


logger = get_logger(__name__)


class PythonLanguageAdapter(LanguageAdapter):
    """Python language adapter using tree-sitter."""

    def __init__(self):
        if not TREE_SITTER_AVAILABLE:
            logger.warning("Tree-sitter not available, Python parsing disabled")
            self.parser = None
            return

        try:
            # Load the Python grammar
            PYTHON_LANGUAGE = Language(tspython.language())
            self.parser = Parser()
            if hasattr(self.parser, "set_language"):
                self.parser.set_language(PYTHON_LANGUAGE)
            else:
                self.parser.language = PYTHON_LANGUAGE
        except Exception as e:
            logger.error(f"Failed to initialize tree-sitter for Python: {e}")
            self.parser = None

    def parse_file(
        self, file_path: str, content: str
    ) -> tuple[List[DefSite], List[Edge]]:  # noqa: E501
        """Parse a Python file and extract definitions and calls."""
        if not self.parser or not TREE_SITTER_AVAILABLE:
            return [], []

        try:
            tree = self.parser.parse(bytes(content, "utf8"))
            root_node = tree.root_node

            definitions: List[DefSite] = []
            edges: List[Edge] = []

            # Traverse the AST to find function definitions and call expressions
            self._traverse_node(root_node, content, file_path, definitions, edges)

            return definitions, edges

        except Exception as e:
            logger.error(f"Error parsing Python file {file_path}: {e}")
            return [], []

    def _traverse_node(
        self,
        node,
        content: str,
        file_path: str,
        definitions: List[DefSite],
        edges: List[Edge],
    ) -> None:
        """Recursively traverse AST nodes to extract definitions and edges."""
        # Function definitions
        if node.type in ["function_definition", "async_function_definition"]:
            # Get function name
            name_node = node.child_by_field_name("name")
            if name_node:
                name = self._get_node_text(name_node, content)
                line_number = (
                    name_node.start_point[0] + 1
                )  # Convert to 1-based line number  # noqa: E501

                # Check if exported (in Python, this would mean not starting with _)
                # and is in __all__ if defined
                exported = not name.startswith("_")  # Simplified

                definitions.append(
                    DefSite(
                        file=file_path, line=line_number, name=name, exported=exported
                    )
                )

        # Class definitions
        elif node.type == "class_definition":
            name_node = node.child_by_field_name("name")
            if name_node:
                name = self._get_node_text(name_node, content)
                line_number = name_node.start_point[0] + 1

                # Classes are considered "exported" if not private
                exported = not name.startswith("_")

                definitions.append(
                    DefSite(
                        file=file_path, line=line_number, name=name, exported=exported
                    )
                )

        # Call expressions
        elif node.type == "call":
            # Get the function being called
            function_node = node.child_by_field_name("function")
            if function_node:
                callee_ref = self._get_node_text(function_node, content)
                line_number = node.start_point[0] + 1

                # Simplified: Use a generic caller site
                caller = DefSite(
                    file=file_path, line=0, name="<module>", exported=False
                )
                edges.append(
                    Edge(caller=caller, callee_ref=callee_ref, line=line_number)
                )

        # Recursively traverse children
        for child in node.children:
            self._traverse_node(child, content, file_path, definitions, edges)

    def _get_node_text(self, node, content: str) -> str:
        """Extract text content from a tree-sitter node."""
        return content[node.start_byte : node.end_byte]

    def get_file_extensions(self) -> List[str]:
        return [".py"]

    def is_ignored_path(self, file_path: str) -> bool:
        ignored_patterns = [
            "__pycache__/",
            ".git/",
            "dist/",
            "build/",
            "coverage/",
            ".venv/",
            "venv/",
            "ENV/",
            ".cache/",
            ".mypy_cache/",
            ".pytest_cache/",
            "htmlcov/",
        ]
        return any(pattern in file_path for pattern in ignored_patterns)
