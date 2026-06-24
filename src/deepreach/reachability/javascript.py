"""JavaScript reachability analyzer using tree-sitter."""

from __future__ import annotations

try:
    from tree_sitter import Language, Parser
    import tree_sitter_javascript as tsjavascript

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

from ..models import DefSite, Edge
from .base import LanguageAdapter
from ..log import get_logger

logger = get_logger(__name__)


class JavaScriptLanguageAdapter(LanguageAdapter):
    """JavaScript/TypeScript language adapter using tree-sitter."""

    def __init__(self) -> None:
        if not TREE_SITTER_AVAILABLE:
            logger.warning("Tree-sitter not available, JavaScript parsing disabled")
            self.parser = None
            return

        try:
            js_language = Language(tsjavascript.language())
            self.parser = Parser()
            if hasattr(self.parser, "set_language"):
                self.parser.set_language(js_language)
            else:
                self.parser.language = js_language
        except Exception as e:
            logger.error(f"Failed to initialize tree-sitter for JavaScript: {e}")
            self.parser = None

    def parse_file(
        self, file_path: str, content: str
    ) -> tuple[list[DefSite], list[Edge]]:
        """Parse a JavaScript/TypeScript file and extract definitions and calls."""
        if not self.parser or not TREE_SITTER_AVAILABLE:
            return [], []

        try:
            tree = self.parser.parse(bytes(content, "utf8"))
            definitions: list[DefSite] = []
            edges: list[Edge] = []
            self._traverse_node(tree.root_node, content, file_path, definitions, edges)
            return definitions, edges
        except Exception as e:
            logger.error(f"Error parsing JavaScript file {file_path}: {e}")
            return [], []

    def _traverse_node(  # noqa: C901
        self,
        node,
        content: str,
        file_path: str,
        definitions: list[DefSite],
        edges: list[Edge],
    ) -> None:
        """Recursively traverse AST nodes to extract definitions and edges."""
        if node.type in ["function_declaration", "generator_function_declaration"]:
            name_node = node.child_by_field_name("name")
            if name_node:
                name = self._get_node_text(name_node, content)
                line_number = name_node.start_point[0] + 1
                exported = self._is_exported(node, content)
                definitions.append(
                    DefSite(
                        file=file_path, line=line_number, name=name, exported=exported
                    )
                )

        elif node.type in ["variable_declarator", "assignment_expression"]:
            value_node = node.child_by_field_name("value")
            if value_node and value_node.type in ["function", "arrow_function"]:
                name_node = node.child_by_field_name("name")
                if name_node:
                    name = self._get_node_text(name_node, content)
                    line_number = name_node.start_point[0] + 1
                    exported = self._is_exported(node, content)
                    definitions.append(
                        DefSite(
                            file=file_path,
                            line=line_number,
                            name=name,
                            exported=exported,
                        )
                    )

        elif node.type == "arrow_function":
            pass

        elif node.type in ["method_definition", "class_method", "getter", "setter"]:
            name_node = node.child_by_field_name("name")
            if name_node:
                name = self._get_node_text(name_node, content)
                line_number = name_node.start_point[0] + 1
                exported = False
                definitions.append(
                    DefSite(
                        file=file_path, line=line_number, name=name, exported=exported
                    )
                )

        elif node.type == "call_expression":
            function_node = node.child_by_field_name("function")
            if function_node:
                callee_ref = self._get_node_text(function_node, content)
                line_number = node.start_point[0] + 1
                caller = DefSite(
                    file=file_path, line=0, name="<global>", exported=False
                )
                edges.append(
                    Edge(caller=caller, callee_ref=callee_ref, line=line_number)
                )

        for child in node.children:
            self._traverse_node(child, content, file_path, definitions, edges)

    def _get_node_text(self, node, content: str) -> str:
        """Extract text content from a tree-sitter node."""
        return content[node.start_byte : node.end_byte]

    def _is_exported(self, node, content: str) -> bool:
        """Check if a definition is exported."""
        return False

    def get_file_extensions(self) -> list[str]:
        return [".js", ".jsx", ".ts", ".tsx"]

    def is_ignored_path(self, file_path: str) -> bool:
        ignored_patterns = [
            "node_modules/",
            ".git/",
            "dist/",
            "build/",
            "coverage/",
            ".next/",
            ".cache/",
        ]
        return any(pattern in file_path for pattern in ignored_patterns)
