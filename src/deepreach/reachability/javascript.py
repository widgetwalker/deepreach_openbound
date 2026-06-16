"""JavaScript reachability analyzer using tree-sitter."""

try:
    from tree_sitter import Language, Parser
    import tree_sitter_javascript as tsjavascript
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

from typing import List, Set
from ..models import DefSite, Edge
from .base import LanguageAdapter
from ..log import get_logger


logger = get_logger(__name__)


class JavaScriptLanguageAdapter(LanguageAdapter):
    """JavaScript/TypeScript language adapter using tree-sitter."""

    def __init__(self):
        if not TREE_SITTER_AVAILABLE:
            logger.warning("Tree-sitter not available, JavaScript parsing disabled")
            self.parser = None
            return
        
        try:
            # Load the JavaScript grammar
            JS_LANGUAGE = Language(tsjavascript.language())
            self.parser = Parser()
            self.parser.set_language(JS_LANGUAGE)
        except Exception as e:
            logger.error(f"Failed to initialize tree-sitter for JavaScript: {e}")
            self.parser = None

    def parse_file(self, file_path: str, content: str) -> tuple[List[DefSite], List[Edge]]:
        """Parse a JavaScript/TypeScript file and extract definitions and calls."""
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
            logger.error(f"Error parsing JavaScript file {file_path}: {e}")
            return [], []

    def _traverse_node(self, node, content: str, file_path: str, 
                      definitions: List[DefSite], edges: List[Edge]) -> None:
        """Recursively traverse AST nodes to extract definitions and edges."""
        # Function declarations
        if node.type in ["function_declaration", "generator_function_declaration"]:
            # Get function name
            name_node = node.child_by_field_name("name")
            if name_node:
                name = self._get_node_text(name_node, content)
                line_number = name_node.start_point[0] + 1  # Convert to 1-based line number
                
                # Check if exported (simplified check)
                exported = self._is_exported(node, content)
                
                definitions.append(DefSite(
                    file=file_path,
                    line=line_number,
                    name=name,
                    exported=exported
                ))
        
        # Function expressions (assigned to variables)
        elif node.type in ["variable_declarator", "assignment_expression"]:
            # Check if this is assigning a function
            value_node = node.child_by_field_name("value")
            if value_node and value_node.type in ["function", "arrow_function"]:
                # Get variable name
                name_node = node.child_by_field_name("name")
                if name_node:
                    name = self._get_node_text(name_node, content)
                    line_number = name_node.start_point[0] + 1
                    
                    # Check if exported
                    exported = self._is_exported(node, content)
                    
                    definitions.append(DefSite(
                        file=file_path,
                        line=line_number,
                        name=name,
                        exported=exported
                    ))
        
        # Arrow functions
        elif node.type == "arrow_function":
            # Check if it's assigned to a variable (handled in variable_declarator above)
            # or if it's a method definition
            pass
        
        # Method definitions in objects/classes
        elif node.type in ["method_definition", "class_method", "getter", "setter"]:
            name_node = node.child_by_field_name("name")
            if name_node:
                name = self._get_node_text(name_node, content)
                line_number = name_node.start_point[0] + 1
                
                # Check if exported (would need to check parent class/object export)
                exported = False  # Simplified
                
                definitions.append(DefSite(
                    file=file_path,
                    line=line_number,
                    name=name,
                    exported=exported
                ))
        
        # Call expressions
        elif node.type == "call_expression":
            # Get the function being called
            function_node = node.child_by_field_name("function")
            if function_node:
                # We would need to resolve what this function refers to
                # For now, we'll create a placeholder edge
                # In a full implementation, we would resolve imports and local functions
                line_number = node.start_point[0] + 1
                
                # This is a simplified placeholder - real implementation would:
                # 1. Resolve the function reference to a DefSite
                # 2. Create an Edge from the caller to the callee
                pass
        
        # Recursively traverse children
        for child in node.children:
            self._traverse_node(child, content, file_path, definitions, edges)

    def _get_node_text(self, node, content: str) -> str:
        """Extract text content from a tree-sitter node."""
        return content[node.start_byte:node.end_byte]

    def _is_exported(self, node, content: str) -> bool:
        """Check if a definition is exported (simplified)."""
        # This is a simplified check - in reality we'd need to check:
        # - ES6 export statements
        # - CommonJS module.exports/exports.*
        # - Assignment to exports
        # For now, return False as placeholder
        return False

    def get_file_extensions(self) -> List[str]:
        return [".js", ".jsx", ".ts", ".tsx"]

    def is_ignored_path(self, file_path: str) -> bool:
        ignored_patterns = [
            "node_modules/",
            ".git/",
            "dist/",
            "build/",
            "coverage/",
            ".next/",
            ".cache/"
        ]
        return any(pattern in file_path for pattern in ignored_patterns)