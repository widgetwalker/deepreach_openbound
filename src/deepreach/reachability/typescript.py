"""TypeScript reachability analyzer using tree-sitter."""

from typing import List

# TypeScript uses the same tree-sitter grammar as JavaScript in many cases
# For now, we'll reuse the JavaScript adapter
from .javascript import JavaScriptLanguageAdapter


class TypeScriptLanguageAdapter(JavaScriptLanguageAdapter):
    """TypeScript language adapter - reuses JavaScript grammar for now."""

    def get_file_extensions(self) -> List[str]:
        return [".ts", ".tsx"]

    # Note: In a full implementation, we would use tree-sitter-typescript
    # which provides more accurate TypeScript-specific parsing
