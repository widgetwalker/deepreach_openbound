"""TypeScript reachability analyzer using tree-sitter."""

from __future__ import annotations

from .javascript import JavaScriptLanguageAdapter


class TypeScriptLanguageAdapter(JavaScriptLanguageAdapter):
    """TypeScript language adapter reusing the JavaScript grammar."""

    def get_file_extensions(self) -> list[str]:
        return [".ts", ".tsx"]
