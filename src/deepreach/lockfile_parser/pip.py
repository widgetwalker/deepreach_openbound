"""PIP lockfile parser (requirements.txt)."""

from __future__ import annotations

import re


class PipLockfileParser:
    """Parser for PIP requirements.txt files."""

    def detect(self, content: str) -> bool:
        """Detect if content looks like a requirements.txt file."""
        lines = content.strip().split("\n")
        if not lines:
            return False

        req_pattern = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*(?:[=<>!~]+.*)?$")
        match_count = 0
        for line in lines[:10]:
            line = line.strip()
            if line and not line.startswith("#") and req_pattern.match(line):
                match_count += 1

        return match_count > 0

    def parse(
        self, content: str
    ) -> list[tuple[str, str, str, str | None, list[str]]]:
        """Parse requirements.txt and return dependency tuples."""
        dependencies: list[tuple[str, str, str, str | None, list[str]]] = []
        lines = content.strip().split("\n")

        for line_num, line in enumerate(lines, 1):
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if (
                line.startswith("-r")
                or line.startswith("--requirement")
                or line.startswith("-e")
                or line.startswith("--editable")
                or line.startswith("-c")
                or line.startswith("--constraint")
            ):
                continue

            match = re.match(r"^([a-zA-Z0-9][a-zA-Z0-9._-]*)", line)
            if not match:
                continue

            name = match.group(1)

            version_match = re.search(r"[=<>!~]+([^\\s]+)", line)
            version = version_match.group(1) if version_match else ""

            version = version.strip()
            if version.startswith(("http://", "https://", "git+", "file://")):
                version = ""

            dependencies.append(("pip", name, version, None, []))

        return dependencies
