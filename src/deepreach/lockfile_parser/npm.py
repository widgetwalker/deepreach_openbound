"""NPM lockfile parser (package-lock.json v1/v2/v3)."""

from __future__ import annotations

import json


class NpmLockfileParser:
    """Parser for NPM package-lock.json files."""

    def detect(self, content: str) -> bool:
        """Detect if content is a package-lock.json file."""
        try:
            data = json.loads(content)
            return (
                isinstance(data, dict)
                and "lockfileVersion" in data
                and "packages" in data
            )
        except (json.JSONDecodeError, TypeError):
            return False

    def parse(
        self, content: str
    ) -> list[tuple[str, str, str, str | None, list[str]]]:
        """Parse package-lock.json and return dependency tuples."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in package-lock.json: {e}")

        if not self.detect(content):
            raise ValueError("Not a valid package-lock.json file")

        dependencies: list[tuple[str, str, str, str | None, list[str]]] = []
        lockfile_version = data.get("lockfileVersion", 0)
        packages = data.get("packages", {})

        if lockfile_version >= 2:
            for path, package_info in packages.items():
                if path == "" or not path.startswith("node_modules/"):
                    continue

                parts = path.split("node_modules/")
                name = parts[-1]
                version = package_info.get("version", "")

                if not version:
                    continue

                parent_name = None
                dep_path: list[str] = []

                dependencies.append(("npm", name, version, parent_name, dep_path))
        else:
            deps = data.get("dependencies", {})
            for name, version_info in deps.items():
                if isinstance(version_info, dict):
                    version = version_info.get("version", "")
                else:
                    version = str(version_info)

                if version:
                    dependencies.append(("npm", name, version, None, []))

        return dependencies
