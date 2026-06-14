"""NPM lockfile parser (package-lock.json v1/v2/v3)."""

import json
from typing import List, Tuple, Optional



class NpmLockfileParser:
    """Parser for NPM package-lock.json files."""

    def detect(self, content: str) -> bool:
        """Detect if content is a package-lock.json file."""
        try:
            data = json.loads(content)
            return (
                isinstance(data, dict) and
                "lockfileVersion" in data and
                "packages" in data
            )
        except (json.JSONDecodeError, TypeError):
            return False

    def parse(self, content: str) -> List[Tuple[str, str, str, Optional[str], List[str]]]:  # noqa: E501
        """Parse package-lock.json and return dependency tuples."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in package-lock.json: {e}")

        if not self.detect(content):
            raise ValueError("Not a valid package-lock.json file")

        dependencies: List[Tuple[str, str, str, Optional[str], List[str]]] = []
        lockfile_version = data.get("lockfileVersion", 0)
        packages = data.get("packages", {})

        # Handle different lockfile versions
        if lockfile_version >= 2:
            # v2/v3 format: packages object with paths as keys
            for path, package_info in packages.items():
                if path == "" or not path.startswith("node_modules/"):
                    # Skip root package or non-dependency paths
                    continue

                # Extract package name from path (e.g., node_modules/axios)
                parts = path.split("node_modules/")
                name = parts[-1]
                version = package_info.get("version", "")

                if not version:
                    continue

                # Determine parent from path
                parent_name = None
                dep_path: List[str] = []

                # For now, we'll keep it simple - in a full implementation,
                # we would trace dependencies through the "dependencies" field
                dependencies.append(("npm", name, version, parent_name, dep_path))
        else:
            # v1 format: dependencies object at root
            deps = data.get("dependencies", {})
            for name, version_info in deps.items():
                if isinstance(version_info, dict):
                    version = version_info.get("version", "")
                else:
                    version = str(version_info)

                if version:
                    dependencies.append(("npm", name, version, None, []))

        return dependencies
