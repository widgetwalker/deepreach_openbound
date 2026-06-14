"""NPM lockfile parser (package-lock.json v1/v2/v3)."""

import json
import re
from typing import List, Tuple, Optional

from .base import EcosystemAdapter


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

    def parse(self, content: str) -> List[Tuple[str, str, str, Optional[str], List[str]]]:
        """Parse package-lock.json and return dependency tuples."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in package-lock.json: {e}")

        if not self.detect(content):
            raise ValueError("Not a valid package-lock.json file")

        dependencies = []
        lockfile_version = data.get("lockfileVersion", 0)
        packages = data.get("packages", {})

        # Handle different lockfile versions
        if lockfileVersion >= 2:
            # v2/v3 format: packages object with paths as keys
            for path, package_info in packages.items():
                if path == "":
                    # Skip root package
                    continue
                
                # Extract package name and version from path
                # Format: node_modules/<package_name>@<version> or node_modules/<scope>/<package_name>@<version>
                match = re.match(r"node_modules?/(.+)@([^/@]+)(?:/.*)?$", path)
                if not match:
                    continue
                
                name = match.group(1)
                version = match.group(2)
                
                # Determine parent from path
                parent_name = None
                dep_path = []
                
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