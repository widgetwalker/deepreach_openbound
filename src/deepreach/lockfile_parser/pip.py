"""PIP lockfile parser (requirements.txt)."""

import re
from typing import List, Tuple, Optional

from .base import EcosystemAdapter


class PipLockfileParser:
    """Parser for PIP requirements.txt files."""

    def detect(self, content: str) -> bool:
        """Detect if content looks like a requirements.txt file."""
        # Simple heuristic: lines with package==version or package>=version etc.
        lines = content.strip().split('\n')
        if not lines:
            return False
        
        # Check if first few lines look like requirements
        req_pattern = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*(?:[=<>!~]+.*)?$')
        match_count = 0
        for line in lines[:10]:  # Check first 10 lines
            line = line.strip()
            if line and not line.startswith('#') and req_pattern.match(line):
                match_count += 1
        
        return match_count > 0

    def parse(self, content: str) -> List[Tuple[str, str, str, Optional[str], List[str]]]:
        """Parse requirements.txt and return dependency tuples."""
        dependencies = []
        lines = content.strip().split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            
            # Handle -r, -e, --editable options (simplified)
            if line.startswith('-r') or line.startswith('--requirement') or \
               line.startswith('-e') or line.startswith('--editable') or \
               line.startswith('-c') or line.startswith('--constraint'):
                # In a full implementation, we would process these
                continue
            
            # Parse package specification
            # Patterns: package==version, package>=version, package<=version, etc.
            # Also handles package@url, package[extra]==version, etc.
            match = re.match(r'^([a-zA-Z0-9][a-zA-Z0-9._-]*)', line)
            if not match:
                continue
            
            name = match.group(1)
            
            # Extract version if present
            version_match = re.search(r'[=<>!~]+([^\\s]+)', line)
            version = version_match.group(1) if version_match else ""
            
            # Clean up version (remove whitespace, handle url specs)
            version = version.strip()
            if version.startswith(('http://', 'https://', 'git+', 'file://')):
                # For URL dependencies, we might not have a version
                version = ""
            
            dependencies.append(("pip", name, version, None, []))
        
        return dependencies