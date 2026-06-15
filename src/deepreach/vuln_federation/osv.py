"""OSV.dev adapter for vulnerability federation."""

from typing import List, Optional
from datetime import timedelta

import httpx

from ..models import Advisory
from .base import SourceAdapter
from ..log import get_logger


logger = get_logger(__name__)


class OSVAdapter(SourceAdapter):
    """Adapter for OSV.dev vulnerability database."""

    def __init__(self):
        self.base_url = "https://api.osv.dev/v1"
        self.cache_timeout = timedelta(hours=6)  # Cache for 6 hours

    def get_name(self) -> str:
        return "OSV"

    def fetch_advisories(self, ecosystem: str, package: str, version: str) -> List[Advisory]:  # noqa: E501
        """Fetch advisories for a specific package version from OSV.dev."""
        try:
            # Map our ecosystem names to OSV format
            osv_ecosystem = {
                "npm": "npm",
                "pip": "PyPI"
            }.get(ecosystem)

            if not osv_ecosystem:
                logger.warning(f"Unsupported ecosystem for OSV: {ecosystem}")
                return []

            # Query OSV.dev for advisories
            query = {
                "version": version,
                "package": {
                    "name": package,
                    "ecosystem": osv_ecosystem
                }
            }

            response = httpx.post(
                f"{self.base_url}/query",
                json=query,
                timeout=10.0
            )
            response.raise_for_status()

            data = response.json()
            advisories = []

            for vuln in data.get("vulns", []):
                advisory = self._parse_osv_vulnerability(vuln, ecosystem)
                if advisory:
                    advisories.append(advisory)

            return advisories

        except Exception as e:
            logger.error(f"Error fetching from OSV.dev: {e}")
            return []

    def _parse_osv_vulnerability(self, vuln: dict, ecosystem: str) -> Optional[Advisory]:  # noqa: C901, E501
        """Parse an OSV vulnerability into our Advisory format."""
        try:
            # Extract basic info
            cve_id = vuln.get("id", "")
            # If not a CVE, try to find one in aliases
            if not cve_id.startswith("CVE-"):
                aliases = vuln.get("aliases", [])
                cve_candidates = [
                    alias for alias in aliases if alias.startswith("CVE-")
                ]
                cve_id = cve_candidates[0] if cve_candidates else cve_id

            # Extract package info from affected entries
            affected = vuln.get("affected", [])
            package_name = ""
            version_range = ""
            vulnerable_functions = None

            for aff in affected:
                if (
                    aff.get("package", {}).get("name") == package_name
                    or not package_name
                ):
                    pkg_info = aff.get("package", {})
                    if pkg_info.get("ecosystem") == ({
                        "npm": "npm",
                        "pip": "PyPI"
                    }.get(ecosystem)):
                        package_name = pkg_info.get("name", "")

                        # Get version range from ranges or events
                        ranges = aff.get("ranges", [])
                        if ranges:
                            # Take the first range for simplicity
                            range_info = ranges[0]
                            version_range = range_info.get("introduced", "") + \
                                           " - " + range_info.get("fixed", "")
                        elif aff.get("versions"):
                            # Specific versions affected
                            versions = aff.get("versions", [])
                            if versions:
                                version_range = f"== {versions[0]}"  # Simplified

                        # Extract vulnerable functions
                        vuln_functions: List[str] = []
                        for ref in aff.get("references", []):
                            # OSV doesn't always have function-level details
                            # This would need to be enhanced based on actual data
                            pass

                        if vuln_functions:
                            vulnerable_functions = vuln_functions
                        break

            if not package_name:
                return None

            # Extract severity (OSV doesn't always have CVSS)
            severity = "unknown"  # Default
            # In a full implementation, we would parse CVSS scores from
            # database_specific

            # Extract fix version
            fix_version = None
            # Look for fixed version in ranges or database_specific

            return Advisory(
                cve_id=cve_id,
                ecosystem=ecosystem,
                package=package_name,
                vulnerable_version_range=version_range,
                vulnerable_functions=vulnerable_functions,
                fix_version=fix_version,
                severity=severity
            )

        except Exception as e:
            logger.error(f"Error parsing OSV vulnerability: {e}")
            return None

    def update_cache(self) -> bool:
        """Update OSV cache - in a full implementation this would batch download."""
        # For now, we rely on on-demand fetching with caching in the store
        # A full implementation would periodically download recent advisories
        logger.info("OSV adapter update_cache called (on-demand caching)")
        return True
