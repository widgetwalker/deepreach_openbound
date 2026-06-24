"""OSV.dev adapter for vulnerability federation."""

from __future__ import annotations

from datetime import timedelta

import httpx

from ..models import Advisory, Severity
from .base import SourceAdapter
from ..log import get_logger

logger = get_logger(__name__)

_ECOSYSTEM_MAP: dict[str, str] = {
    "npm": "npm",
    "pip": "PyPI",
}


class OSVAdapter(SourceAdapter):
    """Adapter for the OSV.dev vulnerability database."""

    def __init__(self) -> None:
        self.base_url = "https://api.osv.dev/v1"
        self.cache_timeout = timedelta(hours=6)

    def get_name(self) -> str:
        return "OSV"

    def fetch_advisories(
        self, ecosystem: str, package: str, version: str
    ) -> list[Advisory]:
        """Fetch advisories for a specific package version from OSV.dev."""
        try:
            osv_ecosystem = _ECOSYSTEM_MAP.get(ecosystem)
            if not osv_ecosystem:
                logger.warning(f"Unsupported ecosystem for OSV: {ecosystem}")
                return []

            query = {
                "version": version,
                "package": {"name": package, "ecosystem": osv_ecosystem},
            }

            response = httpx.post(f"{self.base_url}/query", json=query, timeout=10.0)
            response.raise_for_status()

            data = response.json()
            advisories: list[Advisory] = []

            for vuln in data.get("vulns", []):
                advisory = self._parse_osv_vulnerability(vuln, ecosystem)
                if advisory:
                    advisories.append(advisory)

            return advisories

        except Exception as e:
            logger.error(f"Error fetching from OSV.dev: {e}")
            return []

    def _parse_osv_vulnerability(
        self, vuln: dict, ecosystem: str
    ) -> Advisory | None:
        """Parse an OSV vulnerability into an Advisory."""
        try:
            cve_id = vuln.get("id", "")
            if not cve_id.startswith("CVE-"):
                aliases = vuln.get("aliases", [])
                cve_candidates = [a for a in aliases if a.startswith("CVE-")]
                cve_id = cve_candidates[0] if cve_candidates else cve_id

            affected = vuln.get("affected", [])
            package_name = ""
            version_range = ""
            vulnerable_functions: list[str] | None = None

            osv_ecosystem = _ECOSYSTEM_MAP.get(ecosystem)

            for aff in affected:
                pkg_info = aff.get("package", {})
                if pkg_info.get("ecosystem") != osv_ecosystem:
                    continue
                if package_name and pkg_info.get("name") != package_name:
                    continue

                package_name = pkg_info.get("name", "")

                ranges = aff.get("ranges", [])
                if ranges:
                    range_info = ranges[0]
                    version_range = (
                        range_info.get("introduced", "")
                        + " - "
                        + range_info.get("fixed", "")
                    )
                elif aff.get("versions"):
                    versions = aff["versions"]
                    if versions:
                        version_range = f"== {versions[0]}"
                break

            if not package_name:
                return None

            return Advisory(
                cve_id=cve_id,
                ecosystem=ecosystem,
                package=package_name,
                vulnerable_version_range=version_range,
                vulnerable_functions=vulnerable_functions,
                fix_version=None,
                severity=Severity.UNKNOWN,
                summary=vuln.get("summary"),
                details=vuln.get("details"),
            )

        except Exception as e:
            logger.error(f"Error parsing OSV vulnerability: {e}")
            return None

    def update_cache(self) -> bool:
        """Update OSV cache via on-demand fetching."""
        logger.info("OSV adapter update_cache called (on-demand caching)")
        return True
