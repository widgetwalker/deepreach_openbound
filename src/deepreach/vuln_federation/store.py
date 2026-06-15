"""SQLite store for vulnerability advisories."""

import sqlite3
import json
from pathlib import Path
from typing import List, Optional

from ..models import Advisory
from ..config import get_vulns_db_path


class VulnerabilityStore:
    """Manages SQLite database for vulnerability advisories."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or get_vulns_db_path()
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS advisories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    ecosystem TEXT NOT NULL,
                    package TEXT NOT NULL,
                    version_range TEXT NOT NULL,
                    vulnerable_functions TEXT,  -- JSON array
                    fix_version TEXT,
                    severity TEXT NOT NULL,
                    source TEXT NOT NULL,  -- OSV, GHSA, NVD
                    raw_data TEXT,  -- JSON for debugging
                    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(cve_id, ecosystem, package, version_range, source)
                )
            """)

            # Create indexes for common queries
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_advisories_lookup
                ON advisories(ecosystem, package, severity)
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_advisories_cached
                ON advisories(cached_at)
            """)

            # Schema version tracking
            conn.execute("""
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY
                )
            """)

            # Insert initial schema version if not exists
            cursor = conn.execute("SELECT COUNT(*) FROM schema_version")
            if cursor.fetchone()[0] == 0:
                conn.execute("INSERT INTO schema_version (version) VALUES (1)")

    def upsert_advisory(
        self, advisory: Advisory, source: str, raw_data: Optional[dict] = None
    ) -> None:
        """Insert or update an advisory in the database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO advisories
                (cve_id, ecosystem, package, version_range, vulnerable_functions,
                 fix_version, severity, source, raw_data, cached_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                advisory.cve_id,
                advisory.ecosystem,
                advisory.package,
                advisory.vulnerable_version_range,
                json.dumps(advisory.vulnerable_functions)
                if advisory.vulnerable_functions
                else None,
                advisory.fix_version,
                advisory.severity,
                source,
                json.dumps(raw_data) if raw_data else None
            ))

    def get_advisories(self, ecosystem: str, package: str) -> List[Advisory]:
        """Get all advisories for a specific ecosystem and package."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT cve_id, ecosystem, package, version_range, vulnerable_functions,
                       fix_version, severity
                FROM advisories
                WHERE ecosystem = ? AND package = ?
                ORDER BY severity DESC, cve_id
            """, (ecosystem, package))

            advisories = []
            for row in cursor:
                advisory = Advisory(
                    cve_id=row["cve_id"],
                    ecosystem=row["ecosystem"],
                    package=row["package"],
                    vulnerable_version_range=row["version_range"],
                    vulnerable_functions=(
                        json.loads(row["vulnerable_functions"])
                        if row["vulnerable_functions"]
                        else None
                    ),
                    fix_version=row["fix_version"],
                    severity=row["severity"]
                )
                advisories.append(advisory)

            return advisories

    def get_advisory_by_cve(self, cve_id: str) -> Optional[Advisory]:
        """Get advisory by CVE ID."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT cve_id, ecosystem, package, version_range, vulnerable_functions,
                       fix_version, severity
                FROM advisories
                WHERE cve_id = ?
                LIMIT 1
            """, (cve_id,))

            row = cursor.fetchone()
            if row:
                return Advisory(
                    cve_id=row["cve_id"],
                    ecosystem=row["ecosystem"],
                    package=row["package"],
                    vulnerable_version_range=row["version_range"],
                    vulnerable_functions=(
                        json.loads(row["vulnerable_functions"])
                        if row["vulnerable_functions"]
                        else None
                    ),
                    fix_version=row["fix_version"],
                    severity=row["severity"]
                )
            return None

    def clear_cache(self) -> None:
        """Clear all cached advisories."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM advisories")
            conn.execute("VACUUM")

    def get_cache_stats(self) -> dict:
        """Get statistics about the cache."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT
                    COUNT(*) as total_count,
                    COUNT(DISTINCT ecosystem || ':' || package) as unique_packages,
                    MIN(cached_at) as oldest_entry,
                    MAX(cached_at) as newest_entry
                FROM advisories
            """)
            row = cursor.fetchone()

            return {
                "total_advisories": row[0] if row else 0,
                "unique_packages": row[1] if row else 0,
                "oldest_entry": row[2] if row else None,
                "newest_entry": row[3] if row else None
            }
