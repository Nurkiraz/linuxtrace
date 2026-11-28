"""SQLite persistence for security detection findings."""

import sqlite3
from contextlib import closing
from pathlib import Path

from linuxtrace.detection.models import FindingSeverity, SecurityFinding
from linuxtrace.storage.database import Database

FINDINGS_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    source_ip TEXT,
    finding_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_rule
    ON findings(rule_id);

CREATE INDEX IF NOT EXISTS idx_findings_time
    ON findings(start_time);

CREATE INDEX IF NOT EXISTS idx_findings_severity
    ON findings(severity);
"""


class FindingRepository:
    """Store and retrieve security findings without changing events."""

    def __init__(self, database: Database):
        self.database = database

    def initialize(self) -> None:
        """Create detection tables and indexes when needed."""
        if not Path(self.database.path).is_file():
            raise FileNotFoundError(f"Database not found: {self.database.path}")

        with closing(self.database.connect()) as connection:
            connection.executescript(FINDINGS_SCHEMA)

    def save(self, finding: SecurityFinding) -> bool:
        """Save a finding once; reject conflicting IDs."""

        payload = finding.model_dump_json()

        with closing(self.database.connect()) as connection:
            with connection:
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO findings (
                        finding_id, rule_id, severity,
                        start_time, end_time, source_ip, finding_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding.finding_id,
                        finding.rule_id,
                        finding.severity.value,
                        finding.start_time.isoformat(),
                        finding.end_time.isoformat(),
                        finding.source_ip,
                        payload,
                    ),
                )

                inserted = cursor.rowcount == 1

                if not inserted:
                    row = connection.execute(
                        """
                        SELECT finding_json
                        FROM findings
                        WHERE finding_id = ?
                        """,
                        (finding.finding_id,),
                    ).fetchone()

                    if row is None:
                        raise sqlite3.IntegrityError("Finding could not be stored")

                    existing = SecurityFinding.model_validate_json(row["finding_json"])

                    if existing != finding:
                        raise ValueError("Conflicting finding with identical ID")

                return inserted

    def get(self, finding_id: str) -> SecurityFinding | None:
        """Retrieve one security finding."""

        with closing(self.database.connect()) as connection:
            row = connection.execute(
                """
                SELECT finding_json
                FROM findings
                WHERE finding_id = ?
                """,
                (finding_id,),
            ).fetchone()

        if row is None:
            return None

        return SecurityFinding.model_validate_json(row["finding_json"])

    def list_findings(
        self,
        *,
        severity: FindingSeverity | None = None,
        limit: int = 100,
    ) -> list[SecurityFinding]:
        """List findings by time with optional severity filtering."""

        if not 1 <= limit <= 10000:
            raise ValueError("limit must be between 1 and 10000")

        conditions = []
        parameters = []

        if severity is not None:
            conditions.append("severity = ?")
            parameters.append(FindingSeverity(severity).value)

        where = "WHERE " + " AND ".join(conditions) if conditions else ""

        query = f"""
            SELECT finding_json
            FROM findings
            {where}
            ORDER BY start_time DESC, finding_id ASC
            LIMIT ?
        """

        parameters.append(limit)

        with closing(self.database.connect()) as connection:
            rows = connection.execute(query, parameters).fetchall()

        return [SecurityFinding.model_validate_json(row["finding_json"]) for row in rows]
