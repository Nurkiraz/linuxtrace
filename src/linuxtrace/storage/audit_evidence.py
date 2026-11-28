import hashlib
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path


class AuditEvidenceError(Exception):
    """Audit evidence could not be retrieved."""


@dataclass(frozen=True)
class AuditEvidenceRecord:
    event_id: str
    record_type: str
    audit_serial: int
    source_file: str
    source_line: int
    evidence_hash: str
    raw_log: str
    hash_valid: bool


def get_audit_evidence(
    db_path: Path,
    event_id: str,
) -> list[AuditEvidenceRecord]:
    """Read related audit evidence without modifying the database."""

    db_path = Path(db_path)

    if not db_path.is_file():
        raise AuditEvidenceError(f"Database does not exist: {db_path}")

    try:
        # Open read-only so a query cannot change evidence.
        with closing(
            sqlite3.connect(
                db_path.resolve().as_uri() + "?mode=ro",
                uri=True,
            )
        ) as connection:
            connection.row_factory = sqlite3.Row

            rows = connection.execute(
                """
                SELECT event_id, record_type, audit_serial,
                       source_file, source_line,
                       evidence_hash, raw_log
                FROM audit_event_evidence
                WHERE event_id = ?
                ORDER BY source_file, source_line, record_type
                """,
                (event_id,),
            ).fetchall()

    except sqlite3.Error as exc:
        raise AuditEvidenceError(f"Unable to read audit evidence: {exc}") from exc

    evidence = []

    for row in rows:
        raw_log = row["raw_log"]
        stored_hash = row["evidence_hash"]

        calculated_hash = hashlib.sha256(raw_log.encode("utf-8")).hexdigest()

        evidence.append(
            AuditEvidenceRecord(
                event_id=row["event_id"],
                record_type=row["record_type"],
                audit_serial=row["audit_serial"],
                source_file=row["source_file"],
                source_line=row["source_line"],
                evidence_hash=stored_hash,
                raw_log=raw_log,
                hash_valid=(calculated_hash == stored_hash),
            )
        )

    return evidence
