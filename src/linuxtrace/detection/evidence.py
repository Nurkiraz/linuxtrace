"""Read-only verification of finding-to-event references."""

import sqlite3
from pathlib import Path

from pydantic import ValidationError

from linuxtrace.detection.models import SecurityFinding
from linuxtrace.models.normalized_event import NormalizedEvent


def inspect_finding_events(
    db_path: Path,
    finding: SecurityFinding,
) -> dict:
    """Inspect linked events without modifying forensic records."""

    db_path = Path(db_path)

    if not db_path.is_file():
        raise ValueError(f"Database not found: {db_path}")

    connection = sqlite3.connect(
        db_path.resolve().as_uri() + "?mode=ro",
        uri=True,
    )

    try:
        connection.row_factory = sqlite3.Row

        related = list(dict.fromkeys(finding.related_event_ids))
        found = []
        missing = []
        invalid = []

        for event_id in related:
            row = connection.execute(
                """
                SELECT event_id, event_json
                FROM events
                WHERE event_id = ?
                """,
                (event_id,),
            ).fetchone()

            if row is None:
                missing.append(event_id)
                continue

            try:
                event = NormalizedEvent.model_validate_json(row["event_json"])
            except (ValidationError, ValueError):
                invalid.append(event_id)
                continue

            if event.event_id != row["event_id"]:
                invalid.append(event_id)
                continue

            found.append(
                {
                    "event_id": event.event_id,
                    "timestamp": (event.timestamp.isoformat() if event.timestamp else None),
                    "event_type": event.event_type,
                    "hostname": event.hostname,
                    "username": event.username,
                    "source_ip": event.source_ip,
                    "source_file": event.raw_event.source_file,
                    "source_line": event.raw_event.source_line,
                    "description": event.description,
                }
            )

        return {
            "finding_id": finding.finding_id,
            "expected_events": len(related),
            "verified_events": len(found),
            "missing_event_ids": missing,
            "invalid_event_ids": invalid,
            "all_references_valid": not missing and not invalid,
            "events": found,
        }

    finally:
        connection.close()
