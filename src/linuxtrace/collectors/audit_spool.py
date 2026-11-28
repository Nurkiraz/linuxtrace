import json
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from linuxtrace.collectors.audit import AuditCollector
from linuxtrace.models.raw_event import RawEvent
from linuxtrace.parsers.audit import parse_audit_record
from linuxtrace.parsers.audit_groups import (
    AuditEventGroup,
    AuditEvidence,
)

SPOOL_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_groups (
    id INTEGER PRIMARY KEY,
    group_key TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS audit_records (
    id INTEGER PRIMARY KEY,
    group_id INTEGER NOT NULL,
    raw_json TEXT NOT NULL,
    FOREIGN KEY(group_id) REFERENCES audit_groups(id)
);

CREATE INDEX IF NOT EXISTS idx_audit_records_group
ON audit_records(group_id, id);
"""


@dataclass
class AuditSpoolResult:
    records_read: int = 0
    groups_read: int = 0
    errors: list[str] = field(default_factory=list)


def spool_audit_records(
    root: Path,
    spool_path: Path,
) -> AuditSpoolResult:
    """Stream audit records into a temporary SQLite database.

    The caller owns the spool file and must remove it when finished.
    This function never modifies source evidence.
    """
    result = AuditSpoolResult()
    collector = AuditCollector(root)

    spool_path = Path(spool_path)
    spool_path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(spool_path) as connection:
        connection.executescript(SPOOL_SCHEMA)

        for raw in collector.collect():
            result.records_read += 1

            try:
                parsed = parse_audit_record(raw.raw_log)
            except ValueError as exc:
                result.errors.append(f"{raw.source_file}:{raw.source_line}: {exc}")
                continue

            if parsed is None:
                result.errors.append(
                    f"{raw.source_file}:{raw.source_line}: Unrecognized audit record"
                )
                continue

            key = json.dumps(
                [
                    parsed.node,
                    str(parsed.timestamp),
                    parsed.serial,
                ],
                ensure_ascii=False,
                separators=(",", ":"),
            )

            connection.execute(
                """
                INSERT OR IGNORE INTO audit_groups(group_key)
                VALUES (?)
                """,
                (key,),
            )

            group_id = connection.execute(
                """
                SELECT id
                FROM audit_groups
                WHERE group_key = ?
                """,
                (key,),
            ).fetchone()[0]

            connection.execute(
                """
                INSERT INTO audit_records(group_id, raw_json)
                VALUES (?, ?)
                """,
                (group_id, raw.model_dump_json()),
            )

        result.errors.extend(collector.errors)

        result.groups_read = connection.execute("SELECT COUNT(*) FROM audit_groups").fetchone()[0]

    return result


def iter_spooled_groups(
    spool_path: Path,
) -> Iterator[AuditEventGroup]:
    """Yield one complete audit event group at a time."""

    with sqlite3.connect(spool_path) as connection:
        group_rows = connection.execute(
            """
            SELECT id, group_key
            FROM audit_groups
            ORDER BY id
            """
        )

        for group_id, key_json in group_rows:
            node, timestamp_str, serial = json.loads(key_json)

            from decimal import Decimal

            group = AuditEventGroup(
                node=node,
                timestamp=Decimal(timestamp_str),
                serial=serial,
            )

            records = connection.execute(
                """
                SELECT raw_json
                FROM audit_records
                WHERE group_id = ?
                ORDER BY id
                """,
                (group_id,),
            )

            for (raw_json,) in records:
                raw = RawEvent.model_validate_json(raw_json)
                parsed = parse_audit_record(raw.raw_log)

                if parsed is None:
                    raise ValueError("Stored audit record could not be parsed")

                group.records.append(AuditEvidence(raw=raw, parsed=parsed))

            yield group
