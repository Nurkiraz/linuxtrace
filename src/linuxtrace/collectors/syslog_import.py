import hashlib
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from linuxtrace.collectors.syslog import SyslogCollector
from linuxtrace.normalizers.event import normalize_event
from linuxtrace.parsers.system_log import parse_system_log
from linuxtrace.storage.database import Database
from linuxtrace.storage.event_repository import EventRepository

INSERT_EVENT_SQL = """
INSERT OR IGNORE INTO events (
    event_id, timestamp, timestamp_original,
    timezone, timestamp_confidence, hostname,
    source, source_file, source_line,
    event_category, event_type, severity,
    username, source_ip, destination_ip,
    process_name, process_id, command,
    outcome, description, evidence_hash,
    raw_log, event_json, collected_at
)
VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?
)
"""


@dataclass
class SyslogImportResult:
    read: int
    inserted: int
    errors: list[str]


class CollectionFailure(Exception):
    """Error requiring transaction rollback."""


def update_fingerprint(hasher, raw):
    """Fingerprint source records and their metadata."""
    data = raw.model_dump_json().encode("utf-8")
    hasher.update(len(data).to_bytes(8, "big"))
    hasher.update(data)


def import_syslog(
    root: Path,
    db_path: Path,
    year: int,
    source_timezone: str,
) -> SyslogImportResult:
    """Import syslog events with streaming SQLite transactions."""

    root = Path(root).resolve()
    database = Database(Path(db_path))

    # First pass: validate evidence without writing events.
    collector = SyslogCollector(root)
    before = hashlib.sha256()
    validated = 0
    errors = []

    for raw in collector.collect():
        update_fingerprint(before, raw)

        try:
            parsed = parse_system_log(raw)
            normalize_event(
                parsed,
                year=year,
                source_timezone=source_timezone,
            )
            validated += 1
        except (ValueError, TypeError, ValidationError) as exc:
            errors.append(f"{raw.source_file}:{raw.source_line}: {exc}")

    errors.extend(collector.errors)

    if errors:
        return SyslogImportResult(
            read=validated,
            inserted=0,
            errors=errors,
        )

    # Second pass: stream events into one SQLite transaction.
    inserted = 0
    read = 0
    after = hashlib.sha256()

    try:
        database.initialize()
        repository = EventRepository(database)
        collector = SyslogCollector(root)

        with closing(database.connect()) as connection:
            with connection:
                connection.execute("BEGIN IMMEDIATE")

                for raw in collector.collect():
                    update_fingerprint(after, raw)

                    try:
                        parsed = parse_system_log(raw)
                        event = normalize_event(
                            parsed,
                            year=year,
                            source_timezone=source_timezone,
                        )
                    except (ValueError, TypeError, ValidationError) as exc:
                        raise CollectionFailure(
                            f"{raw.source_file}:{raw.source_line}: {exc}"
                        ) from exc

                    cursor = connection.execute(
                        INSERT_EVENT_SQL,
                        repository._event_values(event),
                    )

                    read += 1
                    inserted += cursor.rowcount

                if collector.errors:
                    raise CollectionFailure("; ".join(collector.errors))

                if read != validated or before.digest() != after.digest():
                    raise CollectionFailure("Source records changed during collection")

        return SyslogImportResult(
            read=read,
            inserted=inserted,
            errors=[],
        )

    except (
        CollectionFailure,
        sqlite3.Error,
        OSError,
        ValueError,
        TypeError,
        ValidationError,
    ) as exc:
        return SyslogImportResult(
            read=read,
            inserted=0,
            errors=[str(exc)],
        )
