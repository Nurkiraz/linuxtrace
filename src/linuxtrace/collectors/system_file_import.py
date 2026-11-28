import hashlib
import sqlite3
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from linuxtrace.collectors.syslog_import import (
    INSERT_EVENT_SQL,
    update_fingerprint,
)
from linuxtrace.collectors.system_files import SystemFileCollector
from linuxtrace.normalizers.event import normalize_event
from linuxtrace.parsers.system_log import parse_system_log
from linuxtrace.storage.database import Database
from linuxtrace.storage.event_repository import EventRepository


@dataclass
class SystemImportResult:
    read: int = 0
    inserted: int = 0
    errors: list[str] = field(default_factory=list)


class SourceChangedError(Exception):
    """Raised when records change between collection passes."""


def import_system_file(
    root: Path,
    db_path: Path,
    source: str,
    year: int,
    source_timezone: str,
) -> SystemImportResult:
    """Import kernel or cron records with atomic SQLite writes."""

    # Pass 1: Validate before writing to the database.
    collector = SystemFileCollector(root, source)
    before = hashlib.sha256()
    validated = 0
    errors = []

    for raw in collector.collect():
        update_fingerprint(before, raw)

        try:
            normalize_event(
                parse_system_log(raw),
                year=year,
                source_timezone=source_timezone,
            )
            validated += 1
        except (ValueError, TypeError, ValidationError) as exc:
            errors.append(f"{raw.source_file}:{raw.source_line}: {exc}")

    errors.extend(collector.errors)

    if errors:
        return SystemImportResult(
            read=validated,
            errors=errors,
        )

    # Pass 2: Write events inside one transaction.
    database = Database(Path(db_path))
    repository = EventRepository(database)
    collector = SystemFileCollector(root, source)

    read = 0
    inserted = 0
    after = hashlib.sha256()

    try:
        database.initialize()

        with closing(database.connect()) as connection:
            with connection:
                connection.execute("BEGIN IMMEDIATE")

                for raw in collector.collect():
                    update_fingerprint(after, raw)

                    event = normalize_event(
                        parse_system_log(raw),
                        year=year,
                        source_timezone=source_timezone,
                    )

                    cursor = connection.execute(
                        INSERT_EVENT_SQL,
                        repository._event_values(event),
                    )

                    read += 1
                    inserted += cursor.rowcount

                if collector.errors:
                    raise SourceChangedError("; ".join(collector.errors))

                if read != validated or before.digest() != after.digest():
                    raise SourceChangedError("Source records changed during collection")

        return SystemImportResult(
            read=read,
            inserted=inserted,
        )

    except (
        SourceChangedError,
        sqlite3.Error,
        OSError,
        ValueError,
        TypeError,
        ValidationError,
    ) as exc:
        return SystemImportResult(
            read=read,
            inserted=0,
            errors=[str(exc)],
        )
