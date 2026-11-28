import hashlib
import sqlite3
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from linuxtrace.collectors.syslog import SYSLOG_FILENAME
from linuxtrace.collectors.syslog_import import INSERT_EVENT_SQL
from linuxtrace.models.raw_event import RawEvent
from linuxtrace.normalizers.event import normalize_event
from linuxtrace.parsers.system_log import parse_system_log
from linuxtrace.storage.event_repository import EventRepository
from linuxtrace.storage.incremental import (
    IncrementalTracker,
)
from linuxtrace.utils.log_reader import LogReadError, read_log

UPDATE_TRACKING_SQL = """
INSERT INTO collected_files (
    source_path, sha256, file_size, collected_at
)
VALUES (?, ?, ?, ?)
ON CONFLICT(source_path)
DO UPDATE SET
    sha256 = excluded.sha256,
    file_size = excluded.file_size,
    collected_at = excluded.collected_at
"""


@dataclass
class IncrementalSyslogResult:
    processed_files: int = 0
    skipped_files: int = 0
    events_read: int = 0
    events_inserted: int = 0
    errors: list[str] = field(default_factory=list)


class SourceChangedError(Exception):
    """Raised when evidence changes during collection."""


def collect_incremental_syslog(
    root: Path,
    repository: EventRepository,
    tracker: IncrementalTracker,
    *,
    year: int,
    source_timezone: str,
) -> IncrementalSyslogResult:
    """Collect changed syslog files with per-file atomic writes."""

    root = Path(root).resolve()
    result = IncrementalSyslogResult()

    if repository.database.path.resolve() != tracker.database.path.resolve():
        raise ValueError("Repository and tracker must share one database")

    log_dir = root / "var/log"

    if log_dir.is_symlink():
        result.errors.append(f"Symbolic log directory is not supported: {log_dir}")
        return result

    try:
        if not log_dir.is_dir():
            return result

        paths = sorted(
            (path for path in log_dir.iterdir() if SYSLOG_FILENAME.fullmatch(path.name)),
            key=lambda path: path.name,
        )
    except OSError as exc:
        result.errors.append(f"Unable to discover syslog files: {exc}")
        return result

    for path in paths:
        try:
            if path.is_symlink():
                raise ValueError("Symbolic links are not supported")

            if not path.is_file():
                raise ValueError("Source must be a regular file")

            if not tracker.needs_collection(path):
                result.skipped_files += 1
                continue

            before_hash = tracker.calculate_hash(path)

            records_read = 0
            records_inserted = 0

            with closing(repository.database.connect()) as connection:
                with connection:
                    connection.execute("BEGIN IMMEDIATE")

                    for line_number, line in read_log(
                        path,
                        root=root,
                    ):
                        if not line.strip():
                            continue

                        raw = RawEvent(
                            source="syslog",
                            source_file=str(path),
                            source_line=line_number,
                            raw_log=line,
                            evidence_hash=hashlib.sha256(line.encode("utf-8")).hexdigest(),
                        )

                        parsed = parse_system_log(raw)
                        event = normalize_event(
                            parsed,
                            year=year,
                            source_timezone=source_timezone,
                        )

                        cursor = connection.execute(
                            INSERT_EVENT_SQL,
                            repository._event_values(event),
                        )

                        records_read += 1
                        records_inserted += cursor.rowcount

                    after_hash = tracker.calculate_hash(path)

                    if before_hash != after_hash:
                        raise SourceChangedError("File changed during collection")

                    connection.execute(
                        UPDATE_TRACKING_SQL,
                        (
                            str(path.resolve()),
                            after_hash,
                            path.stat().st_size,
                            datetime.now(UTC).isoformat(),
                        ),
                    )

            result.processed_files += 1
            result.events_read += records_read
            result.events_inserted += records_inserted

        except (
            SourceChangedError,
            LogReadError,
            OSError,
            ValueError,
            TypeError,
            sqlite3.Error,
            ValidationError,
        ) as exc:
            result.errors.append(f"{path}: {exc}")

    return result
