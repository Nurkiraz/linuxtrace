import hashlib
import sqlite3
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from linuxtrace.models.raw_event import RawEvent
from linuxtrace.normalizers.event import normalize_event
from linuxtrace.parsers.authentication import parse_authentication
from linuxtrace.storage.event_repository import EventRepository
from linuxtrace.storage.incremental import IncrementalTracker
from linuxtrace.utils.discovery import discover_logs, discover_rotated_logs
from linuxtrace.utils.log_reader import LogReadError, read_log


@dataclass
class CollectionResult:
    """Summary of incremental authentication collection."""

    processed_files: int = 0
    skipped_files: int = 0
    events_read: int = 0
    events_inserted: int = 0
    errors: list[str] = field(default_factory=list)


class SourceChangedError(Exception):
    """Raised when a log changes during collection."""


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


def collect_incremental_auth(
    root: Path,
    repository: EventRepository,
    tracker: IncrementalTracker,
    *,
    year: int | None = None,
    source_timezone: str | None = None,
) -> CollectionResult:
    """Collect authentication logs using atomic SQLite transactions."""

    root = Path(root).resolve()
    result = CollectionResult()

    if repository.database.path.resolve() != tracker.database.path.resolve():
        raise ValueError("Repository and tracker must share one database")

    sources = discover_logs(root) + discover_rotated_logs(root)

    for source in sources:
        if source["category"] != "authentication":
            continue

        if source["status"] == "missing":
            continue

        path = Path(source["path"])

        if source["status"] != "available":
            result.errors.append(f"{path}: {source['status']}")
            continue

        try:
            if not tracker.needs_collection(path):
                result.skipped_files += 1
                continue

            before_hash = tracker.calculate_hash(path)
            records_read = 0
            records_inserted = 0

            with closing(repository.database.connect()) as connection:
                with connection:
                    connection.execute("BEGIN IMMEDIATE")

                    for line_number, line in read_log(path, root=root):
                        if not line.strip():
                            continue

                        raw = RawEvent(
                            source="authentication",
                            source_file=str(path),
                            source_line=line_number,
                            raw_log=line,
                            evidence_hash=hashlib.sha256(line.encode("utf-8")).hexdigest(),
                        )

                        parsed = parse_authentication(raw)

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
            sqlite3.Error,
            ValidationError,
        ) as exc:
            result.errors.append(f"{path}: {exc}")

    return result
