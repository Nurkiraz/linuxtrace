from collections.abc import Iterable
from datetime import UTC, datetime

from linuxtrace.models.normalized_event import NormalizedEvent
from linuxtrace.storage.database import Database


class EventRepository:
    """Store normalized forensic events in SQLite."""

    def __init__(self, database: Database):
        self.database = database

    @staticmethod
    def _event_values(event: NormalizedEvent) -> tuple:
        """Prepare event data for SQLite."""

        return (
            event.event_id,
            event.timestamp.isoformat() if event.timestamp else None,
            event.timestamp_original,
            event.timezone,
            event.timestamp_confidence.value,
            event.hostname,
            event.raw_event.source,
            event.raw_event.source_file,
            event.raw_event.source_line,
            event.event_category,
            event.event_type,
            event.severity,
            event.username,
            event.source_ip,
            event.destination_ip,
            event.process_name,
            event.process_id,
            event.command,
            event.outcome,
            event.description,
            event.raw_event.evidence_hash,
            event.raw_event.raw_log,
            event.model_dump_json(),
            datetime.now(UTC).isoformat(),
        )

    def insert_event(self, event: NormalizedEvent) -> bool:
        """Insert one event. Return False if ID already exists."""

        query = """
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

        with self.database.connect() as connection:
            cursor = connection.execute(
                query,
                self._event_values(event),
            )

            return cursor.rowcount == 1

    def insert_events(
        self,
        events: Iterable[NormalizedEvent],
    ) -> int:
        """Insert multiple events in one transaction."""

        inserted = 0

        with self.database.connect() as connection:
            for event in events:
                cursor = connection.execute(
                    """
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
                    """,
                    self._event_values(event),
                )

                inserted += cursor.rowcount

        return inserted

    def count_events(self) -> int:
        """Return the number of stored events."""

        with self.database.connect() as connection:
            row = connection.execute("SELECT COUNT(*) FROM events").fetchone()

            return row[0]
