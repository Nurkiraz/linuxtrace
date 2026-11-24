from datetime import UTC, datetime

from linuxtrace.models.normalized_event import NormalizedEvent
from linuxtrace.storage.database import Database

ALLOWED_SEVERITIES = {
    "info",
    "low",
    "medium",
    "high",
    "critical",
}


class EventQuery:
    """Query normalized forensic events from SQLite."""

    def __init__(self, database: Database):
        self.database = database

    def search(
        self,
        *,
        username: str | None = None,
        source_ip: str | None = None,
        event_type: str | None = None,
        category: str | None = None,
        severity: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[NormalizedEvent]:
        """Search stored events using optional filters."""

        if not 1 <= limit <= 10000:
            raise ValueError("limit must be between 1 and 10000")

        if offset < 0:
            raise ValueError("offset cannot be negative")

        if severity and severity not in ALLOWED_SEVERITIES:
            raise ValueError("Invalid severity")

        conditions = []
        parameters = []

        filters = {
            "username": username,
            "source_ip": source_ip,
            "event_type": event_type,
            "event_category": category,
            "severity": severity,
        }

        for column, value in filters.items():
            if value is not None:
                conditions.append(f"{column} = ?")
                parameters.append(value)

        if start is not None:
            if start.tzinfo is None:
                raise ValueError("start must have a timezone")
            conditions.append("timestamp >= ?")
            parameters.append(start.astimezone(UTC).isoformat())

        if end is not None:
            if end.tzinfo is None:
                raise ValueError("end must have a timezone")
            conditions.append("timestamp <= ?")
            parameters.append(end.astimezone(UTC).isoformat())

        where = "WHERE " + " AND ".join(conditions) if conditions else ""

        sql = f"""
            SELECT event_json
            FROM events
            {where}
            ORDER BY
                timestamp IS NULL,
                timestamp ASC,
                event_id ASC
            LIMIT ? OFFSET ?
        """

        parameters.extend([limit, offset])

        with self.database.connect() as connection:
            rows = connection.execute(sql, parameters).fetchall()

        return [NormalizedEvent.model_validate_json(row["event_json"]) for row in rows]
