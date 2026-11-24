from datetime import UTC, datetime
from typing import Literal

from linuxtrace.storage.database import Database
from linuxtrace.storage.event_query import ALLOWED_SEVERITIES

GroupBy = Literal["hour", "day"]

GROUP_EXPRESSIONS = {
    "hour": "strftime('%Y-%m-%d %H:00', timestamp)",
    "day": "strftime('%Y-%m-%d', timestamp)",
}


class EventGroupQuery:
    """Aggregate filtered events directly in SQLite."""

    def __init__(self, database: Database):
        self.database = database

    def group_counts(
        self,
        group_by: GroupBy,
        username: str | None = None,
        source_ip: str | None = None,
        category: str | None = None,
        event_type: str | None = None,
        severity: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> list[tuple[str, int]]:
        if group_by not in GROUP_EXPRESSIONS:
            raise ValueError("Invalid grouping: use hour or day")

        if severity is not None and severity not in ALLOWED_SEVERITIES:
            raise ValueError("Invalid severity")

        filters = {
            "username": username,
            "source_ip": source_ip,
            "event_type": event_type,
            "event_category": category,
            "severity": severity,
        }

        conditions = ["timestamp IS NOT NULL"]
        parameters = []

        for column, value in filters.items():
            if value is not None:
                conditions.append(f"{column} = ?")
                parameters.append(value)

        for operator, moment in ((">=", start), ("<=", end)):
            if moment is None:
                continue

            if moment.tzinfo is None:
                raise ValueError("Date must have a timezone")

            conditions.append(f"timestamp {operator} ?")
            parameters.append(moment.astimezone(UTC).isoformat())

        if start and end and start > end:
            raise ValueError("Start time cannot be later than end time")

        expression = GROUP_EXPRESSIONS[group_by]
        where = " AND ".join(conditions)

        sql = f"""
            SELECT
                {expression} AS time_bucket,
                COUNT(*) AS event_count
            FROM events
            WHERE {where}
            GROUP BY time_bucket
            ORDER BY time_bucket ASC
        """

        with self.database.connect() as connection:
            rows = connection.execute(sql, parameters).fetchall()

        return [
            (row["time_bucket"], row["event_count"])
            for row in rows
            if row["time_bucket"] is not None
        ]
