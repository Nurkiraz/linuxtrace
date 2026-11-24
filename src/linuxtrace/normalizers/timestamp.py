from datetime import UTC, datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from linuxtrace.models.normalized_event import TimestampConfidence


def normalize_timestamp(
    value: str | None,
    *,
    source: str,
    year: int | None = None,
    source_timezone: str | None = None,
) -> dict:
    """Normalize source timestamps to UTC without inventing dates."""

    result = {
        "timestamp": None,
        "timezone": source_timezone,
        "timestamp_confidence": TimestampConfidence.UNKNOWN,
        "timestamp_method": None,
        "normalization_warnings": [],
    }

    if not value:
        result["normalization_warnings"].append("Timestamp is missing")
        return result

    if source == "journal":
        try:
            microseconds = int(value)
            timestamp = datetime.fromtimestamp(
                microseconds / 1_000_000,
                tz=UTC,
            )
        except (ValueError, OverflowError, OSError):
            result["normalization_warnings"].append("Invalid journal timestamp")
            return result

        result.update(
            {
                "timestamp": timestamp,
                "timezone": "UTC",
                "timestamp_confidence": TimestampConfidence.HIGH,
                "timestamp_method": "journal_unix_microseconds",
            }
        )
        return result

    if source == "iso":
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            result["normalization_warnings"].append("Invalid ISO timestamp")
            return result

        if parsed.tzinfo is None:
            result["normalization_warnings"].append("ISO timestamp has no timezone")
            return result

        result.update(
            {
                "timestamp": parsed.astimezone(UTC),
                "timezone": str(parsed.tzinfo),
                "timestamp_confidence": TimestampConfidence.HIGH,
                "timestamp_method": "iso8601",
            }
        )
        return result

    if source == "syslog":
        if year is None or source_timezone is None:
            result["normalization_warnings"].append("Syslog requires explicit year and timezone")
            return result

        try:
            local_time = datetime.strptime(
                f"{year} {value}",
                "%Y %b %d %H:%M:%S",
            )

            tz = ZoneInfo(source_timezone)

            candidate = local_time.replace(tzinfo=tz)

            # Reject nonexistent local times and flag ambiguous DST.
            roundtrip = candidate.astimezone(UTC).astimezone(tz)

            if roundtrip.replace(tzinfo=None) != local_time:
                result["normalization_warnings"].append(
                    "Nonexistent local time due to timezone transition"
                )
                return result

            alternate = local_time.replace(tzinfo=tz, fold=1)

            if alternate.utcoffset() != candidate.utcoffset():
                result["normalization_warnings"].append(
                    "Ambiguous local time due to DST transition"
                )
                return result

        except (ValueError, ZoneInfoNotFoundError):
            result["normalization_warnings"].append("Invalid syslog timestamp or timezone")
            return result

        result.update(
            {
                "timestamp": candidate.astimezone(UTC),
                "timestamp_confidence": TimestampConfidence.MEDIUM,
                "timestamp_method": "syslog_explicit_context",
            }
        )
        return result

    result["normalization_warnings"].append(f"Unsupported timestamp source: {source}")
    return result
