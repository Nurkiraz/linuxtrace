import re
from datetime import UTC, datetime, timedelta

DURATION_PATTERN = re.compile(r"^([1-9]\d*)([mhdw])$")

DURATION_UNITS = {
    "m": "minutes",
    "h": "hours",
    "d": "days",
    "w": "weeks",
}


def parse_duration(value: str) -> timedelta:
    """Parse durations such as 30m, 24h, 7d and 2w."""

    match = DURATION_PATTERN.fullmatch(value.strip())

    if not match:
        raise ValueError("Invalid duration. Use 30m, 24h, 7d or 2w.")

    amount = int(match.group(1))
    unit = match.group(2)

    return timedelta(**{DURATION_UNITS[unit]: amount})


def parse_datetime(value: str) -> datetime:
    """Parse a timezone-aware date and convert it to UTC."""

    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid date. Use ISO 8601 with a timezone.") from exc

    if parsed.tzinfo is None:
        raise ValueError("Timezone required. Example: 2026-11-18T10:00:00+03:00")

    return parsed.astimezone(UTC)


def get_time_range(
    last: str | None = None,
    start: str | None = None,
    end: str | None = None,
    now: datetime | None = None,
) -> tuple[datetime | None, datetime | None]:
    """Calculate the UTC time range for a timeline query."""

    if last and (start or end):
        raise ValueError("--last cannot be combined with --from or --to")

    if last:
        current = now or datetime.now(UTC)

        if current.tzinfo is None:
            raise ValueError("Current time must have a timezone")

        current = current.astimezone(UTC)

        try:
            beginning = current - parse_duration(last)
        except OverflowError as exc:
            raise ValueError("Duration is too large") from exc

        return beginning, current

    beginning = parse_datetime(start) if start else None
    ending = parse_datetime(end) if end else None

    if beginning and ending and beginning > ending:
        raise ValueError("Start time cannot be later than end time")

    return beginning, ending
