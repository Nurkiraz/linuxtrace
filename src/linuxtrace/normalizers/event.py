from linuxtrace.models.normalized_event import NormalizedEvent
from linuxtrace.models.parsed_event import ParsedEvent
from linuxtrace.normalizers.event_id import generate_event_id
from linuxtrace.normalizers.timestamp import normalize_timestamp


def normalize_event(
    event: ParsedEvent,
    *,
    year: int | None = None,
    source_timezone: str | None = None,
) -> NormalizedEvent:
    """Convert a parsed event into a normalized forensic event."""

    raw = event.raw_event

    if raw.source == "journal":
        source = "journal"
    elif event.timestamp_original and (
        "T" in event.timestamp_original and len(event.timestamp_original) >= 10
    ):
        source = "iso"
    else:
        source = "syslog"

    timestamp_result = normalize_timestamp(
        event.timestamp_original,
        source=source,
        year=year,
        source_timezone=source_timezone,
    )

    event_id = generate_event_id(event)

    return NormalizedEvent(
        **event.model_dump(),
        event_id=event_id,
        **timestamp_result,
    )
