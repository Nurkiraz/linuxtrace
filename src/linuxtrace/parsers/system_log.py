from linuxtrace.models.parsed_event import ParsedEvent
from linuxtrace.models.raw_event import RawEvent
from linuxtrace.parsers.syslog import parse_syslog
from linuxtrace.parsers.system_events import classify_system_event


def parse_system_log(raw: RawEvent) -> ParsedEvent:
    """Convert a raw traditional syslog entry into a parsed event."""

    parsed = parse_syslog(raw.raw_log)

    if parsed is None:
        return ParsedEvent(
            raw_event=raw,
            event_category="system",
            event_type="unclassified",
            severity="info",
            description=raw.raw_log,
        )

    message = parsed["message"]
    process_name = parsed["process"]

    classification = classify_system_event(
        process_name=process_name,
        message=message,
    )

    return ParsedEvent(
        raw_event=raw,
        timestamp_original=parsed["timestamp"],
        hostname=parsed["hostname"],
        event_category=classification.category,
        event_type=classification.event_type,
        severity=classification.severity,
        process_name=process_name,
        process_id=parsed["pid"],
        description=message,
    )
