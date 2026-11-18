from linuxtrace.models.parsed_event import ParsedEvent
from linuxtrace.models.raw_event import RawEvent
from linuxtrace.parsers.pam import parse_pam
from linuxtrace.parsers.ssh import parse_ssh
from linuxtrace.parsers.sudo import parse_sudo
from linuxtrace.parsers.syslog import parse_syslog


def parse_authentication(raw_event: RawEvent) -> ParsedEvent:
    """Dispatch authentication records to supported parsers."""

    for parser in (parse_ssh, parse_pam, parse_sudo):
        event = parser(raw_event)

        if event is not None:
            return event

    header = parse_syslog(raw_event.raw_log) or {}

    return ParsedEvent(
        raw_event=raw_event,
        timestamp_original=header.get("timestamp"),
        hostname=header.get("hostname"),
        process_name=header.get("process"),
        process_id=header.get("pid"),
        event_category="authentication",
        event_type="authentication_unclassified",
        description=header.get("message", raw_event.raw_log),
    )
