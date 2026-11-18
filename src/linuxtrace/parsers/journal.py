from linuxtrace.models.parsed_event import ParsedEvent
from linuxtrace.models.raw_event import RawEvent
from linuxtrace.parsers.pam import parse_pam_message
from linuxtrace.parsers.ssh import parse_ssh_message
from linuxtrace.parsers.sudo import parse_sudo_message


def safe_int(value: object) -> int | None:
    """Safely convert journal fields to integers."""

    if not isinstance(value, (str, int)):
        return None

    try:
        return int(value)
    except ValueError:
        return None


def safe_str(value: object) -> str | None:
    """Accept only string journal fields."""

    if isinstance(value, str):
        return value

    return None


def parse_journal(raw_event: RawEvent) -> ParsedEvent | None:
    """Parse structured systemd journal records."""

    data = raw_event.metadata

    message = safe_str(data.get("MESSAGE"))

    if not message:
        return None

    hostname = safe_str(data.get("_HOSTNAME"))

    process = safe_str(data.get("SYSLOG_IDENTIFIER")) or safe_str(data.get("_COMM"))

    pid = safe_int(data.get("_PID"))

    timestamp = safe_str(data.get("__REALTIME_TIMESTAMP"))

    event = None

    if process in {
        "sshd",
        "sshd-session",
        "sshd-auth",
    }:
        event = parse_ssh_message(
            raw_event=raw_event,
            message=message,
            timestamp=timestamp,
            hostname=hostname,
            pid=pid,
        )

    if event is None:
        event = parse_pam_message(
            raw_event=raw_event,
            message=message,
            timestamp=timestamp,
            hostname=hostname,
            process_name=process,
            pid=pid,
        )

    if event is None and process == "sudo":
        event = parse_sudo_message(
            raw_event=raw_event,
            message=message,
            timestamp=timestamp,
            hostname=hostname,
            pid=pid,
        )

    if event is None:
        event = ParsedEvent(
            raw_event=raw_event,
            timestamp_original=timestamp,
            hostname=hostname,
            process_name=process,
            process_id=pid,
            event_category="system",
            event_type="journal_unclassified",
            description=message,
        )

    return event.model_copy(
        update={
            "boot_id": safe_str(data.get("_BOOT_ID")),
            "session_id": safe_str(data.get("_AUDIT_SESSION")),
            "journal_cursor": safe_str(data.get("__CURSOR")),
            "systemd_unit": safe_str(data.get("_SYSTEMD_UNIT")),
            "journal_priority": safe_int(data.get("PRIORITY")),
            "timestamp_unix_us": safe_int(data.get("__REALTIME_TIMESTAMP")),
            "process_uid": safe_int(data.get("_UID")),
        }
    )
