import re

from linuxtrace.models.parsed_event import ParsedEvent
from linuxtrace.models.raw_event import RawEvent
from linuxtrace.parsers.syslog import parse_syslog

SUDO_PATTERN = re.compile(r"^\s*(?P<user>\S+)\s*:\s*(?P<content>.+)$")

FAILURE_PATTERN = re.compile(
    r"not in sudoers|"
    r"command not allowed|"
    r"incorrect password attempt|"
    r"authentication failure|"
    r"a password is required",
    re.IGNORECASE,
)


def parse_sudo_message(
    raw_event: RawEvent,
    message: str,
    timestamp: str | None = None,
    hostname: str | None = None,
    pid: int | None = None,
) -> ParsedEvent | None:
    """Parse sudo command and authorization events."""

    if message.startswith("pam_"):
        return None

    match = SUDO_PATTERN.match(message)

    if not match:
        return None

    username = match.group("user")
    content = match.group("content")

    metadata, separator, command = content.partition("COMMAND=")

    fields = {}

    for part in metadata.split(";"):
        part = part.strip()

        if "=" not in part:
            continue

        key, value = part.split("=", 1)
        key = key.strip()

        if key in {"TTY", "PWD", "USER"}:
            fields[key] = value.strip() or None

    if FAILURE_PATTERN.search(metadata):
        event_type = "sudo_command_denied"
        outcome = "failure"
        severity = "medium"

    elif separator and fields.get("USER"):
        event_type = "sudo_command_allowed"
        outcome = "success"
        severity = "info"

    else:
        return None

    return ParsedEvent(
        raw_event=raw_event,
        timestamp_original=timestamp,
        hostname=hostname,
        event_category="privilege",
        event_type=event_type,
        severity=severity,
        username=username,
        actor_user=username,
        target_user=fields.get("USER"),
        terminal=fields.get("TTY"),
        working_directory=fields.get("PWD"),
        command=command.strip() if separator else None,
        process_name="sudo",
        process_id=pid,
        outcome=outcome,
        description=message,
    )


def parse_sudo(raw_event: RawEvent) -> ParsedEvent | None:
    """Parse sudo events from traditional syslog records."""

    header = parse_syslog(raw_event.raw_log)

    if not header:
        return None

    if header["process"] != "sudo":
        return None

    return parse_sudo_message(
        raw_event=raw_event,
        message=header["message"],
        timestamp=header["timestamp"],
        hostname=header["hostname"],
        pid=header["pid"],
    )
