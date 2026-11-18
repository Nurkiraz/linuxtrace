import re
from ipaddress import ip_address

from linuxtrace.models.parsed_event import ParsedEvent
from linuxtrace.models.raw_event import RawEvent
from linuxtrace.parsers.syslog import parse_syslog

SSH_LOGIN_PATTERN = re.compile(
    r"^(?P<result>Accepted|Failed)\s+"
    r"(?P<method>\S+)\s+for\s+"
    r"(?:invalid user\s+)?"
    r"(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\S+)\s+port\s+"
    r"(?P<port>\d+)\b"
)

INVALID_USER_PATTERN = re.compile(
    r"^Invalid user\s+(?P<user>\S+)"
    r"\s+from\s+(?P<ip>\S+)"
    r"\s+port\s+(?P<port>\d+)\b"
)


def parse_ssh_message(
    raw_event: RawEvent,
    message: str,
    timestamp: str | None = None,
    hostname: str | None = None,
    pid: int | None = None,
) -> ParsedEvent | None:
    """Parse an SSH authentication message."""

    login = SSH_LOGIN_PATTERN.match(message)
    invalid = INVALID_USER_PATTERN.match(message)

    match = login or invalid

    if not match:
        return None

    data = match.groupdict()

    try:
        source_ip = str(ip_address(data["ip"]))
        source_port = int(data["port"])

        if not 0 <= source_port <= 65535:
            return None

    except ValueError:
        return None

    if invalid:
        event_type = "ssh_invalid_user"
        outcome = "failure"
        severity = "medium"
        method = None

    elif data["result"] == "Accepted":
        event_type = "ssh_login_success"
        outcome = "success"
        severity = "info"
        method = data["method"]

    else:
        event_type = "ssh_login_failed"
        outcome = "failure"
        severity = "low"
        method = data["method"]

    return ParsedEvent(
        raw_event=raw_event,
        timestamp_original=timestamp,
        hostname=hostname,
        event_category="authentication",
        event_type=event_type,
        severity=severity,
        username=data["user"],
        source_ip=source_ip,
        source_port=source_port,
        process_name="sshd",
        process_id=pid,
        authentication_method=method,
        outcome=outcome,
        description=message,
    )


def parse_ssh(raw_event: RawEvent) -> ParsedEvent | None:
    """Parse SSH events from traditional syslog records."""

    header = parse_syslog(raw_event.raw_log)

    if not header:
        return None

    if header["process"] not in {
        "sshd",
        "sshd-session",
        "sshd-auth",
    }:
        return None

    return parse_ssh_message(
        raw_event=raw_event,
        message=header["message"],
        timestamp=header["timestamp"],
        hostname=header["hostname"],
        pid=header["pid"],
    )
