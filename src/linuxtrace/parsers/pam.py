import re
from ipaddress import ip_address

from linuxtrace.models.parsed_event import ParsedEvent
from linuxtrace.models.raw_event import RawEvent
from linuxtrace.parsers.syslog import parse_syslog

PAM_PATTERN = re.compile(
    r"^(?P<module>pam_\w+)"
    r"\((?P<service>[^:]+):(?P<type>[^)]+)\):"
    r"\s*(?P<message>.*)$"
)

SESSION_OPEN_PATTERN = re.compile(
    r"^session opened for user (?P<user>[^\s(]+)"
    r"(?:\(uid=(?P<uid>\d+)\))?"
    r"(?: by (?P<actor>[^\s(]*)"
    r"(?:\(uid=(?P<actor_uid>\d+)\))?)?"
)

SESSION_CLOSE_PATTERN = re.compile(
    r"^session closed for user (?P<user>[^\s(]+)"
    r"(?:\(uid=(?P<uid>\d+)\))?"
)

FIELD_PATTERN = re.compile(r"(?:^|\s)(?P<key>\w+)=(?P<value>[^\s;]*)")


def parse_pam_message(
    raw_event: RawEvent,
    message: str,
    timestamp: str | None = None,
    hostname: str | None = None,
    process_name: str | None = None,
    pid: int | None = None,
) -> ParsedEvent | None:
    """Parse PAM authentication and session events."""

    match = PAM_PATTERN.match(message)

    if not match:
        return None

    data = match.groupdict()
    content = data["message"]

    values = {}

    opened = SESSION_OPEN_PATTERN.match(content)
    closed = SESSION_CLOSE_PATTERN.match(content)

    if opened:
        fields = opened.groupdict()

        event_type = "pam_session_opened"
        outcome = "success"
        severity = "info"

        values["username"] = fields["user"]
        values["user_id"] = int(fields["uid"]) if fields["uid"] is not None else None

        values["actor_user"] = fields["actor"] or None
        values["actor_uid"] = int(fields["actor_uid"]) if fields["actor_uid"] is not None else None

    elif closed:
        fields = closed.groupdict()

        event_type = "pam_session_closed"
        outcome = None
        severity = "info"

        values["username"] = fields["user"]
        values["user_id"] = int(fields["uid"]) if fields["uid"] is not None else None

    elif content.startswith("authentication failure"):
        event_type = "pam_authentication_failed"
        outcome = "failure"
        severity = "low"

        fields = {item["key"]: item["value"] for item in FIELD_PATTERN.finditer(content)}

        values["username"] = fields.get("user") or None
        values["terminal"] = fields.get("tty") or None
        values["actor_user"] = fields.get("ruser") or None

        remote_host = fields.get("rhost")

        if remote_host:
            try:
                values["source_ip"] = str(ip_address(remote_host))
            except ValueError:
                pass

    else:
        return None

    return ParsedEvent(
        raw_event=raw_event,
        timestamp_original=timestamp,
        hostname=hostname,
        process_name=process_name,
        process_id=pid,
        event_category="authentication",
        event_type=event_type,
        severity=severity,
        outcome=outcome,
        pam_module=data["module"],
        pam_service=data["service"],
        pam_type=data["type"],
        description=message,
        **values,
    )


def parse_pam(raw_event: RawEvent) -> ParsedEvent | None:
    """Parse PAM events from traditional syslog records."""

    header = parse_syslog(raw_event.raw_log)

    if not header:
        return None

    return parse_pam_message(
        raw_event=raw_event,
        message=header["message"],
        timestamp=header["timestamp"],
        hostname=header["hostname"],
        process_name=header["process"],
        pid=header["pid"],
    )
