import hashlib
from datetime import UTC, datetime

from linuxtrace.models.normalized_event import (
    NormalizedEvent,
    TimestampConfidence,
)
from linuxtrace.models.raw_event import RawEvent
from linuxtrace.normalizers.event import normalize_event
from linuxtrace.normalizers.event_id import generate_event_id
from linuxtrace.parsers.authentication import parse_authentication
from linuxtrace.parsers.journal import parse_journal


def make_auth_event(
    line: str | None = None,
    source_line: int = 1,
    source_file: str = "/var/log/auth.log",
):
    if line is None:
        line = (
            "Nov 18 10:00:01 lab-server sshd[1201]: "
            "Accepted password for analyst from "
            "192.0.2.10 port 51234 ssh2"
        )

    raw = RawEvent(
        source="authentication",
        source_file=source_file,
        source_line=source_line,
        raw_log=line,
        evidence_hash=hashlib.sha256(line.encode()).hexdigest(),
    )

    return parse_authentication(raw)


def make_journal_event():
    metadata = {
        "MESSAGE": ("Accepted password for analyst from 192.0.2.10 port 51234 ssh2"),
        "SYSLOG_IDENTIFIER": "sshd",
        "_HOSTNAME": "lab-server",
        "_PID": "1201",
        "__REALTIME_TIMESTAMP": "1794996000000000",
        "__CURSOR": "test-journal-cursor",
    }

    raw = RawEvent(
        source="journal",
        source_file="systemd-journal",
        source_line=1,
        raw_log=str(metadata),
        evidence_hash=hashlib.sha256(str(metadata).encode()).hexdigest(),
        metadata=metadata,
    )

    return parse_journal(raw)


def test_normalized_event_creation():
    parsed = make_auth_event()

    event = normalize_event(
        parsed,
        year=2026,
        source_timezone="Europe/Istanbul",
    )

    assert isinstance(event, NormalizedEvent)
    assert event.event_type == "ssh_login_success"
    assert len(event.event_id) == 64


def test_deterministic_event_id():
    parsed = make_auth_event()

    first = generate_event_id(parsed)
    second = generate_event_id(parsed)

    assert first == second


def test_different_source_line_changes_id():
    first = make_auth_event(source_line=1)
    second = make_auth_event(source_line=2)

    assert generate_event_id(first) != generate_event_id(second)


def test_different_source_file_changes_id():
    first = make_auth_event(source_file="/var/log/auth.log")
    second = make_auth_event(source_file="/var/log/secure")

    assert generate_event_id(first) != generate_event_id(second)


def test_event_id_is_hexadecimal():
    event_id = generate_event_id(make_auth_event())

    assert len(event_id) == 64
    assert all(char in "0123456789abcdef" for char in event_id)


def test_syslog_utc_normalization():
    event = normalize_event(
        make_auth_event(),
        year=2026,
        source_timezone="Europe/Istanbul",
    )

    assert event.timestamp == datetime(2026, 11, 18, 7, 0, 1, tzinfo=UTC)
    assert event.timestamp_confidence == TimestampConfidence.MEDIUM
    assert event.timestamp_method == "syslog_explicit_context"


def test_missing_syslog_context():
    event = normalize_event(make_auth_event())

    assert event.timestamp is None
    assert event.timestamp_confidence == TimestampConfidence.UNKNOWN
    assert event.normalization_warnings


def test_missing_year():
    event = normalize_event(
        make_auth_event(),
        source_timezone="Europe/Istanbul",
    )

    assert event.timestamp is None
    assert event.normalization_warnings


def test_missing_timezone():
    event = normalize_event(
        make_auth_event(),
        year=2026,
    )

    assert event.timestamp is None
    assert event.normalization_warnings


def test_journal_timestamp_normalization():
    event = normalize_event(make_journal_event())

    assert event.timestamp == datetime.fromtimestamp(1794996000, tz=UTC)
    assert event.timestamp_confidence == TimestampConfidence.HIGH
    assert event.timestamp_method == "journal_unix_microseconds"


def test_journal_cursor_affects_identity():
    first = make_journal_event()
    second = make_journal_event()

    second.raw_event.metadata["__CURSOR"] = "another-cursor"

    assert generate_event_id(first) != generate_event_id(second)


def test_original_evidence_preserved():
    parsed = make_auth_event()

    event = normalize_event(
        parsed,
        year=2026,
        source_timezone="Europe/Istanbul",
    )

    assert event.raw_event == parsed.raw_event
    assert event.raw_event.raw_log == parsed.raw_event.raw_log
    assert event.raw_event.evidence_hash == (parsed.raw_event.evidence_hash)
    assert event.timestamp_original == "Nov 18 10:00:01"


def test_security_fields_preserved():
    event = normalize_event(make_auth_event())

    assert event.username == "analyst"
    assert event.source_ip == "192.0.2.10"
    assert event.source_port == 51234
    assert event.process_name == "sshd"
    assert event.process_id == 1201
    assert event.outcome == "success"


def test_repeated_normalization_is_stable():
    parsed = make_auth_event()

    first = normalize_event(
        parsed,
        year=2026,
        source_timezone="Europe/Istanbul",
    )

    second = normalize_event(
        parsed,
        year=2026,
        source_timezone="Europe/Istanbul",
    )

    assert first.event_id == second.event_id
    assert first.timestamp == second.timestamp
    assert first.model_dump() == second.model_dump()
