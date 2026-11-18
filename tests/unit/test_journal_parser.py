import hashlib
import json

from linuxtrace.models.raw_event import RawEvent
from linuxtrace.parsers.journal import parse_journal


def make_journal_event(message, process="systemd", **extra):
    data = {
        "MESSAGE": message,
        "SYSLOG_IDENTIFIER": process,
        "_HOSTNAME": "lab-server",
        "_PID": "1200",
        "_UID": "1000",
        "_BOOT_ID": "test-boot-id",
        "_AUDIT_SESSION": "4",
        "_SYSTEMD_UNIT": "test.service",
        "__REALTIME_TIMESTAMP": "1794996000000000",
        "__CURSOR": "test-cursor",
        "PRIORITY": "6",
    }

    data.update(extra)

    raw_log = json.dumps(data)

    return RawEvent(
        source="journal",
        source_file="systemd-journal",
        source_line=1,
        raw_log=raw_log,
        evidence_hash=hashlib.sha256(raw_log.encode()).hexdigest(),
        metadata=data,
    )


def test_journal_ssh_success():
    raw = make_journal_event(
        "Accepted password for analyst from 192.0.2.10 port 51234 ssh2",
        process="sshd",
    )

    event = parse_journal(raw)

    assert event is not None
    assert event.event_type == "ssh_login_success"
    assert event.username == "analyst"
    assert event.source_ip == "192.0.2.10"


def test_journal_ssh_failure():
    raw = make_journal_event(
        "Failed password for root from 198.51.100.25 port 45123 ssh2",
        process="sshd",
    )

    event = parse_journal(raw)

    assert event is not None
    assert event.event_type == "ssh_login_failed"
    assert event.outcome == "failure"


def test_journal_pam_session():
    raw = make_journal_event(
        "pam_unix(sudo:session): session opened for user root(uid=0) by analyst(uid=1000)",
        process="sudo",
    )

    event = parse_journal(raw)

    assert event is not None
    assert event.event_type == "pam_session_opened"
    assert event.actor_user == "analyst"
    assert event.username == "root"


def test_journal_sudo_command():
    raw = make_journal_event(
        "analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/id",
        process="sudo",
    )

    event = parse_journal(raw)

    assert event is not None
    assert event.event_type == "sudo_command_allowed"
    assert event.command == "/usr/bin/id"
    assert event.target_user == "root"


def test_journal_unclassified():
    raw = make_journal_event("Started example.service.")

    event = parse_journal(raw)

    assert event is not None
    assert event.event_type == "journal_unclassified"
    assert event.event_category == "system"
    assert event.raw_event == raw


def test_journal_metadata():
    raw = make_journal_event("Test message")

    event = parse_journal(raw)

    assert event is not None
    assert event.boot_id == "test-boot-id"
    assert event.session_id == "4"
    assert event.journal_cursor == "test-cursor"
    assert event.systemd_unit == "test.service"
    assert event.journal_priority == 6
    assert event.process_uid == 1000
    assert event.process_id == 1200
    assert event.hostname == "lab-server"


def test_journal_timestamp():
    raw = make_journal_event("Test message")

    event = parse_journal(raw)

    assert event is not None
    assert event.timestamp_unix_us == 1794996000000000
    assert event.timestamp_original == "1794996000000000"


def test_missing_message():
    raw = make_journal_event("")

    assert parse_journal(raw) is None


def test_invalid_message_type():
    raw = make_journal_event([1, 2, 3])

    assert parse_journal(raw) is None


def test_invalid_numeric_metadata():
    raw = make_journal_event(
        "Test message",
        _PID="invalid",
        _UID="invalid",
        PRIORITY="invalid",
    )

    event = parse_journal(raw)

    assert event is not None
    assert event.process_id is None
    assert event.process_uid is None
    assert event.journal_priority is None


def test_missing_optional_metadata():
    raw = make_journal_event("Test message")

    raw.metadata.pop("_BOOT_ID")
    raw.metadata.pop("_AUDIT_SESSION")
    raw.metadata.pop("__CURSOR")

    event = parse_journal(raw)

    assert event is not None
    assert event.boot_id is None
    assert event.session_id is None
    assert event.journal_cursor is None


def test_process_name_fallback():
    raw = make_journal_event(
        "Accepted password for analyst from 192.0.2.10 port 51234 ssh2",
        SYSLOG_IDENTIFIER=None,
        _COMM="sshd",
    )

    event = parse_journal(raw)

    assert event is not None
    assert event.event_type == "ssh_login_success"
