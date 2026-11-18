import hashlib

import pytest

from linuxtrace.models.raw_event import RawEvent
from linuxtrace.parsers.ssh import parse_ssh


def make_raw_event(line: str) -> RawEvent:
    """Create a synthetic raw authentication event."""

    return RawEvent(
        source="authentication",
        source_file="/var/log/auth.log",
        source_line=1,
        raw_log=line,
        evidence_hash=hashlib.sha256(line.encode("utf-8")).hexdigest(),
    )


def test_successful_password_login():
    raw = make_raw_event(
        "Nov 18 10:00:01 lab-server sshd[1201]: "
        "Accepted password for analyst from "
        "192.0.2.10 port 51234 ssh2"
    )

    event = parse_ssh(raw)

    assert event is not None
    assert event.event_type == "ssh_login_success"
    assert event.username == "analyst"
    assert event.source_ip == "192.0.2.10"
    assert event.source_port == 51234
    assert event.authentication_method == "password"
    assert event.outcome == "success"


def test_successful_publickey_login():
    raw = make_raw_event(
        "Nov 18 10:00:01 lab-server sshd[1201]: "
        "Accepted publickey for analyst from "
        "192.0.2.10 port 51234 ssh2"
    )

    event = parse_ssh(raw)

    assert event is not None
    assert event.authentication_method == "publickey"
    assert event.outcome == "success"


def test_failed_login():
    raw = make_raw_event(
        "Nov 18 10:01:15 lab-server sshd[1202]: "
        "Failed password for root from "
        "198.51.100.25 port 45123 ssh2"
    )

    event = parse_ssh(raw)

    assert event is not None
    assert event.event_type == "ssh_login_failed"
    assert event.username == "root"
    assert event.outcome == "failure"


def test_invalid_user():
    raw = make_raw_event(
        "Nov 18 10:01:25 lab-server sshd[1204]: Invalid user admin from 198.51.100.25 port 45125"
    )

    event = parse_ssh(raw)

    assert event is not None
    assert event.event_type == "ssh_invalid_user"
    assert event.username == "admin"


def test_failed_invalid_user():
    raw = make_raw_event(
        "Nov 18 10:01:25 lab-server sshd[1204]: "
        "Failed password for invalid user admin from "
        "198.51.100.25 port 45125 ssh2"
    )

    event = parse_ssh(raw)

    assert event is not None
    assert event.username == "admin"
    assert event.outcome == "failure"


def test_ipv6_login():
    raw = make_raw_event(
        "Nov 18 10:00:01 lab-server sshd[1201]: "
        "Accepted password for analyst from "
        "2001:db8::10 port 51234 ssh2"
    )

    event = parse_ssh(raw)

    assert event is not None
    assert event.source_ip == "2001:db8::10"


def test_invalid_ip():
    raw = make_raw_event(
        "Nov 18 10:00:01 lab-server sshd[1201]: "
        "Accepted password for analyst from "
        "999.999.999.999 port 51234 ssh2"
    )

    assert parse_ssh(raw) is None


def test_invalid_port():
    raw = make_raw_event(
        "Nov 18 10:00:01 lab-server sshd[1201]: "
        "Accepted password for analyst from "
        "192.0.2.10 port 99999 ssh2"
    )

    assert parse_ssh(raw) is None


def test_malformed_log():
    raw = make_raw_event("Invalid log format")

    assert parse_ssh(raw) is None


def test_non_ssh_log():
    raw = make_raw_event("Nov 18 10:00:01 lab-server sudo[1234]: Some sudo activity")

    assert parse_ssh(raw) is None


def test_syslog_metadata():
    raw = make_raw_event(
        "Nov 18 10:00:01 lab-server sshd[1201]: "
        "Accepted password for analyst from "
        "192.0.2.10 port 51234 ssh2"
    )

    event = parse_ssh(raw)

    assert event is not None
    assert event.hostname == "lab-server"
    assert event.process_id == 1201
    assert event.process_name == "sshd"
    assert event.timestamp_original == "Nov 18 10:00:01"
    assert event.raw_event == raw


@pytest.mark.parametrize(
    "process",
    ["sshd", "sshd-session", "sshd-auth"],
)
def test_ssh_process_variants(process):
    raw = make_raw_event(
        f"Nov 18 10:00:01 lab-server {process}[1201]: "
        "Accepted password for analyst from "
        "192.0.2.10 port 51234 ssh2"
    )

    assert parse_ssh(raw) is not None
