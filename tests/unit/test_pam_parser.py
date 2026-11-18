import hashlib

import pytest

from linuxtrace.models.raw_event import RawEvent
from linuxtrace.parsers.pam import parse_pam


def make_raw_event(message: str) -> RawEvent:
    return RawEvent(
        source="authentication",
        source_file="/var/log/auth.log",
        source_line=1,
        raw_log=message,
        evidence_hash=hashlib.sha256(message.encode("utf-8")).hexdigest(),
    )


def test_session_opened():
    raw = make_raw_event(
        "Nov 18 10:00:01 lab-server sudo[1201]: "
        "pam_unix(sudo:session): session opened "
        "for user root(uid=0) by analyst(uid=1000)"
    )

    event = parse_pam(raw)

    assert event is not None
    assert event.event_type == "pam_session_opened"
    assert event.username == "root"
    assert event.user_id == 0
    assert event.actor_user == "analyst"
    assert event.actor_uid == 1000
    assert event.outcome == "success"


def test_session_closed():
    raw = make_raw_event(
        "Nov 18 10:00:05 lab-server sudo[1201]: "
        "pam_unix(sudo:session): session closed "
        "for user root"
    )

    event = parse_pam(raw)

    assert event is not None
    assert event.event_type == "pam_session_closed"
    assert event.username == "root"


def test_authentication_failure():
    raw = make_raw_event(
        "Nov 18 10:01:00 lab-server sshd[1202]: "
        "pam_unix(sshd:auth): authentication failure; "
        "logname= uid=0 euid=0 tty=ssh "
        "ruser= rhost=192.0.2.25 user=admin"
    )

    event = parse_pam(raw)

    assert event is not None
    assert event.event_type == "pam_authentication_failed"
    assert event.username == "admin"
    assert event.source_ip == "192.0.2.25"
    assert event.terminal == "ssh"
    assert event.outcome == "failure"


def test_ipv6_authentication_failure():
    raw = make_raw_event(
        "Nov 18 10:01:00 lab-server sshd[1202]: "
        "pam_unix(sshd:auth): authentication failure; "
        "rhost=2001:db8::25 user=admin"
    )

    event = parse_pam(raw)

    assert event is not None
    assert event.source_ip == "2001:db8::25"


def test_missing_uid():
    raw = make_raw_event(
        "Nov 18 10:00:01 lab-server login[1201]: "
        "pam_unix(login:session): session opened "
        "for user analyst"
    )

    event = parse_pam(raw)

    assert event is not None
    assert event.username == "analyst"
    assert event.user_id is None
    assert event.actor_uid is None


def test_missing_username():
    raw = make_raw_event(
        "Nov 18 10:01:00 lab-server sshd[1202]: "
        "pam_unix(sshd:auth): authentication failure; "
        "rhost=192.0.2.25 user="
    )

    event = parse_pam(raw)

    assert event is not None
    assert event.username is None


def test_invalid_remote_ip():
    raw = make_raw_event(
        "Nov 18 10:01:00 lab-server sshd[1202]: "
        "pam_unix(sshd:auth): authentication failure; "
        "rhost=unknown-host user=admin"
    )

    event = parse_pam(raw)

    assert event is not None
    assert event.source_ip is None


def test_pam_metadata():
    raw = make_raw_event(
        "Nov 18 10:00:01 lab-server sudo[1201]: "
        "pam_unix(sudo:session): session opened "
        "for user root(uid=0)"
    )

    event = parse_pam(raw)

    assert event is not None
    assert event.pam_module == "pam_unix"
    assert event.pam_service == "sudo"
    assert event.pam_type == "session"
    assert event.process_id == 1201
    assert event.hostname == "lab-server"


def test_malformed_log():
    raw = make_raw_event("Invalid PAM log")

    assert parse_pam(raw) is None


def test_non_pam_log():
    raw = make_raw_event("Nov 18 10:00:01 lab-server sshd[1201]: Accepted password for analyst")

    assert parse_pam(raw) is None


def test_unhandled_pam_message():
    raw = make_raw_event(
        "Nov 18 10:00:01 lab-server sudo[1201]: pam_unix(sudo:auth): conversation failed"
    )

    assert parse_pam(raw) is None


@pytest.mark.parametrize(
    "service",
    ["sudo", "sshd", "su", "login"],
)
def test_pam_service_variants(service):
    raw = make_raw_event(
        f"Nov 18 10:00:01 lab-server {service}[1201]: "
        f"pam_unix({service}:session): "
        "session opened for user analyst(uid=1000)"
    )

    event = parse_pam(raw)

    assert event is not None
    assert event.pam_service == service
    assert event.process_name == service
