import hashlib

import pytest

from linuxtrace.models.raw_event import RawEvent
from linuxtrace.parsers.sudo import parse_sudo


def make_raw_event(message: str) -> RawEvent:
    return RawEvent(
        source="authentication",
        source_file="/var/log/auth.log",
        source_line=1,
        raw_log=message,
        evidence_hash=hashlib.sha256(message.encode("utf-8")).hexdigest(),
    )


def test_allowed_command():
    raw = make_raw_event(
        "Nov 18 10:03:00 lab-server sudo[1301]: "
        "analyst : TTY=pts/0 ; PWD=/home/analyst ; "
        "USER=root ; COMMAND=/usr/bin/id"
    )

    event = parse_sudo(raw)

    assert event is not None
    assert event.event_type == "sudo_command_allowed"
    assert event.username == "analyst"
    assert event.actor_user == "analyst"
    assert event.target_user == "root"
    assert event.command == "/usr/bin/id"
    assert event.outcome == "success"


def test_user_not_in_sudoers():
    raw = make_raw_event(
        "Nov 18 10:03:00 lab-server sudo[1301]: "
        "guest : user NOT in sudoers ; "
        "TTY=pts/0 ; PWD=/home/guest ; "
        "USER=root ; COMMAND=/usr/bin/id"
    )

    event = parse_sudo(raw)

    assert event is not None
    assert event.event_type == "sudo_command_denied"
    assert event.outcome == "failure"
    assert event.severity == "medium"


def test_incorrect_password():
    raw = make_raw_event(
        "Nov 18 10:03:00 lab-server sudo[1301]: "
        "analyst : 3 incorrect password attempts ; "
        "TTY=pts/0 ; USER=root"
    )

    event = parse_sudo(raw)

    assert event is not None
    assert event.event_type == "sudo_command_denied"


def test_command_not_allowed():
    raw = make_raw_event(
        "Nov 18 10:03:00 lab-server sudo[1301]: "
        "analyst : command not allowed ; "
        "TTY=pts/0 ; USER=root ; "
        "COMMAND=/usr/bin/id"
    )

    event = parse_sudo(raw)

    assert event is not None
    assert event.outcome == "failure"


def test_command_with_arguments():
    raw = make_raw_event(
        "Nov 18 10:03:00 lab-server sudo[1301]: "
        "analyst : TTY=pts/0 ; USER=root ; "
        "COMMAND=/usr/bin/ls -lah /etc"
    )

    event = parse_sudo(raw)

    assert event is not None
    assert event.command == "/usr/bin/ls -lah /etc"


def test_command_with_semicolon():
    raw = make_raw_event(
        "Nov 18 10:03:00 lab-server sudo[1301]: "
        "analyst : USER=root ; "
        "COMMAND=/bin/sh -c 'id; whoami'"
    )

    event = parse_sudo(raw)

    assert event is not None
    assert event.command == "/bin/sh -c 'id; whoami'"


def test_command_with_equals():
    raw = make_raw_event(
        "Nov 18 10:03:00 lab-server sudo[1301]: "
        "analyst : USER=root ; "
        "COMMAND=/usr/bin/echo KEY=value"
    )

    event = parse_sudo(raw)

    assert event is not None
    assert event.command == "/usr/bin/echo KEY=value"


def test_working_directory_and_terminal():
    raw = make_raw_event(
        "Nov 18 10:03:00 lab-server sudo[1301]: "
        "analyst : TTY=pts/2 ; PWD=/tmp ; "
        "USER=root ; COMMAND=/usr/bin/id"
    )

    event = parse_sudo(raw)

    assert event is not None
    assert event.working_directory == "/tmp"
    assert event.terminal == "pts/2"


def test_non_root_target():
    raw = make_raw_event(
        "Nov 18 10:03:00 lab-server sudo[1301]: analyst : USER=postgres ; COMMAND=/usr/bin/id"
    )

    event = parse_sudo(raw)

    assert event is not None
    assert event.target_user == "postgres"


def test_pam_message_ignored():
    raw = make_raw_event(
        "Nov 18 10:03:00 lab-server sudo[1301]: "
        "pam_unix(sudo:session): session opened "
        "for user root(uid=0)"
    )

    assert parse_sudo(raw) is None


def test_non_sudo_log():
    raw = make_raw_event("Nov 18 10:03:00 lab-server sshd[1301]: Accepted password for analyst")

    assert parse_sudo(raw) is None


def test_malformed_log():
    raw = make_raw_event("Invalid sudo log")

    assert parse_sudo(raw) is None


def test_sudo_metadata():
    raw = make_raw_event(
        "Nov 18 10:03:00 lab-server sudo[1301]: analyst : USER=root ; COMMAND=/usr/bin/id"
    )

    event = parse_sudo(raw)

    assert event is not None
    assert event.hostname == "lab-server"
    assert event.process_name == "sudo"
    assert event.process_id == 1301
    assert event.event_category == "privilege"
    assert event.raw_event == raw


@pytest.mark.parametrize(
    "reason",
    [
        "authentication failure",
        "a password is required",
    ],
)
def test_denied_variants(reason):
    raw = make_raw_event(f"Nov 18 10:03:00 lab-server sudo[1301]: analyst : {reason} ; USER=root")

    event = parse_sudo(raw)

    assert event is not None
    assert event.event_type == "sudo_command_denied"
    assert event.outcome == "failure"
