import gzip
from collections import Counter
from pathlib import Path

from linuxtrace.collectors.authentication import (
    AuthenticationCollector,
)
from linuxtrace.parsers.authentication import (
    parse_authentication,
)

FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "evidence"


def test_complete_authentication_pipeline():
    collector = AuthenticationCollector(FIXTURE_ROOT)

    events = [parse_authentication(raw) for raw in collector.collect()]

    counts = Counter(event.event_type for event in events)

    assert len(events) == 8
    assert counts["ssh_login_success"] == 2
    assert counts["ssh_login_failed"] == 2
    assert counts["ssh_invalid_user"] == 1
    assert counts["sudo_command_allowed"] == 1
    assert counts["pam_session_opened"] == 1
    assert counts["pam_session_closed"] == 1


def test_gzip_authentication_pipeline(tmp_path):
    directory = tmp_path / "var/log"
    directory.mkdir(parents=True)

    path = directory / "auth.log.1.gz"

    with gzip.open(path, "wt") as file:
        file.write(
            "Nov 18 10:00:01 lab-server sshd[1201]: "
            "Accepted password for analyst from "
            "192.0.2.10 port 51234 ssh2\n"
        )

    collector = AuthenticationCollector(tmp_path)

    events = [parse_authentication(raw) for raw in collector.collect()]

    assert len(events) == 1
    assert events[0].event_type == "ssh_login_success"
    assert events[0].username == "analyst"


def test_evidence_preservation():
    collector = AuthenticationCollector(FIXTURE_ROOT)

    for raw in collector.collect():
        event = parse_authentication(raw)

        assert event.raw_event == raw
        assert event.raw_event.evidence_hash
        assert event.raw_event.source_file
        assert event.raw_event.source_line >= 1


def test_unclassified_event_preservation(tmp_path):
    directory = tmp_path / "var/log"
    directory.mkdir(parents=True)

    message = "Nov 18 10:00:01 lab-server sshd[1201]: Connection closed by remote host"

    (directory / "auth.log").write_text(message + "\n")

    collector = AuthenticationCollector(tmp_path)

    events = [parse_authentication(raw) for raw in collector.collect()]

    assert len(events) == 1
    assert events[0].event_type == ("authentication_unclassified")
    assert events[0].raw_event.raw_log == message


def test_missing_sources_pipeline(tmp_path):
    collector = AuthenticationCollector(tmp_path)

    events = [parse_authentication(raw) for raw in collector.collect()]

    assert events == []
    assert collector.errors
