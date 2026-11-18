import hashlib
import io
import json

from linuxtrace.collectors import journal
from linuxtrace.collectors.journal import JournalCollector


class FakeProcess:
    """Controlled subprocess replacement for tests."""

    def __init__(self, output, returncode=0):
        self.stdout = io.BytesIO(output)
        self.returncode = returncode

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stdout.close()

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.returncode = -9


def configure_process(monkeypatch, output, returncode=0):
    monkeypatch.setattr(
        journal.shutil,
        "which",
        lambda name: "/usr/bin/journalctl",
    )

    commands = []

    def fake_popen(command, **kwargs):
        commands.append(command)

        assert kwargs["shell"] is False

        return FakeProcess(output, returncode)

    monkeypatch.setattr(
        journal.subprocess,
        "Popen",
        fake_popen,
    )

    return commands


def make_record(message="Test event"):
    return (
        json.dumps(
            {
                "MESSAGE": message,
                "_HOSTNAME": "lab-server",
                "SYSLOG_IDENTIFIER": "systemd",
                "__REALTIME_TIMESTAMP": "1794996000000000",
            }
        ).encode()
        + b"\n"
    )


def test_collect_valid_record(monkeypatch):
    output = make_record()

    configure_process(monkeypatch, output)

    collector = JournalCollector()
    events = list(collector.collect())

    assert len(events) == 1
    assert events[0].source == "journal"
    assert events[0].source_line == 1
    assert events[0].metadata["MESSAGE"] == "Test event"
    assert collector.errors == []


def test_multiple_records(monkeypatch):
    output = make_record("First") + make_record("Second")

    configure_process(monkeypatch, output)

    collector = JournalCollector()
    events = list(collector.collect())

    assert len(events) == 2
    assert events[0].source_line == 1
    assert events[1].source_line == 2


def test_evidence_hash(monkeypatch):
    output = make_record()

    configure_process(monkeypatch, output)

    collector = JournalCollector()
    events = list(collector.collect())

    expected = hashlib.sha256(output).hexdigest()

    assert events[0].evidence_hash == expected


def test_invalid_json(monkeypatch):
    output = b"Invalid JSON\n" + make_record()

    configure_process(monkeypatch, output)

    collector = JournalCollector()
    events = list(collector.collect())

    assert len(events) == 1
    assert events[0].source_line == 2
    assert "Invalid JSON at line 1" in collector.errors


def test_non_object_json(monkeypatch):
    configure_process(monkeypatch, b"[1, 2, 3]\n")

    collector = JournalCollector()
    events = list(collector.collect())

    assert events == []
    assert len(collector.errors) == 1


def test_empty_output(monkeypatch):
    configure_process(monkeypatch, b"")

    collector = JournalCollector()

    assert list(collector.collect()) == []
    assert collector.errors == []


def test_journalctl_unavailable(monkeypatch):
    monkeypatch.setattr(
        journal.shutil,
        "which",
        lambda name: None,
    )

    collector = JournalCollector()

    assert list(collector.collect()) == []
    assert "journalctl is not available" in collector.errors


def test_invalid_record_limit(monkeypatch):
    configure_process(monkeypatch, b"")

    collector = JournalCollector()

    assert list(collector.collect(limit=0)) == []
    assert "Invalid journal record limit" in collector.errors


def test_excessive_record_limit(monkeypatch):
    configure_process(monkeypatch, b"")

    collector = JournalCollector()

    assert list(collector.collect(limit=10001)) == []
    assert "Invalid journal record limit" in collector.errors


def test_output_size_limit(monkeypatch):
    configure_process(monkeypatch, make_record())

    monkeypatch.setattr(
        journal,
        "MAX_OUTPUT_BYTES",
        10,
    )

    collector = JournalCollector()

    assert list(collector.collect()) == []
    assert "Journal output limit exceeded" in collector.errors


def test_record_size_limit(monkeypatch):
    output = b"A" * (1024 * 1024 + 2)

    configure_process(monkeypatch, output)

    collector = JournalCollector()

    assert list(collector.collect()) == []
    assert "Journal record size limit exceeded" in collector.errors


def test_identifier_filter(monkeypatch):
    commands = configure_process(monkeypatch, b"")

    collector = JournalCollector()

    list(collector.collect(limit=5, identifier="sudo"))

    command = commands[0]

    assert "--lines=5" in command
    assert "--identifier" in command
    assert "sudo" in command


def test_date_filters(monkeypatch):
    commands = configure_process(monkeypatch, b"")

    collector = JournalCollector()

    list(
        collector.collect(
            since="2026-11-18 00:00:00",
            until="2026-11-18 23:59:59",
        )
    )

    command = commands[0]

    assert "--since" in command
    assert "--until" in command
    assert "2026-11-18 00:00:00" in command
    assert "2026-11-18 23:59:59" in command


def test_process_failure(monkeypatch):
    configure_process(monkeypatch, b"", returncode=1)

    collector = JournalCollector()

    assert list(collector.collect()) == []
    assert "journalctl exited with code 1" in collector.errors


def test_subprocess_permission_error(monkeypatch):
    configure_process(monkeypatch, b"")

    def deny_access(*args, **kwargs):
        raise PermissionError("Access denied")

    monkeypatch.setattr(
        journal.subprocess,
        "Popen",
        deny_access,
    )

    collector = JournalCollector()

    assert list(collector.collect()) == []
    assert "Access denied" in collector.errors
