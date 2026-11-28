"""Integration tests for the SSH correlation CLI."""

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256

from typer.testing import CliRunner

from linuxtrace.cli import app
from linuxtrace.models.normalized_event import NormalizedEvent
from linuxtrace.models.raw_event import RawEvent
from linuxtrace.storage.database import Database
from linuxtrace.storage.event_repository import EventRepository

runner = CliRunner()


def prepare_database(path, *, success=True, failures=5):
    database = Database(path)
    database.initialize()

    start = datetime(2026, 11, 28, 10, 0, tzinfo=UTC)
    events = []

    for index in range(failures + int(success)):
        is_success = success and index == failures
        raw = f"SSH correlation event {index}"

        events.append(
            NormalizedEvent(
                event_id=sha256(raw.encode()).hexdigest(),
                raw_event=RawEvent(
                    source="auth",
                    source_file="/var/log/auth.log",
                    source_line=index + 1,
                    raw_log=raw,
                    evidence_hash=sha256(raw.encode()).hexdigest(),
                ),
                timestamp=start + timedelta(seconds=index * 30),
                hostname="server1",
                event_category="authentication",
                event_type=("ssh_login_success" if is_success else "ssh_login_failed"),
                severity="info" if is_success else "low",
                username="admin",
                source_ip="192.0.2.15",
                outcome="success" if is_success else "failure",
                description=raw,
            )
        )

    EventRepository(database).insert_events(events)


def invoke_detection(path, *options):
    return runner.invoke(
        app,
        [
            "detect",
            "ssh-success-after-failures",
            "--db",
            str(path),
            *options,
        ],
    )


def test_cli_detects_success_after_failures(tmp_path):
    path = tmp_path / "events.db"
    prepare_database(path)

    result = invoke_detection(path, "--json")

    assert result.exit_code == 0, result.output

    payload = json.loads(result.output)

    assert payload["total_findings"] == 1
    assert payload["findings"][0]["rule_id"] == "LT-SSH-002"
    assert payload["findings"][0]["severity"] == "critical"
    assert payload["findings"][0]["username"] == "admin"


def test_cli_saves_and_lists_finding(tmp_path):
    path = tmp_path / "events.db"
    prepare_database(path)

    result = invoke_detection(path, "--save", "--json")

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["saved_findings"] == 1

    listed = runner.invoke(
        app,
        ["findings", "list", "--db", str(path), "--json"],
    )

    assert listed.exit_code == 0, listed.output
    assert json.loads(listed.output)["total_findings"] == 1


def test_cli_does_not_save_duplicate(tmp_path):
    path = tmp_path / "events.db"
    prepare_database(path)

    first = invoke_detection(path, "--save", "--json")
    second = invoke_detection(path, "--save", "--json")

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output

    assert json.loads(first.output)["saved_findings"] == 1
    assert json.loads(second.output)["saved_findings"] == 0


def test_cli_without_save_is_read_only(tmp_path):
    path = tmp_path / "events.db"
    prepare_database(path)

    before = path.read_bytes()
    result = invoke_detection(path, "--json")

    assert result.exit_code == 0, result.output
    assert path.read_bytes() == before


def test_cli_no_success_no_finding(tmp_path):
    path = tmp_path / "events.db"
    prepare_database(path, success=False)

    result = invoke_detection(path, "--json")

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["total_findings"] == 0


def test_cli_missing_database(tmp_path):
    path = tmp_path / "missing.db"

    result = invoke_detection(path)

    assert result.exit_code == 1
    assert not path.exists()
