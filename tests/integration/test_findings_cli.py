"""Tests for persisted security findings CLI."""

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


def build_database(path):
    database = Database(path)
    database.initialize()

    start = datetime(2026, 11, 28, 10, 0, tzinfo=UTC)
    events = []

    for index in range(5):
        raw = f"Failed SSH attempt {index}"

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
                event_type="ssh_login_failed",
                severity="low",
                source_ip="192.0.2.15",
                outcome="failure",
                description=raw,
            )
        )

    EventRepository(database).insert_events(events)


def run_detection(path):
    return runner.invoke(
        app,
        [
            "detect",
            "ssh-bruteforce",
            "--db",
            str(path),
            "--save",
            "--json",
        ],
    )


def test_detect_and_save(tmp_path):
    path = tmp_path / "events.db"
    build_database(path)

    result = run_detection(path)

    assert result.exit_code == 0, result.output

    payload = json.loads(result.output)

    assert payload["total_findings"] == 1
    assert payload["saved_findings"] == 1


def test_duplicate_detection_is_not_saved_twice(tmp_path):
    path = tmp_path / "events.db"
    build_database(path)

    first = run_detection(path)
    second = run_detection(path)

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output

    assert json.loads(first.output)["saved_findings"] == 1
    assert json.loads(second.output)["saved_findings"] == 0


def test_findings_list_json(tmp_path):
    path = tmp_path / "events.db"
    build_database(path)
    assert run_detection(path).exit_code == 0

    result = runner.invoke(
        app,
        ["findings", "list", "--db", str(path), "--json"],
    )

    assert result.exit_code == 0, result.output

    payload = json.loads(result.output)

    assert payload["total_findings"] == 1
    assert payload["findings"][0]["rule_id"] == "LT-SSH-001"


def test_findings_show_json(tmp_path):
    path = tmp_path / "events.db"
    build_database(path)

    saved = run_detection(path)
    finding_id = json.loads(saved.output)["findings"][0]["finding_id"]

    result = runner.invoke(
        app,
        [
            "findings",
            "show",
            finding_id,
            "--db",
            str(path),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output

    payload = json.loads(result.output)

    assert payload["finding_id"] == finding_id
    assert len(payload["related_event_ids"]) == 5


def test_findings_list_severity_filter(tmp_path):
    path = tmp_path / "events.db"
    build_database(path)
    assert run_detection(path).exit_code == 0

    result = runner.invoke(
        app,
        [
            "findings",
            "list",
            "--db",
            str(path),
            "--severity",
            "medium",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["total_findings"] == 0


def test_findings_show_missing_id(tmp_path):
    path = tmp_path / "events.db"
    build_database(path)
    assert run_detection(path).exit_code == 0

    result = runner.invoke(
        app,
        [
            "findings",
            "show",
            "0" * 64,
            "--db",
            str(path),
        ],
    )

    assert result.exit_code == 1
    assert "Finding not found" in result.output


def test_detection_without_save_remains_read_only(tmp_path):
    path = tmp_path / "events.db"
    build_database(path)

    before = path.read_bytes()

    result = runner.invoke(
        app,
        ["detect", "ssh-bruteforce", "--db", str(path)],
    )

    assert result.exit_code == 0, result.output
    assert path.read_bytes() == before
