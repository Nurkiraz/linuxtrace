"""Integration tests for the detection CLI."""

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


def populate_database(path, count):
    database = Database(path)
    database.initialize()

    events = []

    for index in range(count):
        raw = f"Failed SSH authentication {index}"

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
                timestamp=datetime(2026, 11, 28, 10, 0, tzinfo=UTC) + timedelta(seconds=index * 30),
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


def test_detection_cli_finds_bruteforce(tmp_path):
    db_path = tmp_path / "events.db"
    populate_database(db_path, 5)

    result = runner.invoke(
        app,
        ["detect", "ssh-bruteforce", "--db", str(db_path)],
    )

    assert result.exit_code == 0, result.output
    assert "Findings: 1" in result.output
    assert "192.0.2.15" in result.output


def test_detection_cli_json(tmp_path):
    db_path = tmp_path / "events.db"
    populate_database(db_path, 5)

    result = runner.invoke(
        app,
        ["detect", "ssh-bruteforce", "--db", str(db_path), "--json"],
    )

    assert result.exit_code == 0, result.output

    payload = json.loads(result.output)

    assert payload["total_findings"] == 1
    assert payload["findings"][0]["rule_id"] == "LT-SSH-001"
    assert len(payload["findings"][0]["related_event_ids"]) == 5


def test_detection_cli_no_findings(tmp_path):
    db_path = tmp_path / "events.db"
    populate_database(db_path, 4)

    result = runner.invoke(
        app,
        ["detect", "ssh-bruteforce", "--db", str(db_path)],
    )

    assert result.exit_code == 0, result.output
    assert "Findings: 0" in result.output


def test_detection_cli_missing_database(tmp_path):
    db_path = tmp_path / "missing.db"

    result = runner.invoke(
        app,
        ["detect", "ssh-bruteforce", "--db", str(db_path)],
    )

    assert result.exit_code == 1
    assert not db_path.exists()


def test_detection_does_not_modify_database(tmp_path):
    db_path = tmp_path / "events.db"
    populate_database(db_path, 5)

    before = db_path.read_bytes()

    result = runner.invoke(
        app,
        ["detect", "ssh-bruteforce", "--db", str(db_path)],
    )

    assert result.exit_code == 0, result.output
    assert db_path.read_bytes() == before


def test_detection_cli_relative_database_path(tmp_path, monkeypatch):
    db_path = tmp_path / "events.db"
    populate_database(db_path, 5)

    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        ["detect", "ssh-bruteforce", "--db", "events.db"],
    )

    assert result.exit_code == 0, result.output
    assert "Findings: 1" in result.output
