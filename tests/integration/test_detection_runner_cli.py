"""Integration tests for the unified detection runner."""

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


def prepare_database(path):
    database = Database(path)
    database.initialize()

    start = datetime(2026, 11, 28, 10, 0, tzinfo=UTC)
    events = []

    for index in range(6):
        success = index == 5
        raw = f"Runner SSH event {index}"

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
                event_type=("ssh_login_success" if success else "ssh_login_failed"),
                severity="info" if success else "low",
                username="admin",
                source_ip="192.0.2.15",
                outcome="success" if success else "failure",
                description=raw,
            )
        )

    EventRepository(database).insert_events(events)


def test_runner_detects_both_rules(tmp_path):
    path = tmp_path / "events.db"
    prepare_database(path)

    result = runner.invoke(
        app,
        ["detect", "run", "--db", str(path), "--json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)

    assert payload["total_findings"] == 2
    assert {item["rule_id"] for item in payload["findings"]} == {
        "LT-SSH-001",
        "LT-SSH-002",
    }


def test_runner_save_is_idempotent(tmp_path):
    path = tmp_path / "events.db"
    prepare_database(path)

    args = ["detect", "run", "--db", str(path), "--save", "--json"]
    first = runner.invoke(app, args)
    second = runner.invoke(app, args)

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    assert json.loads(first.output)["saved_findings"] == 2
    assert json.loads(second.output)["saved_findings"] == 0


def test_runner_without_save_is_read_only(tmp_path):
    path = tmp_path / "events.db"
    prepare_database(path)

    before = path.read_bytes()

    result = runner.invoke(
        app,
        ["detect", "run", "--db", str(path)],
    )

    assert result.exit_code == 0, result.output
    assert path.read_bytes() == before


def test_runner_missing_database(tmp_path):
    path = tmp_path / "missing.db"

    result = runner.invoke(
        app,
        ["detect", "run", "--db", str(path)],
    )

    assert result.exit_code == 1
    assert not path.exists()
