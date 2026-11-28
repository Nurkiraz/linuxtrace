"""End-to-end tests for registered SSH password spraying detection."""

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


def prepare_spraying_database(path):
    database = Database(path)
    database.initialize()

    start = datetime(2026, 11, 28, 10, 0, tzinfo=UTC)
    events = []
    users = ["root", "admin", "backup", "deploy", "test"]

    for index, username in enumerate(users):
        raw = f"Failed SSH login for {username}"

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
                timestamp=start + timedelta(minutes=index),
                hostname="server1",
                event_category="authentication",
                event_type="ssh_login_failed",
                severity="low",
                username=username,
                source_ip="192.0.2.15",
                outcome="failure",
                description=raw,
            )
        )

    EventRepository(database).insert_events(events)


def test_runner_detects_password_spraying(tmp_path):
    db = tmp_path / "events.db"
    prepare_spraying_database(db)

    result = runner.invoke(app, ["detect", "run", "--db", str(db), "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)

    assert payload["total_findings"] == 2
    assert {item["rule_id"] for item in payload["findings"]} == {
        "LT-SSH-001",
        "LT-SSH-003",
    }
    assert "LT-SSH-003" in payload["rules"]


def test_yaml_can_disable_spraying(tmp_path):
    db = tmp_path / "events.db"
    prepare_spraying_database(db)

    config = tmp_path / "rules.yaml"
    config.write_text("version: 1\nssh_password_spraying:\n  enabled: false\n")

    result = runner.invoke(
        app,
        [
            "detect",
            "run",
            "--db",
            str(db),
            "--config",
            str(config),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)

    assert "LT-SSH-003" not in payload["rules"]
    assert {item["rule_id"] for item in payload["findings"]} == {"LT-SSH-001"}


def test_spraying_finding_can_be_saved(tmp_path):
    db = tmp_path / "events.db"
    prepare_spraying_database(db)

    result = runner.invoke(
        app,
        [
            "detect",
            "run",
            "--db",
            str(db),
            "--save",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["saved_findings"] == 2

    listed = runner.invoke(
        app,
        ["findings", "list", "--db", str(db), "--json"],
    )

    assert listed.exit_code == 0, listed.output
    assert json.loads(listed.output)["total_findings"] == 2
