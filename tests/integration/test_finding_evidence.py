"""Tests for finding-to-event evidence verification."""

import json
import sqlite3
from datetime import UTC, datetime
from hashlib import sha256

from typer.testing import CliRunner

from linuxtrace.cli import app
from linuxtrace.detection.models import FindingSeverity, SecurityFinding
from linuxtrace.detection.repository import FindingRepository
from linuxtrace.models.normalized_event import NormalizedEvent
from linuxtrace.models.raw_event import RawEvent
from linuxtrace.storage.database import Database
from linuxtrace.storage.event_repository import EventRepository

runner = CliRunner()


def prepare(tmp_path):
    path = tmp_path / "events.db"
    database = Database(path)
    database.initialize()

    raw = "Failed password for root from 192.0.2.15"
    event_id = sha256(raw.encode()).hexdigest()
    timestamp = datetime(2026, 11, 28, 10, 0, tzinfo=UTC)

    event = NormalizedEvent(
        event_id=event_id,
        raw_event=RawEvent(
            source="auth",
            source_file="/var/log/auth.log",
            source_line=1,
            raw_log=raw,
            evidence_hash=sha256(raw.encode()).hexdigest(),
        ),
        timestamp=timestamp,
        hostname="server1",
        event_category="authentication",
        event_type="ssh_login_failed",
        severity="low",
        source_ip="192.0.2.15",
        outcome="failure",
        description=raw,
    )

    EventRepository(database).insert_event(event)

    finding = SecurityFinding(
        finding_id="a" * 64,
        rule_id="LT-SSH-001",
        title="SSH Brute-Force Detected",
        description="Repeated SSH authentication failures.",
        severity=FindingSeverity.HIGH,
        start_time=timestamp,
        end_time=timestamp,
        source_ip="192.0.2.15",
        related_event_ids=[event_id],
    )

    repository = FindingRepository(database)
    repository.initialize()
    repository.save(finding)

    return path, finding, event_id


def test_valid_linked_event(tmp_path):
    path, finding, event_id = prepare(tmp_path)

    result = runner.invoke(
        app,
        [
            "findings",
            "show",
            finding.finding_id,
            "--db",
            str(path),
            "--events",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output

    evidence = json.loads(result.output)["linked_evidence"]

    assert evidence["all_references_valid"] is True
    assert evidence["verified_events"] == 1
    assert evidence["events"][0]["event_id"] == event_id


def test_missing_linked_event(tmp_path):
    path, finding, event_id = prepare(tmp_path)

    with sqlite3.connect(path) as connection:
        connection.execute(
            "DELETE FROM events WHERE event_id = ?",
            (event_id,),
        )

    result = runner.invoke(
        app,
        [
            "findings",
            "show",
            finding.finding_id,
            "--db",
            str(path),
            "--events",
        ],
    )

    assert result.exit_code == 2
    assert "Missing event" in result.output


def test_mismatched_event_json(tmp_path):
    path, finding, event_id = prepare(tmp_path)

    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT event_json FROM events WHERE event_id = ?",
            (event_id,),
        ).fetchone()

        payload = json.loads(row[0])
        payload["event_id"] = "b" * 64

        connection.execute(
            "UPDATE events SET event_json = ? WHERE event_id = ?",
            (json.dumps(payload), event_id),
        )

    result = runner.invoke(
        app,
        [
            "findings",
            "show",
            finding.finding_id,
            "--db",
            str(path),
            "--events",
        ],
    )

    assert result.exit_code == 2
    assert "Invalid event" in result.output
