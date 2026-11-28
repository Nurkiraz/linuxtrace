import json
import sqlite3
from pathlib import Path

from typer.testing import CliRunner

from linuxtrace.cli import app
from linuxtrace.collectors.audit_import import import_audit

runner = CliRunner()

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/audit"


def prepare(tmp_path):
    db_path = tmp_path / "events.db"

    result = import_audit(FIXTURE, db_path)
    assert result.errors == []

    with sqlite3.connect(db_path) as connection:
        event_id = connection.execute(
            """
            SELECT event_id FROM events
            WHERE event_type = 'audit_syscall'
            LIMIT 1
            """
        ).fetchone()[0]

    return db_path, event_id


def run_cli(db_path, event_id, *extra):
    return runner.invoke(
        app,
        [
            "event",
            "evidence",
            event_id,
            "--db",
            str(db_path),
            *extra,
        ],
    )


def test_evidence_command_shows_four_records(tmp_path):
    db_path, event_id = prepare(tmp_path)

    result = run_cli(db_path, event_id)

    assert result.exit_code == 0, result.output
    assert "Evidence records: 4" in result.output
    assert "SYSCALL" in result.output
    assert "EXECVE" in result.output
    assert "CWD" in result.output
    assert "PATH" in result.output
    assert "Hash verification: VALID" in result.output


def test_evidence_json_output(tmp_path):
    db_path, event_id = prepare(tmp_path)

    result = run_cli(db_path, event_id, "--json")

    assert result.exit_code == 0, result.output

    payload = json.loads(result.output)

    assert payload["event_id"] == event_id
    assert payload["evidence_count"] == 4
    assert payload["all_hashes_valid"] is True
    assert len(payload["evidence"]) == 4


def test_unknown_event_returns_error(tmp_path):
    db_path, _ = prepare(tmp_path)

    result = run_cli(db_path, "unknown-event")

    assert result.exit_code == 1
    assert "No audit evidence found" in result.output


def test_corrupted_evidence_is_reported(tmp_path):
    db_path, event_id = prepare(tmp_path)

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            UPDATE audit_event_evidence
            SET raw_log = 'tampered'
            WHERE event_id = ?
              AND record_type = 'SYSCALL'
            """,
            (event_id,),
        )

    result = run_cli(db_path, event_id)

    assert result.exit_code == 2
    assert "MISMATCH" in result.output
