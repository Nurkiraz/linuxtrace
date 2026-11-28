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
            SELECT event_id
            FROM events
            WHERE event_type = 'audit_syscall'
            LIMIT 1
            """
        ).fetchone()[0]

    return db_path, event_id


def run_show(db_path, event_id, *options):
    return runner.invoke(
        app,
        [
            "event",
            "show",
            event_id,
            "--db",
            str(db_path),
            *options,
        ],
    )


def test_existing_event_show_unchanged(tmp_path):
    db_path, event_id = prepare(tmp_path)

    result = run_show(db_path, event_id)

    assert result.exit_code == 0, result.output
    assert "Event Detail" in result.output
    assert "Related Audit Evidence" not in result.output


def test_show_includes_audit_evidence(tmp_path):
    db_path, event_id = prepare(tmp_path)

    result = run_show(db_path, event_id, "--evidence")

    assert result.exit_code == 0, result.output
    assert "Evidence records: 4" in result.output

    for record_type in ("SYSCALL", "EXECVE", "CWD", "PATH"):
        assert record_type in result.output

    assert result.output.count("Hash verification: VALID") == 4


def test_show_evidence_json(tmp_path):
    db_path, event_id = prepare(tmp_path)

    result = run_show(
        db_path,
        event_id,
        "--evidence",
        "--json",
    )

    assert result.exit_code == 0, result.output

    payload = json.loads(result.output)

    assert payload["event_id"] == event_id
    assert payload["audit_evidence"]["count"] == 4
    assert payload["audit_evidence"]["all_hashes_valid"] is True
    assert len(payload["audit_evidence"]["records"]) == 4


def test_show_evidence_detects_tampering(tmp_path):
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

    result = run_show(db_path, event_id, "--evidence")

    assert result.exit_code == 2
    assert "MISMATCH" in result.output
