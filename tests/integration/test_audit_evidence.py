import hashlib
import sqlite3
from pathlib import Path

import pytest

from linuxtrace.collectors.audit_import import import_audit
from linuxtrace.storage.audit_evidence import (
    AuditEvidenceError,
    get_audit_evidence,
)

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/audit"


def prepare(tmp_path):
    db_path = tmp_path / "events.db"
    result = import_audit(FIXTURE, db_path)

    assert result.errors == []

    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT event_id, event_type
            FROM events
            ORDER BY event_type
            """
        ).fetchall()

    return db_path, dict((event_type, event_id) for event_id, event_type in rows)


def test_syscall_evidence_contains_four_records(tmp_path):
    db_path, ids = prepare(tmp_path)

    records = get_audit_evidence(
        db_path,
        ids["audit_syscall"],
    )

    assert len(records) == 4
    assert {record.record_type for record in records} == {
        "SYSCALL",
        "EXECVE",
        "CWD",
        "PATH",
    }
    assert all(record.hash_valid for record in records)


def test_login_evidence_is_separate(tmp_path):
    db_path, ids = prepare(tmp_path)

    records = get_audit_evidence(
        db_path,
        ids["audit_user_login"],
    )

    assert len(records) == 1
    assert records[0].record_type == "USER_LOGIN"
    assert records[0].audit_serial == 451


def test_modified_stored_raw_log_is_detected(tmp_path):
    db_path, ids = prepare(tmp_path)
    event_id = ids["audit_syscall"]

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            UPDATE audit_event_evidence
            SET raw_log = 'modified evidence'
            WHERE event_id = ?
              AND record_type = 'SYSCALL'
            """,
            (event_id,),
        )

    records = get_audit_evidence(db_path, event_id)

    assert len(records) == 4
    assert sum(not record.hash_valid for record in records) == 1


def test_hash_algorithm_matches_source(tmp_path):
    db_path, ids = prepare(tmp_path)

    records = get_audit_evidence(
        db_path,
        ids["audit_syscall"],
    )

    for record in records:
        expected = hashlib.sha256(record.raw_log.encode("utf-8")).hexdigest()

        assert record.evidence_hash == expected


def test_unknown_event_returns_empty_list(tmp_path):
    db_path, _ = prepare(tmp_path)

    assert (
        get_audit_evidence(
            db_path,
            "nonexistent-event-id",
        )
        == []
    )


def test_missing_database_is_not_created(tmp_path):
    db_path = tmp_path / "missing.db"

    with pytest.raises(
        AuditEvidenceError,
        match="Database does not exist",
    ):
        get_audit_evidence(db_path, "test")

    assert not db_path.exists()
