from contextlib import closing
from pathlib import Path

from linuxtrace.collectors.audit_import import import_audit
from linuxtrace.storage.database import Database
from linuxtrace.storage.event_repository import EventRepository

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/audit"


def read_rows(database, sql):
    with closing(database.connect()) as connection:
        return connection.execute(sql).fetchall()


def test_audit_import_creates_two_timeline_events(tmp_path):
    db_path = tmp_path / "events.db"

    result = import_audit(FIXTURE, db_path)

    assert result.errors == []
    assert result.records_read == 5
    assert result.groups_read == 2
    assert result.events_inserted == 2
    assert result.evidence_inserted == 5

    database = Database(db_path)
    assert EventRepository(database).count_events() == 2


def test_audit_import_preserves_raw_evidence(tmp_path):
    db_path = tmp_path / "events.db"

    result = import_audit(FIXTURE, db_path)
    assert result.errors == []

    database = Database(db_path)

    evidence = read_rows(
        database,
        """
        SELECT record_type, source_file, source_line,
               evidence_hash, raw_log
        FROM audit_event_evidence
        ORDER BY source_line
        """,
    )

    assert len(evidence) == 5
    assert [row["record_type"] for row in evidence] == [
        "SYSCALL",
        "EXECVE",
        "CWD",
        "PATH",
        "USER_LOGIN",
    ]

    assert all(row["evidence_hash"] for row in evidence)
    assert all(row["raw_log"] for row in evidence)


def test_audit_import_is_idempotent(tmp_path):
    db_path = tmp_path / "events.db"

    first = import_audit(FIXTURE, db_path)
    second = import_audit(FIXTURE, db_path)

    assert first.errors == []
    assert second.errors == []

    assert first.events_inserted == 2
    assert second.events_inserted == 0
    assert second.evidence_inserted == 0

    database = Database(db_path)

    assert EventRepository(database).count_events() == 2

    evidence = read_rows(
        database,
        "SELECT * FROM audit_event_evidence",
    )
    assert len(evidence) == 5


def test_audit_event_has_process_details(tmp_path):
    db_path = tmp_path / "events.db"

    result = import_audit(FIXTURE, db_path)
    assert result.errors == []

    database = Database(db_path)

    events = read_rows(
        database,
        """
        SELECT event_type, process_name,
               process_id, command, description
        FROM events
        WHERE event_type = 'audit_syscall'
        """,
    )

    assert len(events) == 1
    assert events[0]["process_name"] == "cat"
    assert events[0]["process_id"] == 1200
    assert events[0]["command"] == "cat /etc/hosts"
    assert "/etc/hosts" in events[0]["description"]
