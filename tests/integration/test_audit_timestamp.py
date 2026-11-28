from datetime import UTC, datetime
from pathlib import Path

from linuxtrace.collectors.audit_import import import_audit
from linuxtrace.event_detail import get_event_by_id
from linuxtrace.storage.database import Database

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/audit"


def test_audit_unix_timestamp_normalized(tmp_path):
    db_path = tmp_path / "audit.db"

    result = import_audit(FIXTURE, db_path)

    assert result.errors == []
    assert result.events_inserted == 2

    database = Database(db_path)

    with database.connect() as connection:
        event_id = connection.execute(
            """
            SELECT event_id
            FROM events
            WHERE event_type = 'audit_syscall'
            LIMIT 1
            """
        ).fetchone()[0]

    event = get_event_by_id(database, event_id)

    assert event is not None

    expected = datetime.fromtimestamp(
        1794996001.123,
        tz=UTC,
    )

    assert event.timestamp is not None
    assert event.timestamp == expected
    assert event.timestamp.microsecond == 123000
    assert event.timezone == "UTC"
    assert event.timestamp_method == "audit_unix_epoch"
    assert event.timestamp_confidence.value != "unknown"
    assert not any(
        "Syslog requires explicit year" in warning for warning in event.normalization_warnings
    )
