import shutil
from pathlib import Path

from linuxtrace.collectors import audit_import
from linuxtrace.collectors.audit import AuditCollector
from linuxtrace.collectors.audit_import import import_audit
from linuxtrace.storage.database import Database
from linuxtrace.storage.event_repository import EventRepository

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/audit"


def prepare(tmp_path):
    root = tmp_path / "evidence"
    shutil.copytree(FIXTURE, root)

    log_path = root / "var/log/audit/audit.log"
    db_path = tmp_path / "events.db"

    return root, log_path, db_path


def event_count(db_path):
    return EventRepository(Database(db_path)).count_events()


def evidence_count(db_path):
    with Database(db_path).connect() as connection:
        return connection.execute("SELECT COUNT(*) FROM audit_event_evidence").fetchone()[0]


def test_event_write_failure_rolls_back(tmp_path, monkeypatch):
    root, _, db_path = prepare(tmp_path)

    original = EventRepository._event_values
    calls = 0

    def failing_values(event):
        nonlocal calls
        calls += 1

        if calls == 2:
            raise ValueError("Simulated event write failure")

        return original(event)

    monkeypatch.setattr(
        EventRepository,
        "_event_values",
        staticmethod(failing_values),
    )

    result = import_audit(root, db_path)

    assert calls == 2
    assert result.errors
    assert result.events_inserted == 0
    assert result.evidence_inserted == 0
    assert event_count(db_path) == 0
    assert evidence_count(db_path) == 0


def test_evidence_write_failure_rolls_back(tmp_path, monkeypatch):
    root, _, db_path = prepare(tmp_path)

    monkeypatch.setattr(
        audit_import,
        "INSERT_AUDIT_EVIDENCE",
        "INSERT INTO missing_audit_table VALUES (?)",
    )

    result = import_audit(root, db_path)

    assert result.errors
    assert result.events_inserted == 0
    assert result.evidence_inserted == 0
    assert event_count(db_path) == 0
    assert evidence_count(db_path) == 0


def test_source_change_rolls_back(tmp_path, monkeypatch):
    root, log_path, db_path = prepare(tmp_path)

    original = AuditCollector.collect
    calls = 0

    def changing_collect(self):
        nonlocal calls
        calls += 1

        if calls == 2:
            with log_path.open("a") as file:
                file.write(
                    'type=USER_LOGIN msg=audit(1794996020.123:452): acct="second" res=success\n'
                )

        yield from original(self)

    monkeypatch.setattr(
        AuditCollector,
        "collect",
        changing_collect,
    )

    result = import_audit(root, db_path)

    assert calls == 2
    assert result.errors
    assert result.events_inserted == 0
    assert result.evidence_inserted == 0
    assert event_count(db_path) == 0
    assert evidence_count(db_path) == 0


def test_malformed_audit_record_rejected(tmp_path):
    root, log_path, db_path = prepare(tmp_path)

    with log_path.open("a") as file:
        file.write("this is not a valid audit record\n")

    result = import_audit(root, db_path)

    assert result.errors
    assert result.events_inserted == 0
    assert result.evidence_inserted == 0
    assert not db_path.exists()


def test_symlink_audit_file_rejected(tmp_path):
    root, log_path, db_path = prepare(tmp_path)

    outside = tmp_path / "outside.log"
    outside.write_bytes(log_path.read_bytes())

    log_path.unlink()
    log_path.symlink_to(outside)

    result = import_audit(root, db_path)

    assert result.errors
    assert result.events_inserted == 0
    assert result.evidence_inserted == 0
    assert not db_path.exists()
