from pathlib import Path

from linuxtrace.collectors.syslog_import import import_syslog
from linuxtrace.storage.database import Database
from linuxtrace.storage.event_repository import EventRepository

VALID_LINE = "Nov 18 10:00:01 lab-server systemd[1]: Started Daily Cleanup Service.\n"


def prepare(tmp_path):
    root = tmp_path / "evidence"
    log_dir = root / "var/log"
    log_dir.mkdir(parents=True)

    (log_dir / "syslog").write_text(VALID_LINE * 5)

    db_path = tmp_path / "events.db"
    return root, db_path


def run_import(root, db_path):
    return import_syslog(
        root=root,
        db_path=db_path,
        year=2026,
        source_timezone="Europe/Istanbul",
    )


def count_events(db_path):
    return EventRepository(Database(db_path)).count_events()


def test_streaming_import(tmp_path, monkeypatch):
    root, db_path = prepare(tmp_path)

    def prohibit_batch_insert(*args, **kwargs):
        raise AssertionError("Batch insert must not be used")

    monkeypatch.setattr(
        EventRepository,
        "insert_events",
        prohibit_batch_insert,
    )

    result = run_import(root, db_path)

    assert result.errors == []
    assert result.read == 5
    assert result.inserted == 5
    assert count_events(db_path) == 5


def test_database_write_failure_rolls_back(tmp_path, monkeypatch):
    root, db_path = prepare(tmp_path)

    original = EventRepository._event_values
    calls = 0

    def failing_values(event):
        nonlocal calls
        calls += 1

        if calls == 3:
            raise ValueError("Simulated database preparation failure")

        return original(event)

    monkeypatch.setattr(
        EventRepository,
        "_event_values",
        staticmethod(failing_values),
    )

    result = run_import(root, db_path)

    assert calls == 3
    assert result.errors
    assert result.inserted == 0
    assert count_events(db_path) == 0


def test_source_change_rolls_back(tmp_path, monkeypatch):
    from linuxtrace.collectors.syslog import SyslogCollector

    root, db_path = prepare(tmp_path)

    original_collect = SyslogCollector.collect
    calls = 0

    def changing_collect(self):
        nonlocal calls
        calls += 1

        if calls == 2:
            path = Path(self.root) / "var/log/syslog"
            path.write_text(VALID_LINE * 6)

        yield from original_collect(self)

    monkeypatch.setattr(
        SyslogCollector,
        "collect",
        changing_collect,
    )

    result = run_import(root, db_path)

    assert calls == 2
    assert result.errors
    assert result.inserted == 0
    assert count_events(db_path) == 0
