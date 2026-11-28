from contextlib import closing

from linuxtrace.collectors.incremental_syslog import (
    collect_incremental_syslog,
)
from linuxtrace.storage.database import Database
from linuxtrace.storage.event_repository import EventRepository
from linuxtrace.storage.incremental import IncrementalTracker

LOG_A = "Nov 18 10:00:01 lab-server systemd[1]: Started Daily Cleanup Service.\n"

LOG_B = "Nov 18 10:05:01 lab-server systemd[1]: Started Another Service.\n"


def prepare(tmp_path):
    root = tmp_path / "evidence"
    log_dir = root / "var/log"
    log_dir.mkdir(parents=True)

    database = Database(tmp_path / "events.db")
    database.initialize()

    repository = EventRepository(database)
    tracker = IncrementalTracker(database)
    tracker.initialize()

    return root, log_dir, database, repository, tracker


def collect(root, repository, tracker):
    return collect_incremental_syslog(
        root,
        repository,
        tracker,
        year=2026,
        source_timezone="Europe/Istanbul",
    )


def get_stored_events(database):
    with closing(database.connect()) as connection:
        return connection.execute(
            """
            SELECT event_id, source_file, source_line,
                   evidence_hash, raw_log
            FROM events
            ORDER BY source_file, event_id
            """
        ).fetchall()


def test_identical_logs_preserve_separate_sources(tmp_path):
    root, log_dir, database, repository, tracker = prepare(tmp_path)

    (log_dir / "syslog").write_text(LOG_A)
    (log_dir / "syslog.1").write_text(LOG_A)

    result = collect(root, repository, tracker)
    rows = get_stored_events(database)

    assert result.errors == []
    assert result.events_inserted == 2
    assert len(rows) == 2

    # Same raw evidence, different source locations.
    assert rows[0]["evidence_hash"] == rows[1]["evidence_hash"]
    assert rows[0]["event_id"] != rows[1]["event_id"]
    assert rows[0]["source_file"] != rows[1]["source_file"]
    assert rows[0]["source_line"] == rows[1]["source_line"] == 1


def test_modified_source_preserves_previous_event(tmp_path):
    root, log_dir, database, repository, tracker = prepare(tmp_path)

    source = log_dir / "syslog"
    source.write_text(LOG_A)

    first = collect(root, repository, tracker)
    assert first.events_inserted == 1

    original = get_stored_events(database)[0]

    source.write_text(LOG_B)

    second = collect(root, repository, tracker)
    rows = get_stored_events(database)

    assert second.errors == []
    assert second.events_inserted == 1
    assert len(rows) == 2

    # Previous evidence remains in SQLite.
    assert original["event_id"] in {row["event_id"] for row in rows}
    assert len({row["evidence_hash"] for row in rows}) == 2
    assert len({row["source_file"] for row in rows}) == 1
