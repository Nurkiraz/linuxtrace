import gzip

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

    (log_dir / "syslog").write_text(LOG_A)

    database = Database(tmp_path / "events.db")
    database.initialize()

    repository = EventRepository(database)
    tracker = IncrementalTracker(database)
    tracker.initialize()

    return root, log_dir, repository, tracker


def collect(root, repository, tracker):
    return collect_incremental_syslog(
        root,
        repository,
        tracker,
        year=2026,
        source_timezone="Europe/Istanbul",
    )


def test_rotated_file_and_new_active_log(tmp_path):
    root, log_dir, repository, tracker = prepare(tmp_path)

    first = collect(root, repository, tracker)
    assert first.events_inserted == 1

    (log_dir / "syslog").rename(log_dir / "syslog.1")
    (log_dir / "syslog").write_text(LOG_B)

    second = collect(root, repository, tracker)

    assert second.errors == []
    assert second.processed_files == 2
    assert second.events_inserted == 2
    assert repository.count_events() == 3


def test_rotated_file_compressed(tmp_path):
    root, log_dir, repository, tracker = prepare(tmp_path)

    collect(root, repository, tracker)

    active = log_dir / "syslog"
    rotated = log_dir / "syslog.1.gz"

    with gzip.open(rotated, "wb") as file:
        file.write(active.read_bytes())

    active.unlink()
    active.write_text(LOG_B)

    result = collect(root, repository, tracker)

    assert result.errors == []
    assert result.processed_files == 2
    assert result.events_inserted == 2
    assert repository.count_events() == 3


def test_unchanged_rotated_log_skipped(tmp_path):
    root, log_dir, repository, tracker = prepare(tmp_path)

    with gzip.open(log_dir / "syslog.1.gz", "wb") as file:
        file.write(LOG_B.encode())

    first = collect(root, repository, tracker)
    second = collect(root, repository, tracker)

    assert first.processed_files == 2
    assert second.processed_files == 0
    assert second.skipped_files == 2
    assert second.events_inserted == 0


def test_changed_file_reprocessed_without_duplicate_ids(tmp_path):
    root, log_dir, repository, tracker = prepare(tmp_path)

    collect(root, repository, tracker)

    (log_dir / "syslog").write_text(LOG_A + LOG_B)

    result = collect(root, repository, tracker)

    assert result.errors == []
    assert result.processed_files == 1
    assert result.events_read == 2
    assert result.events_inserted == 1
    assert repository.count_events() == 2
