from linuxtrace.collectors.incremental_syslog import (
    collect_incremental_syslog,
)
from linuxtrace.storage.database import Database
from linuxtrace.storage.event_repository import EventRepository
from linuxtrace.storage.incremental import IncrementalTracker

LOG_LINE = "Nov 18 10:00:01 lab-server systemd[1]: Started Daily Cleanup Service.\n"


def prepare(tmp_path):
    root = tmp_path / "evidence"
    log_dir = root / "var/log"
    log_dir.mkdir(parents=True)

    (log_dir / "syslog").write_text(LOG_LINE * 5)

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


def test_first_collection(tmp_path):
    root, _, repository, tracker = prepare(tmp_path)

    result = collect(root, repository, tracker)

    assert result.errors == []
    assert result.processed_files == 1
    assert result.skipped_files == 0
    assert result.events_read == 5
    assert result.events_inserted == 5
    assert repository.count_events() == 5
    assert tracker.count_tracked_files() == 1


def test_unchanged_file_is_skipped(tmp_path):
    root, _, repository, tracker = prepare(tmp_path)

    first = collect(root, repository, tracker)
    second = collect(root, repository, tracker)

    assert first.events_inserted == 5
    assert second.errors == []
    assert second.processed_files == 0
    assert second.skipped_files == 1
    assert second.events_read == 0
    assert second.events_inserted == 0
    assert repository.count_events() == 5


def test_modified_file_is_reprocessed(tmp_path):
    root, log_dir, repository, tracker = prepare(tmp_path)

    collect(root, repository, tracker)

    with (log_dir / "syslog").open("a") as file:
        file.write("Nov 18 10:05:01 lab-server systemd[1]: Started Another Service.\n")

    result = collect(root, repository, tracker)

    assert result.errors == []
    assert result.processed_files == 1
    assert result.events_read == 6
    assert result.events_inserted == 1
    assert repository.count_events() == 6


def test_new_rotated_gzip(tmp_path):
    import gzip

    root, log_dir, repository, tracker = prepare(tmp_path)

    collect(root, repository, tracker)

    with gzip.open(log_dir / "syslog.1.gz", "wb") as file:
        file.write(LOG_LINE.encode("utf-8"))

    result = collect(root, repository, tracker)

    assert result.errors == []
    assert result.processed_files == 1
    assert result.skipped_files == 1
    assert result.events_inserted == 1
    assert repository.count_events() == 6
    assert tracker.count_tracked_files() == 2


def test_failure_rolls_back_file(tmp_path, monkeypatch):
    root, _, repository, tracker = prepare(tmp_path)

    original = EventRepository._event_values
    calls = 0

    def failing_values(event):
        nonlocal calls
        calls += 1

        if calls == 3:
            raise ValueError("Simulated failure")

        return original(event)

    monkeypatch.setattr(
        EventRepository,
        "_event_values",
        staticmethod(failing_values),
    )

    result = collect(root, repository, tracker)

    assert calls == 3
    assert result.errors
    assert result.processed_files == 0
    assert result.events_inserted == 0
    assert repository.count_events() == 0
    assert tracker.count_tracked_files() == 0


def test_symlink_rejected(tmp_path):
    root, log_dir, repository, tracker = prepare(tmp_path)

    outside = tmp_path / "outside.log"
    outside.write_text(LOG_LINE)

    (log_dir / "syslog.1.gz").symlink_to(outside)

    result = collect(root, repository, tracker)

    assert result.errors
    assert repository.count_events() == 5
    assert tracker.count_tracked_files() == 1
