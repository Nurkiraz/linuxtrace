from linuxtrace.collectors.incremental_auth import collect_incremental_auth
from linuxtrace.storage.database import Database
from linuxtrace.storage.event_repository import EventRepository
from linuxtrace.storage.incremental import IncrementalTracker


def test_changed_file_does_not_commit_events(tmp_path, monkeypatch):
    """A changed evidence file must not leave committed events."""

    evidence_root = tmp_path / "evidence"
    log_dir = evidence_root / "var/log"
    log_dir.mkdir(parents=True)

    log_file = log_dir / "auth.log"
    log_file.write_text(
        "Nov 18 10:00:01 lab-server sshd[1201]: "
        "Accepted password for analyst from "
        "192.0.2.10 port 51234 ssh2\n"
    )

    db = Database(tmp_path / "test.db")
    db.initialize()

    repository = EventRepository(db)
    tracker = IncrementalTracker(db)
    tracker.initialize()

    original_hash = tracker.calculate_hash
    calls = 0

    def changing_hash(path):
        nonlocal calls
        calls += 1

        # Simulate a source modification during collection.
        if calls == 3:
            log_file.write_text(log_file.read_text() + "Modified event\n")

        return original_hash(path)

    monkeypatch.setattr(
        tracker,
        "calculate_hash",
        changing_hash,
    )

    result = collect_incremental_auth(
        evidence_root,
        repository,
        tracker,
        year=2026,
        source_timezone="Europe/Istanbul",
    )

    assert result.errors
    assert repository.count_events() == 0
    assert tracker.count_tracked_files() == 0


def test_parser_failure_rolls_back(tmp_path, monkeypatch):
    """Parser failure must roll back all events from that file."""
    from linuxtrace.collectors import incremental_auth
    from linuxtrace.storage.database import Database
    from linuxtrace.storage.event_repository import EventRepository
    from linuxtrace.storage.incremental import IncrementalTracker

    root = tmp_path / "evidence"
    log_dir = root / "var/log"
    log_dir.mkdir(parents=True)

    message = (
        "Nov 18 10:00:01 lab-server sshd[1201]: "
        "Accepted password for analyst from "
        "192.0.2.10 port 51234 ssh2\n"
    )

    (log_dir / "auth.log").write_text(message * 2)

    db = Database(tmp_path / "test.db")
    db.initialize()

    repo = EventRepository(db)
    tracker = IncrementalTracker(db)
    tracker.initialize()

    original_parser = incremental_auth.parse_authentication
    calls = 0

    def failing_parser(raw):
        nonlocal calls
        calls += 1

        if calls == 2:
            raise ValueError("Simulated parser failure")

        return original_parser(raw)

    monkeypatch.setattr(
        incremental_auth,
        "parse_authentication",
        failing_parser,
    )

    result = incremental_auth.collect_incremental_auth(
        root,
        repo,
        tracker,
        year=2026,
        source_timezone="Europe/Istanbul",
    )

    assert result.errors
    assert repo.count_events() == 0
    assert tracker.count_tracked_files() == 0


def test_successful_collection_is_skipped(tmp_path):
    """An unchanged file must not be collected twice."""
    from linuxtrace.collectors.incremental_auth import collect_incremental_auth
    from linuxtrace.storage.database import Database
    from linuxtrace.storage.event_repository import EventRepository
    from linuxtrace.storage.incremental import IncrementalTracker

    root = tmp_path / "evidence"
    log_dir = root / "var/log"
    log_dir.mkdir(parents=True)

    (log_dir / "auth.log").write_text(
        "Nov 18 10:00:01 lab-server sshd[1201]: "
        "Accepted password for analyst from "
        "192.0.2.10 port 51234 ssh2\n"
    )

    db = Database(tmp_path / "test.db")
    db.initialize()

    repo = EventRepository(db)
    tracker = IncrementalTracker(db)
    tracker.initialize()

    first = collect_incremental_auth(
        root,
        repo,
        tracker,
        year=2026,
        source_timezone="Europe/Istanbul",
    )

    second = collect_incremental_auth(
        root,
        repo,
        tracker,
        year=2026,
        source_timezone="Europe/Istanbul",
    )

    assert first.processed_files == 1
    assert first.events_inserted == 1
    assert first.errors == []

    assert second.processed_files == 0
    assert second.skipped_files == 1
    assert second.events_inserted == 0
    assert second.errors == []

    assert repo.count_events() == 1
    assert tracker.count_tracked_files() == 1
