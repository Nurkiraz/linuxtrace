import hashlib

import pytest

from linuxtrace.storage.database import Database
from linuxtrace.storage.incremental import IncrementalTracker


@pytest.fixture
def tracker(tmp_path):
    db = Database(tmp_path / "test.db")
    db.initialize()

    result = IncrementalTracker(db)
    result.initialize()
    return result


def test_new_file_needs_collection(tracker, tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("First event\n")

    assert tracker.needs_collection(path) is True


def test_unchanged_file_is_skipped(tracker, tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("First event\n")

    tracker.mark_collected(path)

    assert tracker.needs_collection(path) is False


def test_modified_file_needs_collection(tracker, tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("First event\n")

    tracker.mark_collected(path)

    path.write_text("First event\nSecond event\n")

    assert tracker.needs_collection(path) is True


def test_modified_file_can_be_marked_again(tracker, tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("First event\n")

    tracker.mark_collected(path)

    path.write_text("Updated event\n")
    assert tracker.needs_collection(path) is True

    tracker.mark_collected(path)

    assert tracker.needs_collection(path) is False
    assert tracker.count_tracked_files() == 1


def test_multiple_tracked_files(tracker, tmp_path):
    first = tmp_path / "auth.log"
    second = tmp_path / "secure"

    first.write_text("Authentication event\n")
    second.write_text("Security event\n")

    tracker.mark_collected(first)
    tracker.mark_collected(second)

    assert tracker.count_tracked_files() == 2


def test_sha256_hash(tracker, tmp_path):
    path = tmp_path / "auth.log"
    content = b"Synthetic authentication event\n"
    path.write_bytes(content)

    expected = hashlib.sha256(content).hexdigest()

    assert tracker.calculate_hash(path) == expected


def test_missing_file(tracker, tmp_path):
    path = tmp_path / "missing.log"

    with pytest.raises(FileNotFoundError):
        tracker.needs_collection(path)


def test_directory_rejected(tracker, tmp_path):
    with pytest.raises(ValueError):
        tracker.calculate_hash(tmp_path)


def test_symlink_hash_rejected(tracker, tmp_path):
    target = tmp_path / "auth.log"
    target.write_text("Authentication event\n")

    link = tmp_path / "linked.log"
    link.symlink_to(target)

    with pytest.raises(ValueError):
        tracker.calculate_hash(link)


def test_tracking_persists_between_instances(tmp_path):
    db = Database(tmp_path / "test.db")
    db.initialize()

    path = tmp_path / "auth.log"
    path.write_text("Authentication event\n")

    first = IncrementalTracker(db)
    first.initialize()
    first.mark_collected(path)

    second = IncrementalTracker(db)
    second.initialize()

    assert second.needs_collection(path) is False
    assert second.count_tracked_files() == 1


def test_symlink_needs_collection_rejected(tracker, tmp_path):
    target = tmp_path / "auth.log"
    target.write_text("Synthetic event\n")

    link = tmp_path / "linked.log"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="Symbolic links"):
        tracker.needs_collection(link)


def test_symlink_mark_collected_rejected(tracker, tmp_path):
    target = tmp_path / "auth.log"
    target.write_text("Synthetic event\n")

    link = tmp_path / "linked.log"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="Symbolic links"):
        tracker.mark_collected(link)
