import gzip
import hashlib

from linuxtrace.collectors.authentication import (
    AuthenticationCollector,
)


def create_log_directory(root):
    directory = root / "var/log"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def test_collect_auth_log(tmp_path):
    directory = create_log_directory(tmp_path)

    path = directory / "auth.log"
    path.write_text("First event\nSecond event\n")

    collector = AuthenticationCollector(tmp_path)
    events = list(collector.collect())

    assert len(events) == 2
    assert events[0].source == "authentication"
    assert events[0].raw_log == "First event"
    assert events[1].raw_log == "Second event"


def test_collect_secure_log(tmp_path):
    directory = create_log_directory(tmp_path)

    (directory / "secure").write_text("Authentication event\n")

    collector = AuthenticationCollector(tmp_path)
    events = list(collector.collect())

    assert len(events) == 1
    assert events[0].source_file.endswith("/secure")


def test_collect_multiple_sources(tmp_path):
    directory = create_log_directory(tmp_path)

    (directory / "auth.log").write_text("Auth event\n")
    (directory / "secure").write_text("Secure event\n")

    collector = AuthenticationCollector(tmp_path)
    events = list(collector.collect())

    assert len(events) == 2
    assert collector.errors == []


def test_collect_rotated_log(tmp_path):
    directory = create_log_directory(tmp_path)

    (directory / "auth.log.1").write_text("Historical event\n")

    collector = AuthenticationCollector(tmp_path)
    events = list(collector.collect())

    assert len(events) == 1
    assert events[0].raw_log == "Historical event"


def test_collect_gzip_log(tmp_path):
    directory = create_log_directory(tmp_path)

    path = directory / "auth.log.2.gz"

    with gzip.open(path, "wt") as file:
        file.write("Compressed event\n")

    collector = AuthenticationCollector(tmp_path)
    events = list(collector.collect())

    assert len(events) == 1
    assert events[0].raw_log == "Compressed event"


def test_missing_sources(tmp_path):
    collector = AuthenticationCollector(tmp_path)

    assert list(collector.collect()) == []
    assert len(collector.errors) == 2


def test_empty_log(tmp_path):
    directory = create_log_directory(tmp_path)

    (directory / "auth.log").touch()

    collector = AuthenticationCollector(tmp_path)

    assert list(collector.collect()) == []


def test_skip_blank_lines(tmp_path):
    directory = create_log_directory(tmp_path)

    (directory / "auth.log").write_text("\nFirst event\n\nSecond event\n")

    collector = AuthenticationCollector(tmp_path)
    events = list(collector.collect())

    assert len(events) == 2
    assert events[0].source_line == 2
    assert events[1].source_line == 4


def test_evidence_hash(tmp_path):
    directory = create_log_directory(tmp_path)

    message = "Authentication event"

    (directory / "auth.log").write_text(message + "\n")

    collector = AuthenticationCollector(tmp_path)
    events = list(collector.collect())

    expected = hashlib.sha256(message.encode("utf-8")).hexdigest()

    assert events[0].evidence_hash == expected


def test_ignore_unrelated_logs(tmp_path):
    directory = create_log_directory(tmp_path)

    (directory / "syslog").write_text("System event\n")

    (directory / "dpkg.log").write_text("Package event\n")

    collector = AuthenticationCollector(tmp_path)

    assert list(collector.collect()) == []


def test_corrupted_gzip(tmp_path):
    directory = create_log_directory(tmp_path)

    (directory / "auth.log.1.gz").write_bytes(b"Invalid gzip content")

    collector = AuthenticationCollector(tmp_path)

    assert list(collector.collect()) == []
    assert any("Unable to read" in error for error in collector.errors)


def test_unsafe_symlink(tmp_path):
    root = tmp_path / "evidence"
    directory = create_log_directory(root)

    outside = tmp_path / "outside.log"
    outside.write_text("Outside evidence\n")

    (directory / "auth.log").symlink_to(outside)

    collector = AuthenticationCollector(root)

    assert list(collector.collect()) == []
    assert any("unsafe_path" in error for error in collector.errors)


def test_errors_reset_between_collections(tmp_path):
    collector = AuthenticationCollector(tmp_path)

    list(collector.collect())

    first_count = len(collector.errors)

    list(collector.collect())

    assert len(collector.errors) == first_count
