import gzip

import pytest

from linuxtrace.utils import log_reader
from linuxtrace.utils.log_reader import LogReadError, read_log


def test_plain_log(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("First event\nSecond event\n")

    results = list(read_log(path))

    assert results == [
        (1, "First event"),
        (2, "Second event"),
    ]


def test_gzip_log(tmp_path):
    path = tmp_path / "auth.log.1.gz"

    with gzip.open(path, "wt") as file:
        file.write("Compressed event\n")

    assert list(read_log(path)) == [
        (1, "Compressed event"),
    ]


def test_empty_log(tmp_path):
    path = tmp_path / "empty.log"
    path.touch()

    assert list(read_log(path)) == []


def test_missing_log(tmp_path):
    path = tmp_path / "missing.log"

    with pytest.raises(LogReadError):
        list(read_log(path))


def test_invalid_encoding(tmp_path):
    path = tmp_path / "invalid.log"
    path.write_bytes(b"Invalid byte: \xff\n")

    results = list(read_log(path))

    assert "\ufffd" in results[0][1]


def test_outside_evidence_root(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()

    outside = tmp_path / "outside.log"
    outside.write_text("Outside evidence")

    with pytest.raises(LogReadError):
        list(read_log(outside, root=root))


def test_unsafe_symlink(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()

    outside = tmp_path / "outside.log"
    outside.touch()

    link = root / "auth.log"
    link.symlink_to(outside)

    with pytest.raises(LogReadError):
        list(read_log(link, root=root))


def test_line_size_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(log_reader, "MAX_LINE_BYTES", 16)

    path = tmp_path / "large.log"
    path.write_text("A" * 100)

    with pytest.raises(LogReadError):
        list(read_log(path))


def test_total_size_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(log_reader, "MAX_TOTAL_BYTES", 20)

    path = tmp_path / "large.log"
    path.write_text("1234567890\n" * 5)

    with pytest.raises(LogReadError):
        list(read_log(path))


def test_corrupted_gzip(tmp_path):
    path = tmp_path / "corrupted.log.gz"
    path.write_bytes(b"Not a valid gzip file")

    with pytest.raises(LogReadError):
        list(read_log(path))


def test_directory_rejection(tmp_path):
    with pytest.raises(LogReadError):
        list(read_log(tmp_path))


def test_permission_denied(tmp_path, monkeypatch):
    path = tmp_path / "restricted.log"
    path.touch()

    def deny_access(*args, **kwargs):
        raise PermissionError("Access denied")

    monkeypatch.setattr(log_reader, "open", deny_access, raising=False)

    with pytest.raises(LogReadError):
        list(read_log(path))
