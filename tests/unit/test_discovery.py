from linuxtrace.utils.discovery import (
    discover_logs,
    discover_rotated_logs,
)


def test_existing_log(tmp_path):
    log_dir = tmp_path / "var/log"
    log_dir.mkdir(parents=True)

    auth_log = log_dir / "auth.log"
    auth_log.write_text("Synthetic authentication log")

    results = discover_logs(tmp_path)

    event = next(item for item in results if item["path"] == str(auth_log))

    assert event["status"] == "available"
    assert event["category"] == "authentication"


def test_missing_log(tmp_path):
    results = discover_logs(tmp_path)

    assert all(item["status"] == "missing" for item in results)


def test_rotated_logs(tmp_path):
    log_dir = tmp_path / "var/log"
    log_dir.mkdir(parents=True)

    (log_dir / "auth.log.1").touch()
    (log_dir / "auth.log.2.gz").touch()
    (log_dir / "auth.log.tmp").touch()

    results = discover_rotated_logs(tmp_path)

    assert len(results) == 2
    assert all(item["rotated"] for item in results)


def test_compressed_log_discovery(tmp_path):
    log_dir = tmp_path / "var/log"
    log_dir.mkdir(parents=True)

    (log_dir / "auth.log.2.gz").touch()

    results = discover_rotated_logs(tmp_path)

    assert len(results) == 1
    assert results[0]["compressed"] is True


def test_unsafe_symlink(tmp_path):
    root = tmp_path / "evidence"
    log_dir = root / "var/log"
    log_dir.mkdir(parents=True)

    outside = tmp_path / "outside.log"
    outside.touch()

    auth_log = log_dir / "auth.log"
    auth_log.symlink_to(outside)

    results = discover_logs(root)

    event = next(item for item in results if item["path"] == str(auth_log))

    assert event["status"] == "unsafe_path"
