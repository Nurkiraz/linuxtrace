import gzip

from linuxtrace.collectors.system_files import SystemFileCollector
from linuxtrace.parsers.system_log import parse_system_log

KERNEL_LINE = "Nov 18 10:02:10 lab-server kernel: [12345.678901] eth0: link down\n"

CRON_LINE = "Nov 18 10:01:15 lab-server CROND[1402]: (root) CMD (/usr/local/bin/backup.sh)\n"


def make_root(tmp_path):
    root = tmp_path / "evidence"
    log_dir = root / "var/log"
    log_dir.mkdir(parents=True)
    return root, log_dir


def test_kernel_log_collection(tmp_path):
    root, log_dir = make_root(tmp_path)
    (log_dir / "kern.log").write_text(KERNEL_LINE)

    collector = SystemFileCollector(root, "kernel")
    events = list(collector.collect())

    assert collector.errors == []
    assert len(events) == 1
    assert events[0].source == "kernel"

    parsed = parse_system_log(events[0])
    assert parsed.event_type == "kernel_message"


def test_cron_log_collection(tmp_path):
    root, log_dir = make_root(tmp_path)
    (log_dir / "cron").write_text(CRON_LINE)

    collector = SystemFileCollector(root, "cron")
    events = list(collector.collect())

    assert collector.errors == []
    assert len(events) == 1

    parsed = parse_system_log(events[0])
    assert parsed.event_type == "cron_execution"
    assert parsed.event_category == "scheduled_task"


def test_rotated_gzip_log(tmp_path):
    root, log_dir = make_root(tmp_path)

    with gzip.open(log_dir / "kern.log.2.gz", "wb") as file:
        file.write(KERNEL_LINE.encode("utf-8"))

    events = list(SystemFileCollector(root, "kernel").collect())

    assert len(events) == 1
    assert events[0].source_file.endswith(".gz")


def test_kernel_and_cron_are_separate(tmp_path):
    root, log_dir = make_root(tmp_path)

    (log_dir / "kern.log").write_text(KERNEL_LINE)
    (log_dir / "cron").write_text(CRON_LINE)

    kernel = list(SystemFileCollector(root, "kernel").collect())
    cron = list(SystemFileCollector(root, "cron").collect())

    assert len(kernel) == 1
    assert len(cron) == 1
    assert kernel[0].source != cron[0].source


def test_symlink_rejected(tmp_path):
    root, log_dir = make_root(tmp_path)

    outside = tmp_path / "outside.log"
    outside.write_text(KERNEL_LINE)

    (log_dir / "kern.log").symlink_to(outside)

    collector = SystemFileCollector(root, "kernel")
    events = list(collector.collect())

    assert events == []
    assert collector.errors


def test_invalid_source(tmp_path):
    import pytest

    with pytest.raises(ValueError, match="Unsupported source"):
        SystemFileCollector(tmp_path, "unknown")


def test_missing_log_directory(tmp_path):
    collector = SystemFileCollector(tmp_path, "kernel")

    assert list(collector.collect()) == []
    assert collector.errors == []
