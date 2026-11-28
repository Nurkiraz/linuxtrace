from typer.testing import CliRunner

from linuxtrace.cli import app
from linuxtrace.collectors.system_file_import import import_system_file
from linuxtrace.storage.database import Database
from linuxtrace.storage.event_repository import EventRepository

runner = CliRunner()

KERNEL_LINE = "Nov 18 10:02:10 lab-server kernel: [12345.678901] eth0: link down\n"

CRON_LINE = "Nov 18 10:01:15 lab-server CROND[1402]: (root) CMD (/usr/local/bin/backup.sh)\n"


def prepare(tmp_path):
    root = tmp_path / "evidence"
    log_dir = root / "var/log"
    log_dir.mkdir(parents=True)

    (log_dir / "kern.log").write_text(KERNEL_LINE)
    (log_dir / "cron").write_text(CRON_LINE)

    return root, log_dir, tmp_path / "events.db"


def run_cli(source, root, db_path, *extra):
    return runner.invoke(
        app,
        [
            "collect",
            source,
            "--root",
            str(root),
            "--year",
            "2026",
            "--timezone",
            "Europe/Istanbul",
            "--db",
            str(db_path),
            *extra,
        ],
    )


def stored_count(db_path):
    return EventRepository(Database(db_path)).count_events()


def test_kernel_cli_import(tmp_path):
    root, _, db_path = prepare(tmp_path)

    result = run_cli("kernel", root, db_path)

    assert result.exit_code == 0, result.output
    assert "Read events: 1" in result.output
    assert "Inserted events: 1" in result.output
    assert stored_count(db_path) == 1


def test_cron_cli_import(tmp_path):
    root, _, db_path = prepare(tmp_path)

    result = run_cli("cron", root, db_path)

    assert result.exit_code == 0, result.output
    assert "Read events: 1" in result.output
    assert "Inserted events: 1" in result.output
    assert stored_count(db_path) == 1


def test_kernel_and_cron_share_database(tmp_path):
    root, _, db_path = prepare(tmp_path)

    first = run_cli("kernel", root, db_path)
    second = run_cli("cron", root, db_path)
    third = run_cli("kernel", root, db_path)

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    assert third.exit_code == 0, third.output

    assert "Inserted events: 0" in third.output
    assert "Existing events: 1" in third.output
    assert stored_count(db_path) == 2


def test_invalid_timezone(tmp_path):
    root, _, db_path = prepare(tmp_path)

    result = run_cli(
        "kernel",
        root,
        db_path,
        "--timezone",
        "Invalid/Timezone",
    )

    assert result.exit_code == 2
    assert "Invalid timezone" in result.output
    assert not db_path.exists()


def test_missing_evidence_root(tmp_path):
    root = tmp_path / "missing"
    db_path = tmp_path / "events.db"

    result = run_cli("cron", root, db_path)

    assert result.exit_code == 1
    assert "Evidence directory not found" in result.output
    assert not db_path.exists()


def test_sqlite_failure_rolls_back(tmp_path, monkeypatch):
    root, log_dir, db_path = prepare(tmp_path)

    (log_dir / "kern.log").write_text(
        KERNEL_LINE + "Nov 18 10:03:10 lab-server kernel: eth0: link up\n"
    )

    original = EventRepository._event_values
    calls = 0

    def failing_values(event):
        nonlocal calls
        calls += 1

        if calls == 2:
            raise ValueError("Simulated write failure")

        return original(event)

    monkeypatch.setattr(
        EventRepository,
        "_event_values",
        staticmethod(failing_values),
    )

    result = import_system_file(
        root=root,
        db_path=db_path,
        source="kernel",
        year=2026,
        source_timezone="Europe/Istanbul",
    )

    assert calls == 2
    assert result.errors
    assert result.inserted == 0
    assert stored_count(db_path) == 0


def test_source_change_rolls_back(tmp_path, monkeypatch):
    from linuxtrace.collectors.system_files import SystemFileCollector

    root, log_dir, db_path = prepare(tmp_path)

    original_collect = SystemFileCollector.collect
    calls = 0

    def changing_collect(self):
        nonlocal calls
        calls += 1

        if calls == 2:
            (log_dir / "kern.log").write_text(
                KERNEL_LINE + "Nov 18 10:03:10 lab-server kernel: eth0: link up\n"
            )

        yield from original_collect(self)

    monkeypatch.setattr(
        SystemFileCollector,
        "collect",
        changing_collect,
    )

    result = import_system_file(
        root=root,
        db_path=db_path,
        source="kernel",
        year=2026,
        source_timezone="Europe/Istanbul",
    )

    assert calls == 2
    assert result.errors
    assert result.inserted == 0
    assert stored_count(db_path) == 0
