from typer.testing import CliRunner

from linuxtrace.cli import app
from linuxtrace.storage.database import Database
from linuxtrace.storage.event_repository import EventRepository
from linuxtrace.storage.incremental import IncrementalTracker

runner = CliRunner()

LINE = "Nov 18 10:00:01 lab-server systemd[1]: Started Daily Cleanup Service.\n"


def prepare(tmp_path):
    root = tmp_path / "evidence"
    log_dir = root / "var/log"
    log_dir.mkdir(parents=True)
    (log_dir / "syslog").write_text(LINE)

    return root, log_dir, tmp_path / "test.db"


def run_collect(root, db_path):
    return runner.invoke(
        app,
        [
            "collect",
            "syslog",
            "--root",
            str(root),
            "--year",
            "2026",
            "--timezone",
            "Europe/Istanbul",
            "--db",
            str(db_path),
            "--incremental",
        ],
    )


def test_first_incremental_collection(tmp_path):
    root, _, db_path = prepare(tmp_path)

    result = run_collect(root, db_path)

    assert result.exit_code == 0, result.output
    assert "Processed files: 1" in result.output
    assert "Skipped files: 0" in result.output
    assert "Inserted events: 1" in result.output

    database = Database(db_path)
    assert EventRepository(database).count_events() == 1
    assert IncrementalTracker(database).count_tracked_files() == 1


def test_second_collection_skips_unchanged_file(tmp_path):
    root, _, db_path = prepare(tmp_path)

    first = run_collect(root, db_path)
    second = run_collect(root, db_path)

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    assert "Processed files: 0" in second.output
    assert "Skipped files: 1" in second.output
    assert "Read events: 0" in second.output
    assert "Inserted events: 0" in second.output

    assert EventRepository(Database(db_path)).count_events() == 1


def test_modified_file_is_collected_again(tmp_path):
    root, log_dir, db_path = prepare(tmp_path)

    first = run_collect(root, db_path)
    assert first.exit_code == 0, first.output

    with (log_dir / "syslog").open("a") as file:
        file.write("Nov 18 10:01:01 lab-server systemd[1]: Started Another Service.\n")

    second = run_collect(root, db_path)

    assert second.exit_code == 0, second.output
    assert "Processed files: 1" in second.output
    assert "Read events: 2" in second.output
    assert "Inserted events: 1" in second.output

    assert EventRepository(Database(db_path)).count_events() == 2
