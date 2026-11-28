from pathlib import Path

from typer.testing import CliRunner

from linuxtrace.cli import app
from linuxtrace.storage.database import Database
from linuxtrace.storage.event_query import EventQuery

runner = CliRunner()

FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "syslog"


def run_collect(root, db_path, *extra):
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
            *extra,
        ],
    )


def test_first_syslog_import(tmp_path):
    db_path = tmp_path / "test.db"

    result = run_collect(FIXTURE_ROOT, db_path)

    assert result.exit_code == 0, result.output
    assert "Read events: 10" in result.output
    assert "Inserted events: 10" in result.output

    events = EventQuery(Database(db_path)).search(limit=20)

    assert len(events) == 10


def test_duplicate_syslog_import(tmp_path):
    db_path = tmp_path / "test.db"

    first = run_collect(FIXTURE_ROOT, db_path)
    second = run_collect(FIXTURE_ROOT, db_path)

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output

    assert "Inserted events: 10" in first.output
    assert "Inserted events: 0" in second.output
    assert "Existing events: 10" in second.output

    events = EventQuery(Database(db_path)).search(limit=20)
    assert len(events) == 10


def test_invalid_timezone(tmp_path):
    db_path = tmp_path / "test.db"

    result = run_collect(
        FIXTURE_ROOT,
        db_path,
        "--timezone",
        "Invalid/Timezone",
    )

    assert result.exit_code == 2
    assert "Invalid timezone" in result.output
    assert not db_path.exists()


def test_missing_evidence_root(tmp_path):
    root = tmp_path / "missing"
    db_path = tmp_path / "test.db"

    result = run_collect(root, db_path)

    assert result.exit_code == 1
    assert "Evidence directory not found" in result.output
    assert not db_path.exists()


def test_empty_syslog_directory(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()

    db_path = tmp_path / "test.db"

    result = run_collect(root, db_path)

    assert result.exit_code == 0, result.output
    assert "Read events: 0" in result.output
    assert "Inserted events: 0" in result.output


def test_invalid_year(tmp_path):
    db_path = tmp_path / "test.db"

    result = run_collect(
        FIXTURE_ROOT,
        db_path,
        "--year",
        "1960",
    )

    assert result.exit_code != 0
    assert not db_path.exists()
