from pathlib import Path

import pytest
from typer.testing import CliRunner

from linuxtrace.cli import app
from linuxtrace.collectors.authentication import AuthenticationCollector
from linuxtrace.normalizers.event import normalize_event
from linuxtrace.parsers.authentication import parse_authentication
from linuxtrace.storage.database import Database
from linuxtrace.storage.event_repository import EventRepository

runner = CliRunner()

FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "evidence"


@pytest.fixture
def populated_database(tmp_path):
    """Create an isolated database with eight synthetic events."""

    db_path = tmp_path / "timeline.db"

    database = Database(db_path)
    database.initialize()

    repository = EventRepository(database)
    collector = AuthenticationCollector(FIXTURE_ROOT)

    events = [
        normalize_event(
            parse_authentication(raw),
            year=2026,
            source_timezone="Europe/Istanbul",
        )
        for raw in collector.collect()
    ]

    assert len(events) == 8
    assert repository.insert_events(events) == 8

    return db_path


def run_timeline(db_path, *arguments):
    """Invoke the actual Timeline CLI command."""

    return runner.invoke(
        app,
        [
            "timeline",
            "--db",
            str(db_path),
            *arguments,
        ],
        color=False,
    )


def test_timeline_displays_events(populated_database):
    result = run_timeline(populated_database)

    assert result.exit_code == 0
    assert "Incident Timeline" in result.output
    assert "Total events:" in result.output
    assert "8" in result.output


def test_timeline_user_filter(populated_database):
    result = run_timeline(
        populated_database,
        "--user",
        "root",
    )

    assert result.exit_code == 0
    assert "Total events: 5" in result.output


def test_timeline_ip_filter(populated_database):
    result = run_timeline(
        populated_database,
        "--ip",
        "198.51.100.25",
    )

    assert result.exit_code == 0
    assert "Total events: 4" in result.output


def test_timeline_event_type_filter(populated_database):
    result = run_timeline(
        populated_database,
        "--type",
        "ssh_login_failed",
    )

    assert result.exit_code == 0
    assert "Total events: 2" in result.output


def test_timeline_severity_filter(populated_database):
    result = run_timeline(
        populated_database,
        "--severity",
        "medium",
    )

    assert result.exit_code == 0
    assert "Total events: 1" in result.output


def test_timeline_category_filter(populated_database):
    result = run_timeline(
        populated_database,
        "--category",
        "privilege",
    )

    assert result.exit_code == 0
    assert "Total events: 1" in result.output


def test_timeline_date_range(populated_database):
    result = run_timeline(
        populated_database,
        "--from",
        "2026-11-18T00:00:00+03:00",
        "--to",
        "2026-11-19T00:00:00+03:00",
    )

    assert result.exit_code == 0
    assert "Total events: 8" in result.output


def test_timeline_last_24h(populated_database):
    result = run_timeline(
        populated_database,
        "--last",
        "24h",
    )

    assert result.exit_code == 0
    assert "Total events: 0" in result.output


def test_timeline_conflicting_dates(populated_database):
    result = run_timeline(
        populated_database,
        "--last",
        "24h",
        "--from",
        "2026-11-18T00:00:00+03:00",
    )

    assert result.exit_code == 2
    assert "cannot be combined" in result.output


def test_timeline_invalid_duration(populated_database):
    result = run_timeline(
        populated_database,
        "--last",
        "invalid",
    )

    assert result.exit_code == 2
    assert "Invalid filter" in result.output


def test_timeline_invalid_severity(populated_database):
    result = run_timeline(
        populated_database,
        "--severity",
        "unknown",
    )

    assert result.exit_code == 2
    assert "Invalid severity" in result.output


def test_timeline_missing_database(tmp_path):
    missing_db = tmp_path / "missing.db"

    result = run_timeline(missing_db)

    assert result.exit_code == 1
    assert "Database not found" in result.output


def test_timeline_limit(populated_database):
    result = run_timeline(
        populated_database,
        "--limit",
        "3",
    )

    assert result.exit_code == 0
    assert "Total events: 3" in result.output


def test_timeline_invalid_limit(populated_database):
    result = run_timeline(
        populated_database,
        "--limit",
        "0",
    )

    assert result.exit_code != 0


def test_timeline_unknown_user(populated_database):
    result = run_timeline(
        populated_database,
        "--user",
        "nonexistent_user",
    )

    assert result.exit_code == 0
    assert "Total events: 0" in result.output


def test_timeline_group_by_hour(populated_database):
    result = run_timeline(
        populated_database,
        "--group-by",
        "hour",
    )

    assert result.exit_code == 0
    assert "2026-11-18 07:00" in result.output
    assert "Total events: 8" in result.output


def test_timeline_group_by_day(populated_database):
    result = run_timeline(
        populated_database,
        "--group-by",
        "day",
    )

    assert result.exit_code == 0
    assert "2026-11-18" in result.output
    assert "2026-11-18" in result.output
    assert "Total events: 8" in result.output


def test_timeline_grouped_ssh_failures(populated_database):
    result = run_timeline(
        populated_database,
        "--type",
        "ssh_login_failed",
        "--group-by",
        "hour",
    )

    assert result.exit_code == 0
    assert "Total events: 2" in result.output


def test_timeline_invalid_group_by(populated_database):
    result = run_timeline(
        populated_database,
        "--group-by",
        "minute",
    )

    assert result.exit_code == 2
    assert "Invalid grouping" in result.output


def test_sql_grouping_counts_all_events_despite_limit(
    populated_database,
):
    import hashlib

    from linuxtrace.storage.database import Database
    from linuxtrace.storage.event_query import EventQuery
    from linuxtrace.storage.event_repository import EventRepository

    database = Database(populated_database)
    repository = EventRepository(database)

    original = EventQuery(database).search(limit=1)[0]

    extra_events = []
    for index in range(150):
        event_id = hashlib.sha256(f"synthetic-group-test-{index}".encode()).hexdigest()

        extra_events.append(original.model_copy(update={"event_id": event_id}))

    assert repository.insert_events(extra_events) == 150

    result = run_timeline(
        populated_database,
        "--group-by",
        "day",
        "--limit",
        "3",
    )

    assert result.exit_code == 0
    assert "2026-11-18" in result.output
    assert "Total events: 158" in result.output


def test_timeline_json_output(populated_database):
    import json

    result = run_timeline(
        populated_database,
        "--json",
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)

    assert payload["total_events"] == 8
    assert len(payload["events"]) == 8
    assert all("event_id" in event for event in payload["events"])


def test_timeline_json_user_filter(populated_database):
    import json

    result = run_timeline(
        populated_database,
        "--user",
        "root",
        "--json",
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)

    assert payload["total_events"] == 5
    assert all(event["username"] == "root" for event in payload["events"])


def test_timeline_grouped_json(populated_database):
    import json

    result = run_timeline(
        populated_database,
        "--group-by",
        "day",
        "--limit",
        "3",
        "--json",
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)

    assert payload["group_by"] == "day"
    assert payload["timezone"] == "UTC"
    assert payload["total_events"] == 8
    assert sum(group["count"] for group in payload["groups"]) == 8


def test_event_show_details(populated_database):
    from linuxtrace.storage.database import Database
    from linuxtrace.storage.event_query import EventQuery

    event = EventQuery(Database(populated_database)).search(limit=1)[0]

    result = runner.invoke(
        app,
        ["event", "show", event.event_id, "--db", str(populated_database)],
        color=False,
        terminal_width=120,
    )

    assert result.exit_code == 0
    assert event.event_id[:32] in result.output
    assert event.event_id[-7:] in result.output
    assert event.event_type in result.output
    assert "Original Log Entry" in result.output


def test_event_show_json(populated_database):
    import json

    from linuxtrace.storage.database import Database
    from linuxtrace.storage.event_query import EventQuery

    event = EventQuery(Database(populated_database)).search(limit=1)[0]

    result = runner.invoke(
        app,
        [
            "event",
            "show",
            event.event_id,
            "--db",
            str(populated_database),
            "--json",
        ],
        color=False,
    )

    assert result.exit_code == 0

    payload = json.loads(result.output)
    assert payload["event_id"] == event.event_id
    assert "raw_event" in payload


def test_event_show_invalid_id(populated_database):
    result = runner.invoke(
        app,
        ["event", "show", "invalid", "--db", str(populated_database)],
    )

    assert result.exit_code == 2
    assert "Invalid Event ID" in result.output


def test_event_show_not_found(populated_database):
    result = runner.invoke(
        app,
        ["event", "show", "0" * 64, "--db", str(populated_database)],
    )

    assert result.exit_code == 1
    assert "Event not found" in result.output


def test_timeline_no_color(populated_database):
    result = run_timeline(
        populated_database,
        "--no-color",
    )

    assert result.exit_code == 0
    assert "Total events: 8" in result.output
    assert "\x1b[" not in result.output


def test_grouped_timeline_no_color(populated_database):
    result = run_timeline(
        populated_database,
        "--group-by",
        "hour",
        "--no-color",
    )

    assert result.exit_code == 0
    assert "Total events: 8" in result.output
    assert "\x1b[" not in result.output


def test_event_show_no_color(populated_database):
    from linuxtrace.storage.database import Database
    from linuxtrace.storage.event_query import EventQuery

    event = EventQuery(Database(populated_database)).search(limit=1)[0]

    result = runner.invoke(
        app,
        [
            "event",
            "show",
            event.event_id,
            "--db",
            str(populated_database),
            "--no-color",
        ],
        color=False,
    )

    assert result.exit_code == 0
    assert "Original Log Entry" in result.output
    assert event.event_type in result.output
    assert "\x1b[" not in result.output
