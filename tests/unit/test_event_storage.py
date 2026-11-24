from datetime import UTC, datetime
from pathlib import Path

import pytest

from linuxtrace.collectors.authentication import AuthenticationCollector
from linuxtrace.normalizers.event import normalize_event
from linuxtrace.parsers.authentication import parse_authentication
from linuxtrace.storage.database import Database
from linuxtrace.storage.event_query import EventQuery
from linuxtrace.storage.event_repository import EventRepository

FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "evidence"


@pytest.fixture
def storage(tmp_path):
    """Create an isolated SQLite database for each test."""
    db = Database(tmp_path / "linuxtrace.db")
    db.initialize()

    repository = EventRepository(db)
    query = EventQuery(db)

    return db, repository, query


@pytest.fixture
def sample_events():
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
    return events


def test_database_initialization(storage):
    db, _, _ = storage

    assert db.path.exists()

    with db.connect() as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]

    assert version == 1


def test_insert_single_event(storage, sample_events):
    _, repository, _ = storage

    inserted = repository.insert_event(sample_events[0])

    assert inserted is True
    assert repository.count_events() == 1


def test_duplicate_event_id(storage, sample_events):
    _, repository, _ = storage

    first = repository.insert_event(sample_events[0])
    second = repository.insert_event(sample_events[0])

    assert first is True
    assert second is False
    assert repository.count_events() == 1


def test_bulk_insert(storage, sample_events):
    _, repository, _ = storage

    inserted = repository.insert_events(sample_events)

    assert inserted == 8
    assert repository.count_events() == 8


def test_bulk_duplicate_prevention(storage, sample_events):
    _, repository, _ = storage

    repository.insert_events(sample_events)
    second = repository.insert_events(sample_events)

    assert second == 0
    assert repository.count_events() == 8


def test_filter_by_username(storage, sample_events):
    _, repository, query = storage

    repository.insert_events(sample_events)

    events = query.search(username="root")

    assert len(events) == 5
    assert all(event.username == "root" for event in events)


def test_filter_by_source_ip(storage, sample_events):
    _, repository, query = storage

    repository.insert_events(sample_events)

    events = query.search(source_ip="198.51.100.25")

    assert len(events) == 4
    assert all(event.source_ip == "198.51.100.25" for event in events)


def test_filter_by_event_type(storage, sample_events):
    _, repository, query = storage

    repository.insert_events(sample_events)

    events = query.search(event_type="ssh_login_failed")

    assert len(events) == 2


def test_multiple_filters(storage, sample_events):
    _, repository, query = storage

    repository.insert_events(sample_events)

    events = query.search(
        username="root",
        event_type="ssh_login_failed",
    )

    assert len(events) == 2


def test_chronological_order(storage, sample_events):
    _, repository, query = storage

    repository.insert_events(sample_events)

    events = query.search()

    timestamps = [event.timestamp for event in events]

    assert timestamps == sorted(timestamps)


def test_date_range_filter(storage, sample_events):
    _, repository, query = storage

    repository.insert_events(sample_events)

    events = query.search(
        start=datetime(2026, 11, 18, 7, 1, tzinfo=UTC),
        end=datetime(2026, 11, 18, 7, 2, tzinfo=UTC),
    )

    assert len(events) == 3


def test_pagination(storage, sample_events):
    _, repository, query = storage

    repository.insert_events(sample_events)

    first_page = query.search(limit=3, offset=0)
    second_page = query.search(limit=3, offset=3)

    assert len(first_page) == 3
    assert len(second_page) == 3

    first_ids = {event.event_id for event in first_page}
    second_ids = {event.event_id for event in second_page}

    assert first_ids.isdisjoint(second_ids)


def test_invalid_limit(storage):
    _, _, query = storage

    with pytest.raises(ValueError):
        query.search(limit=0)


def test_invalid_offset(storage):
    _, _, query = storage

    with pytest.raises(ValueError):
        query.search(offset=-1)


def test_invalid_severity(storage):
    _, _, query = storage

    with pytest.raises(ValueError):
        query.search(severity="invalid")


def test_sql_injection_is_not_executed(storage, sample_events):
    _, repository, query = storage

    repository.insert_events(sample_events)

    events = query.search(username="' OR 1=1 --")

    assert events == []
    assert repository.count_events() == 8
