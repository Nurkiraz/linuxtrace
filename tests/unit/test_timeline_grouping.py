from datetime import UTC, datetime, timedelta, timezone

import pytest

from linuxtrace.timeline_grouping import group_events


class SampleEvent:
    def __init__(self, timestamp):
        self.timestamp = timestamp


def test_group_by_hour():
    events = [
        SampleEvent(datetime(2026, 11, 18, 7, 10, tzinfo=UTC)),
        SampleEvent(datetime(2026, 11, 18, 7, 40, tzinfo=UTC)),
        SampleEvent(datetime(2026, 11, 18, 8, 5, tzinfo=UTC)),
    ]

    result = group_events(events, "hour")

    assert result == [
        ("2026-11-18 07:00", 2),
        ("2026-11-18 08:00", 1),
    ]


def test_group_by_day():
    events = [
        SampleEvent(datetime(2026, 11, 18, 7, tzinfo=UTC)),
        SampleEvent(datetime(2026, 11, 18, 20, tzinfo=UTC)),
        SampleEvent(datetime(2026, 11, 19, 8, tzinfo=UTC)),
    ]

    assert group_events(events, "day") == [
        ("2026-11-18", 2),
        ("2026-11-19", 1),
    ]


def test_timezone_conversion():
    source_tz = timezone(timedelta(hours=3))
    events = [
        SampleEvent(
            datetime(
                2026,
                11,
                18,
                1,
                30,
                tzinfo=source_tz,
            )
        )
    ]

    assert group_events(events, "day") == [
        ("2026-11-17", 1),
    ]


def test_empty_events():
    assert group_events([], "hour") == []


def test_unknown_timestamp_skipped():
    assert group_events([SampleEvent(None)], "hour") == []


def test_naive_timestamp_rejected():
    events = [SampleEvent(datetime(2026, 11, 18, 7))]

    with pytest.raises(ValueError, match="timezone-aware"):
        group_events(events, "hour")


def test_invalid_grouping():
    with pytest.raises(ValueError, match="Grouping"):
        group_events([], "week")
