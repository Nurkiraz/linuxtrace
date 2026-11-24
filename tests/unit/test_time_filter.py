from datetime import UTC, datetime, timedelta

import pytest

from linuxtrace.utils.time_filter import (
    get_time_range,
    parse_datetime,
    parse_duration,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("30m", timedelta(minutes=30)),
        ("24h", timedelta(hours=24)),
        ("7d", timedelta(days=7)),
        ("2w", timedelta(weeks=2)),
    ],
)
def test_valid_durations(value, expected):
    assert parse_duration(value) == expected


@pytest.mark.parametrize(
    "value",
    ["", "24", "abc", "0h", "-1h", "1x", "1.5h"],
)
def test_invalid_durations(value):
    with pytest.raises(ValueError):
        parse_duration(value)


def test_iso_timezone_conversion():
    result = parse_datetime("2026-11-18T10:00:00+03:00")

    assert result == datetime(2026, 11, 18, 7, 0, tzinfo=UTC)


def test_iso_utc_suffix():
    result = parse_datetime("2026-11-18T07:00:00Z")

    assert result == datetime(2026, 11, 18, 7, 0, tzinfo=UTC)


def test_missing_timezone():
    with pytest.raises(ValueError, match="Timezone required"):
        parse_datetime("2026-11-18T10:00:00")


def test_invalid_date():
    with pytest.raises(ValueError, match="Invalid date"):
        parse_datetime("invalid-date")


def test_last_24_hours():
    now = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)

    start, end = get_time_range(
        last="24h",
        now=now,
    )

    assert start == datetime(2026, 11, 23, 12, 0, tzinfo=UTC)
    assert end == now


def test_explicit_date_range():
    start, end = get_time_range(
        start="2026-11-18T10:00:00+03:00",
        end="2026-11-18T12:00:00+03:00",
    )

    assert start == datetime(2026, 11, 18, 7, 0, tzinfo=UTC)
    assert end == datetime(2026, 11, 18, 9, 0, tzinfo=UTC)


def test_last_with_from_rejected():
    with pytest.raises(ValueError):
        get_time_range(
            last="24h",
            start="2026-11-18T00:00:00Z",
        )


def test_last_with_to_rejected():
    with pytest.raises(ValueError):
        get_time_range(
            last="24h",
            end="2026-11-18T00:00:00Z",
        )


def test_reversed_date_range():
    with pytest.raises(ValueError):
        get_time_range(
            start="2026-11-19T00:00:00Z",
            end="2026-11-18T00:00:00Z",
        )


def test_naive_current_time_rejected():
    with pytest.raises(ValueError):
        get_time_range(
            last="24h",
            now=datetime(2026, 11, 24, 12, 0),
        )


def test_empty_time_range():
    start, end = get_time_range()

    assert start is None
    assert end is None
