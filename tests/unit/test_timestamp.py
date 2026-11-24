from datetime import UTC, datetime

import pytest

from linuxtrace.models.normalized_event import TimestampConfidence
from linuxtrace.normalizers.timestamp import normalize_timestamp


def test_journal_timestamp():
    result = normalize_timestamp(
        "1794996000000000",
        source="journal",
    )

    assert result["timestamp"] == datetime.fromtimestamp(1794996000, tz=UTC)
    assert result["timestamp_confidence"] == TimestampConfidence.HIGH
    assert result["timestamp_method"] == "journal_unix_microseconds"


def test_iso_timezone_conversion():
    result = normalize_timestamp(
        "2026-11-18T10:00:01+03:00",
        source="iso",
    )

    assert result["timestamp"] == datetime(2026, 11, 18, 7, 0, 1, tzinfo=UTC)


def test_iso_utc_z_suffix():
    result = normalize_timestamp(
        "2026-11-18T07:00:01Z",
        source="iso",
    )

    assert result["timestamp"] == datetime(2026, 11, 18, 7, 0, 1, tzinfo=UTC)


def test_iso_without_timezone():
    result = normalize_timestamp(
        "2026-11-18T10:00:01",
        source="iso",
    )

    assert result["timestamp"] is None
    assert result["timestamp_confidence"] == TimestampConfidence.UNKNOWN
    assert result["normalization_warnings"]


def test_syslog_explicit_context():
    result = normalize_timestamp(
        "Nov 18 10:00:01",
        source="syslog",
        year=2026,
        source_timezone="Europe/Istanbul",
    )

    assert result["timestamp"] == datetime(2026, 11, 18, 7, 0, 1, tzinfo=UTC)
    assert result["timestamp_confidence"] == TimestampConfidence.MEDIUM


def test_syslog_missing_year():
    result = normalize_timestamp(
        "Nov 18 10:00:01",
        source="syslog",
        source_timezone="Europe/Istanbul",
    )

    assert result["timestamp"] is None
    assert result["normalization_warnings"]


def test_syslog_missing_timezone():
    result = normalize_timestamp(
        "Nov 18 10:00:01",
        source="syslog",
        year=2026,
    )

    assert result["timestamp"] is None


def test_syslog_invalid_timezone():
    result = normalize_timestamp(
        "Nov 18 10:00:01",
        source="syslog",
        year=2026,
        source_timezone="Invalid/Timezone",
    )

    assert result["timestamp"] is None
    assert result["normalization_warnings"]


def test_dst_ambiguous_time():
    result = normalize_timestamp(
        "Nov 1 01:30:00",
        source="syslog",
        year=2026,
        source_timezone="America/New_York",
    )

    assert result["timestamp"] is None
    assert any("Ambiguous" in warning for warning in result["normalization_warnings"])


def test_dst_nonexistent_time():
    result = normalize_timestamp(
        "Mar 8 02:30:00",
        source="syslog",
        year=2026,
        source_timezone="America/New_York",
    )

    assert result["timestamp"] is None
    assert any("Nonexistent" in warning for warning in result["normalization_warnings"])


@pytest.mark.parametrize(
    "source,value",
    [
        ("journal", "invalid"),
        ("iso", "not-a-date"),
        ("syslog", "Invalid date"),
    ],
)
def test_invalid_timestamps(source, value):
    result = normalize_timestamp(
        value,
        source=source,
        year=2026,
        source_timezone="UTC",
    )

    assert result["timestamp"] is None
    assert result["normalization_warnings"]


def test_missing_timestamp():
    result = normalize_timestamp(
        None,
        source="journal",
    )

    assert result["timestamp"] is None
    assert "Timestamp is missing" in result["normalization_warnings"]


def test_unsupported_source():
    result = normalize_timestamp(
        "2026-11-18",
        source="unknown",
    )

    assert result["timestamp"] is None
    assert result["normalization_warnings"]
