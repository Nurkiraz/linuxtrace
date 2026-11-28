from datetime import UTC, datetime
from pathlib import Path

from linuxtrace.collectors.syslog import SyslogCollector
from linuxtrace.normalizers.event import normalize_event
from linuxtrace.parsers.system_log import parse_system_log

FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "syslog"


def test_syslog_collector_reads_plain_and_gzip():
    collector = SyslogCollector(FIXTURE_ROOT)
    events = list(collector.collect())

    assert len(events) == 10
    assert collector.errors == []
    assert len({event.source_file for event in events}) == 2


def test_syslog_evidence_hash():
    import hashlib

    event = next(SyslogCollector(FIXTURE_ROOT).collect())

    assert event.evidence_hash == hashlib.sha256(event.raw_log.encode("utf-8")).hexdigest()


def test_syslog_event_classification():
    events = [parse_system_log(raw) for raw in SyslogCollector(FIXTURE_ROOT).collect()]

    types = {event.event_type for event in events}

    assert "service_started" in types
    assert "service_failed" in types
    assert "cron_execution" in types
    assert "kernel_message" in types
    assert "system_message" in types


def test_syslog_normalization():
    raw = next(SyslogCollector(FIXTURE_ROOT).collect())
    parsed = parse_system_log(raw)

    normalized = normalize_event(
        parsed,
        year=2026,
        source_timezone="Europe/Istanbul",
    )

    assert normalized.timestamp == datetime(2026, 11, 18, 7, 0, 1, tzinfo=UTC)
    assert len(normalized.event_id) == 64


def test_missing_syslog_directory(tmp_path):
    collector = SyslogCollector(tmp_path)

    assert list(collector.collect()) == []
    assert collector.errors == []


def test_unrecognized_syslog_entry():
    from linuxtrace.models.raw_event import RawEvent

    raw = RawEvent(
        source="syslog",
        source_file="/evidence/var/log/syslog",
        source_line=1,
        raw_log="Unrecognized system log format",
        evidence_hash="0" * 64,
    )

    event = parse_system_log(raw)

    assert event.event_type == "unclassified"
    assert event.timestamp_original is None
