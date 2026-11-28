"""Tests for security finding models."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from linuxtrace.detection.models import FindingSeverity, SecurityFinding


def make_finding(**overrides):
    start = datetime(2026, 11, 28, 10, 0, tzinfo=UTC)

    values = {
        "finding_id": "a" * 64,
        "rule_id": "LT-SSH-001",
        "title": "SSH Brute-Force",
        "description": "Multiple failed SSH authentication attempts.",
        "severity": FindingSeverity.HIGH,
        "start_time": start,
        "end_time": start + timedelta(minutes=5),
        "source_ip": "192.0.2.15",
        "related_event_ids": ["b" * 64],
        "mitre_techniques": ["T1110"],
    }
    values.update(overrides)
    return SecurityFinding(**values)


def test_valid_finding():
    finding = make_finding()

    assert finding.rule_id == "LT-SSH-001"
    assert finding.severity == FindingSeverity.HIGH
    assert len(finding.related_event_ids) == 1


def test_rejects_invalid_finding_id():
    with pytest.raises(ValidationError):
        make_finding(finding_id="invalid")


def test_rejects_naive_timestamp():
    with pytest.raises(ValidationError):
        make_finding(start_time=datetime(2026, 11, 28, 10, 0))


def test_rejects_reverse_time_window():
    with pytest.raises(ValidationError):
        make_finding(end_time=datetime(2026, 11, 28, 9, 0, tzinfo=UTC))


def test_requires_related_events():
    with pytest.raises(ValidationError):
        make_finding(related_event_ids=[])


def test_finding_json_round_trip():
    original = make_finding()
    restored = SecurityFinding.model_validate_json(original.model_dump_json())

    assert restored == original
