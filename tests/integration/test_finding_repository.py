"""Integration tests for security finding persistence."""

from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest

from linuxtrace.detection.models import FindingSeverity, SecurityFinding
from linuxtrace.detection.repository import FindingRepository
from linuxtrace.storage.database import Database


def make_finding(index=1, **overrides):
    start = datetime(2026, 11, 28, 10, 0, tzinfo=UTC)

    values = {
        "finding_id": sha256(f"finding-{index}".encode()).hexdigest(),
        "rule_id": "LT-SSH-001",
        "title": "SSH Brute-Force Detected",
        "description": "Repeated failed SSH authentication attempts.",
        "severity": FindingSeverity.HIGH,
        "start_time": start + timedelta(minutes=index),
        "end_time": start + timedelta(minutes=index + 5),
        "source_ip": "192.0.2.15",
        "related_event_ids": ["a" * 64],
        "mitre_techniques": ["T1110"],
    }

    values.update(overrides)
    return SecurityFinding(**values)


@pytest.fixture
def repository(tmp_path):
    database = Database(tmp_path / "linuxtrace.db")
    database.initialize()

    repo = FindingRepository(database)
    repo.initialize()

    return repo


def test_save_and_retrieve_finding(repository):
    finding = make_finding()

    assert repository.save(finding) is True
    assert repository.get(finding.finding_id) == finding


def test_duplicate_finding_is_not_inserted(repository):
    finding = make_finding()

    assert repository.save(finding) is True
    assert repository.save(finding) is False
    assert len(repository.list_findings()) == 1


def test_rejects_conflicting_finding_id(repository):
    first = make_finding()
    conflicting = first.model_copy(update={"title": "Different detection"})

    repository.save(first)

    with pytest.raises(ValueError, match="Conflicting finding"):
        repository.save(conflicting)

    assert repository.get(first.finding_id) == first


def test_list_findings(repository):
    repository.save(make_finding(1))
    repository.save(make_finding(2))

    findings = repository.list_findings()

    assert len(findings) == 2
    assert findings[0].start_time >= findings[1].start_time


def test_severity_filter(repository):
    repository.save(make_finding(1))
    repository.save(make_finding(2, severity=FindingSeverity.MEDIUM))

    findings = repository.list_findings(severity=FindingSeverity.HIGH)

    assert len(findings) == 1
    assert findings[0].severity == FindingSeverity.HIGH


def test_missing_finding(repository):
    assert repository.get("0" * 64) is None


def test_invalid_limit(repository):
    with pytest.raises(ValueError):
        repository.list_findings(limit=0)


def test_finding_storage_preserves_events_table(repository):
    repository.save(make_finding())

    with repository.database.connect() as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }

    assert "events" in tables
    assert "findings" in tables
