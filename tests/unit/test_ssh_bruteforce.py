"""Tests for SSH brute-force detection."""

from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest

from linuxtrace.detection.ssh_bruteforce import detect_ssh_bruteforce
from linuxtrace.models.normalized_event import NormalizedEvent
from linuxtrace.models.raw_event import RawEvent


def make_event(
    index,
    *,
    minute=None,
    source_ip="192.0.2.15",
    hostname="server1",
    event_type="ssh_login_failed",
    outcome="failure",
):
    timestamp = datetime(2026, 11, 28, 10, 0, tzinfo=UTC)
    timestamp += timedelta(minutes=index if minute is None else minute)

    return NormalizedEvent(
        event_id=sha256(f"event-{index}".encode()).hexdigest(),
        raw_event=RawEvent(
            source="auth",
            source_file="/var/log/auth.log",
            source_line=index + 1,
            raw_log=f"SSH event {index}",
            evidence_hash=sha256(f"log-{index}".encode()).hexdigest(),
        ),
        timestamp=timestamp,
        event_category="authentication",
        event_type=event_type,
        severity="low",
        hostname=hostname,
        source_ip=source_ip,
        outcome=outcome,
        description="Failed SSH authentication",
    )


def test_detects_five_failures():
    events = [make_event(i, minute=i) for i in range(5)]

    findings = detect_ssh_bruteforce(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "LT-SSH-001"
    assert findings[0].severity == "high"
    assert len(findings[0].related_event_ids) == 5


def test_does_not_detect_below_threshold():
    assert detect_ssh_bruteforce([make_event(i) for i in range(4)]) == []


def test_does_not_combine_different_ips():
    events = [make_event(i, source_ip="192.0.2.15") for i in range(3)] + [
        make_event(i + 3, source_ip="192.0.2.16", minute=i) for i in range(3)
    ]

    assert detect_ssh_bruteforce(events) == []


def test_does_not_combine_different_hosts():
    events = [make_event(i, hostname="server1") for i in range(3)] + [
        make_event(i + 3, hostname="server2", minute=i) for i in range(3)
    ]

    assert detect_ssh_bruteforce(events) == []


def test_ignores_successful_logins():
    events = [make_event(i, event_type="ssh_login_success", outcome="success") for i in range(5)]

    assert detect_ssh_bruteforce(events) == []


def test_detects_invalid_user_attempts():
    events = [make_event(i, event_type="ssh_invalid_user") for i in range(5)]

    assert len(detect_ssh_bruteforce(events)) == 1


def test_does_not_combine_distant_attempts():
    events = [make_event(i, minute=i * 10) for i in range(5)]

    assert detect_ssh_bruteforce(events) == []


def test_is_deterministic():
    events = [make_event(i) for i in range(5)]

    first = detect_ssh_bruteforce(events)
    second = detect_ssh_bruteforce(reversed(events))

    assert first == second


def test_duplicate_events_do_not_inflate_counts():
    events = [make_event(i) for i in range(4)]
    events.append(events[0])

    assert detect_ssh_bruteforce(events) == []


def test_rejects_invalid_configuration():
    with pytest.raises(ValueError):
        detect_ssh_bruteforce([], threshold=1)

    with pytest.raises(ValueError):
        detect_ssh_bruteforce([], window_minutes=0)
