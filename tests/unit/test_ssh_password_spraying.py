"""Tests for SSH password spraying detection."""

from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest

from linuxtrace.detection.ssh_password_spraying import (
    detect_ssh_password_spraying,
)
from linuxtrace.models.normalized_event import NormalizedEvent
from linuxtrace.models.raw_event import RawEvent


def make_event(
    index,
    *,
    username=None,
    ip="192.0.2.15",
    hostname="server1",
    minute=None,
    event_type="ssh_login_failed",
    outcome="failure",
):
    raw = f"spraying-test-{index}"
    timestamp = datetime(2026, 11, 28, 10, 0, tzinfo=UTC)
    timestamp += timedelta(minutes=index if minute is None else minute)

    return NormalizedEvent(
        event_id=sha256(raw.encode()).hexdigest(),
        raw_event=RawEvent(
            source="auth",
            source_file="/var/log/auth.log",
            source_line=index + 1,
            raw_log=raw,
            evidence_hash=sha256(raw.encode()).hexdigest(),
        ),
        timestamp=timestamp,
        hostname=hostname,
        event_category="authentication",
        event_type=event_type,
        outcome=outcome,
        username=username or f"user{index}",
        source_ip=ip,
        severity="low",
        description=raw,
    )


def test_detects_five_distinct_users():
    events = [make_event(i) for i in range(5)]

    findings = detect_ssh_password_spraying(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "LT-SSH-003"
    assert findings[0].severity.value == "high"
    assert findings[0].mitre_techniques == ["T1110.003"]
    assert len(findings[0].related_event_ids) == 5


def test_repeated_single_username_does_not_trigger():
    events = [make_event(i, username="admin") for i in range(8)]

    assert detect_ssh_password_spraying(events) == []


def test_below_distinct_user_threshold():
    events = [make_event(i) for i in range(4)]

    assert detect_ssh_password_spraying(events) == []


def test_separate_ips_not_combined():
    events = [make_event(i, ip="192.0.2.15") for i in range(3)] + [
        make_event(i + 3, ip="192.0.2.16", minute=i) for i in range(3)
    ]

    assert detect_ssh_password_spraying(events) == []


def test_separate_hosts_not_combined():
    events = [make_event(i, hostname="server1") for i in range(3)] + [
        make_event(i + 3, hostname="server2", minute=i) for i in range(3)
    ]

    assert detect_ssh_password_spraying(events) == []


def test_events_outside_window_not_combined():
    events = [make_event(i, minute=i * 20) for i in range(5)]

    assert detect_ssh_password_spraying(events) == []


def test_ignores_successful_logins():
    events = [
        make_event(
            i,
            event_type="ssh_login_success",
            outcome="success",
        )
        for i in range(5)
    ]

    assert detect_ssh_password_spraying(events) == []


def test_supports_invalid_user_events():
    events = [make_event(i, event_type="ssh_invalid_user") for i in range(5)]

    assert len(detect_ssh_password_spraying(events)) == 1


def test_deterministic_output():
    events = [make_event(i) for i in range(5)]

    first = detect_ssh_password_spraying(events)
    second = detect_ssh_password_spraying(reversed(events))

    assert first == second


def test_duplicate_events_do_not_inflate_count():
    events = [make_event(i) for i in range(4)]
    events.extend([events[0], events[1]])

    assert detect_ssh_password_spraying(events) == []


def test_rejects_invalid_configuration():
    with pytest.raises(ValueError):
        detect_ssh_password_spraying([], threshold=1)

    with pytest.raises(ValueError):
        detect_ssh_password_spraying([], window_minutes=0)
