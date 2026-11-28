"""Tests for SSH authentication correlation."""

from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest

from linuxtrace.detection.ssh_correlation import (
    detect_ssh_success_after_failures,
)
from linuxtrace.models.normalized_event import NormalizedEvent
from linuxtrace.models.raw_event import RawEvent


def make_event(
    index,
    *,
    success=False,
    minute=None,
    ip="192.0.2.15",
    host="server1",
):
    raw = f"ssh-correlation-test-{index}"
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
        hostname=host,
        event_category="authentication",
        event_type=("ssh_login_success" if success else "ssh_login_failed"),
        outcome="success" if success else "failure",
        username="admin",
        source_ip=ip,
        severity="info" if success else "low",
        description=raw,
    )


def attack_events():
    failures = [make_event(i) for i in range(5)]
    success = make_event(5, success=True)
    return [*failures, success]


def test_detects_success_after_failures():
    findings = detect_ssh_success_after_failures(attack_events())

    assert len(findings) == 1
    assert findings[0].rule_id == "LT-SSH-002"
    assert findings[0].severity.value == "critical"
    assert findings[0].username == "admin"
    assert len(findings[0].related_event_ids) == 6


def test_no_success_no_finding():
    assert detect_ssh_success_after_failures([make_event(i) for i in range(5)]) == []


def test_below_threshold():
    events = [make_event(i) for i in range(4)]
    events.append(make_event(4, success=True))

    assert detect_ssh_success_after_failures(events) == []


def test_success_outside_window():
    events = [make_event(i) for i in range(5)]
    events.append(make_event(5, success=True, minute=20))

    assert detect_ssh_success_after_failures(events) == []


def test_different_source_ip():
    events = [make_event(i) for i in range(5)]
    events.append(make_event(5, success=True, ip="192.0.2.16"))

    assert detect_ssh_success_after_failures(events) == []


def test_different_hostname():
    events = [make_event(i) for i in range(5)]
    events.append(make_event(5, success=True, host="server2"))

    assert detect_ssh_success_after_failures(events) == []


def test_deterministic_output():
    events = attack_events()

    first = detect_ssh_success_after_failures(events)
    second = detect_ssh_success_after_failures(reversed(events))

    assert first == second


def test_duplicate_events_do_not_inflate_count():
    events = [make_event(i) for i in range(4)]
    events.append(events[0])
    events.append(make_event(4, success=True))

    assert detect_ssh_success_after_failures(events) == []


def test_rejects_invalid_configuration():
    with pytest.raises(ValueError):
        detect_ssh_success_after_failures([], threshold=1)

    with pytest.raises(ValueError):
        detect_ssh_success_after_failures([], window_minutes=0)
