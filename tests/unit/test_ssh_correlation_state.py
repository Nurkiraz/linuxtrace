"""Equivalence tests for stateful SSH success correlation."""

from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest

from linuxtrace.detection.ssh_correlation import (
    detect_ssh_success_after_failures,
)
from linuxtrace.detection.ssh_correlation_state import (
    SSHSuccessCorrelationState,
)
from linuxtrace.models.normalized_event import NormalizedEvent
from linuxtrace.models.raw_event import RawEvent


def make_event(index, second, *, success=False, username="admin"):
    raw = f"correlation-state-test-{index}"
    digest = sha256(raw.encode()).hexdigest()

    return NormalizedEvent(
        event_id=digest,
        raw_event=RawEvent(
            source="auth",
            source_file="/tmp/auth.log",
            source_line=index + 1,
            raw_log=raw,
            evidence_hash=digest,
        ),
        timestamp=(datetime(2026, 11, 28, tzinfo=UTC) + timedelta(seconds=second)),
        hostname="test-server",
        event_category="authentication",
        event_type=("ssh_login_success" if success else "ssh_login_failed"),
        severity="low",
        username=username,
        source_ip="192.0.2.15",
        outcome="success" if success else "failure",
        description=raw,
    )


def run_stateful(events, *, threshold=5, window_minutes=5):
    state = SSHSuccessCorrelationState(
        "test-server",
        "192.0.2.15",
        threshold=threshold,
        window_minutes=window_minutes,
    )

    findings = []

    for event in sorted(
        events,
        key=lambda item: (item.timestamp, item.event_id),
    ):
        finding = state.process(event)

        if finding is not None:
            findings.append(finding)

    return sorted(
        findings,
        key=lambda item: (item.start_time, item.finding_id),
    )


def reference(events, *, threshold=5, window_minutes=5):
    return detect_ssh_success_after_failures(
        events,
        threshold=threshold,
        window_minutes=window_minutes,
    )


def test_five_failures_then_success():
    events = [make_event(i, i * 30) for i in range(5)]
    events.append(make_event(5, 150, success=True))

    assert run_stateful(events) == reference(events)
    assert len(run_stateful(events)) == 1


def test_success_without_enough_failures():
    events = [make_event(i, i * 30) for i in range(4)]
    events.append(make_event(4, 150, success=True))

    assert run_stateful(events) == reference(events) == []


def test_failures_outside_window():
    events = [make_event(i, i * 120) for i in range(5)]
    events.append(make_event(5, 700, success=True))

    assert run_stateful(events) == reference(events) == []


def test_multiple_success_events_do_not_reuse_failures():
    events = [make_event(i, i * 10) for i in range(5)]
    events.extend(
        [
            make_event(5, 60, success=True),
            make_event(6, 70, success=True),
        ]
    )

    assert run_stateful(events) == reference(events)
    assert len(run_stateful(events)) == 1


def test_two_separate_attack_sequences():
    events = [make_event(i, i * 10) for i in range(5)]
    events.append(make_event(5, 50, success=True))

    events.extend(make_event(i + 6, 100 + i * 10) for i in range(5))
    events.append(make_event(11, 150, success=True))

    assert run_stateful(events) == reference(events)
    assert len(run_stateful(events)) == 2


def test_exact_window_boundary():
    events = [make_event(i, i * 60) for i in range(5)]
    events.append(make_event(5, 300, success=True))

    assert run_stateful(events) == reference(events)
    assert len(run_stateful(events)) == 1


def test_reversed_input_preserves_findings():
    events = [make_event(i, i * 15) for i in range(10)]
    events.append(make_event(10, 160, success=True))

    assert run_stateful(reversed(events)) == reference(events)


def test_different_username_on_success():
    events = [make_event(i, i * 15) for i in range(5)]
    events.append(
        make_event(
            5,
            90,
            success=True,
            username="root",
        )
    )

    assert run_stateful(events) == reference(events)
    assert run_stateful(events)[0].username == "root"


def test_dense_success_only_keeps_no_failures():
    state = SSHSuccessCorrelationState(
        "test-server",
        "192.0.2.15",
    )

    for index in range(1000):
        assert state.process(make_event(index, index, success=True)) is None

    assert len(state.failures) == 0


def test_sparse_failures_keep_bounded_window():
    state = SSHSuccessCorrelationState(
        "test-server",
        "192.0.2.15",
    )

    for index in range(1000):
        state.process(make_event(index, index * 600))
        assert len(state.failures) <= 1


def test_rejects_out_of_order_events():
    state = SSHSuccessCorrelationState(
        "test-server",
        "192.0.2.15",
    )

    state.process(make_event(1, 100))

    with pytest.raises(ValueError, match="strictly ordered"):
        state.process(make_event(2, 0))


def test_rejects_duplicate_event():
    state = SSHSuccessCorrelationState(
        "test-server",
        "192.0.2.15",
    )
    event = make_event(1, 0)

    state.process(event)

    with pytest.raises(ValueError, match="strictly ordered"):
        state.process(event)


def test_rejects_different_group():
    state = SSHSuccessCorrelationState(
        "another-server",
        "192.0.2.15",
    )

    with pytest.raises(ValueError, match="different SSH group"):
        state.process(make_event(1, 0))


def test_rejects_invalid_configuration():
    with pytest.raises(ValueError):
        SSHSuccessCorrelationState("test-server", "192.0.2.15", threshold=1)

    with pytest.raises(ValueError):
        SSHSuccessCorrelationState("test-server", "192.0.2.15", window_minutes=0)
