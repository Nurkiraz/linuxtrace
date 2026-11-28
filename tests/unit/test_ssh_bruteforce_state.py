"""Compare stateful SSH brute-force detection with the original."""

from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest

from linuxtrace.detection.ssh_bruteforce import detect_ssh_bruteforce
from linuxtrace.detection.ssh_bruteforce_state import SSHBruteForceState
from linuxtrace.models.normalized_event import NormalizedEvent
from linuxtrace.models.raw_event import RawEvent


def make_event(index, second, *, success=False):
    raw = f"stateful-test-{index}"
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
        username="admin",
        source_ip="192.0.2.15",
        outcome="success" if success else "failure",
        description=raw,
    )


def run_stateful(events, threshold=5, window_minutes=5):
    state = SSHBruteForceState(
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


@pytest.mark.parametrize(
    "seconds",
    [
        [0, 30, 60, 90],
        [0, 60, 120, 180, 240],
        [0, 60, 120, 180, 300],
        [0, 60, 120, 180, 301],
        list(range(100)),
        list(range(1000)),
        [0, 10, 20, 30, 40, 1000, 1010, 1020, 1030, 1040],
    ],
)
def test_stateful_matches_original(seconds):
    events = [make_event(index, second) for index, second in enumerate(seconds)]

    assert run_stateful(events) == detect_ssh_bruteforce(events)


def test_success_events_do_not_change_findings():
    events = [make_event(i, i * 30) for i in range(5)]
    events.insert(2, make_event(100, 45, success=True))

    assert run_stateful(events) == detect_ssh_bruteforce(events)


def test_unordered_input_can_be_sorted_before_processing():
    events = [make_event(i, i * 20) for i in range(20)]

    assert run_stateful(reversed(events)) == (detect_ssh_bruteforce(events))


def test_rejects_out_of_order_events():
    state = SSHBruteForceState("test-server", "192.0.2.15")

    state.process(make_event(1, 100))

    with pytest.raises(ValueError, match="strictly ordered"):
        state.process(make_event(2, 0))


def test_rejects_duplicate_event():
    state = SSHBruteForceState("test-server", "192.0.2.15")
    event = make_event(1, 0)

    state.process(event)

    with pytest.raises(ValueError, match="strictly ordered"):
        state.process(event)


def test_rejects_another_source_group():
    state = SSHBruteForceState("another-server", "192.0.2.15")

    with pytest.raises(ValueError, match="different SSH group"):
        state.process(make_event(1, 0))


def test_window_state_does_not_grow_for_sparse_events():
    state = SSHBruteForceState(
        "test-server",
        "192.0.2.15",
        window_minutes=5,
    )

    for index in range(1000):
        assert state.process(make_event(index, index * 600)) is None
        assert len(state.active) <= 1
