"""Baseline tests before bounded-state SSH detection refactoring."""

from datetime import UTC, datetime, timedelta
from hashlib import sha256

from linuxtrace.detection.config import DetectionConfig
from linuxtrace.detection.registry import get_registered_rules
from linuxtrace.detection.runner import run_ssh_detections
from linuxtrace.models.normalized_event import NormalizedEvent
from linuxtrace.models.raw_event import RawEvent


def make_event(index, username, success=False):
    raw = f"dense-baseline-{index}"
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
        timestamp=(datetime(2026, 11, 28, tzinfo=UTC) + timedelta(seconds=index)),
        hostname="test-server",
        event_category="authentication",
        event_type=("ssh_login_success" if success else "ssh_login_failed"),
        severity="low",
        username=username,
        source_ip="192.0.2.15",
        outcome="success" if success else "failure",
        description=raw,
    )


def reference_findings(events):
    config = DetectionConfig()
    findings = []

    for rule in get_registered_rules():
        if not rule.uses_window:
            continue

        settings = getattr(config, rule.config_key)

        findings.extend(
            rule.detector(
                events,
                threshold=settings.threshold,
                window_minutes=settings.window_minutes,
            )
        )

    return sorted(
        findings,
        key=lambda finding: (
            finding.start_time,
            finding.rule_id,
            finding.finding_id,
        ),
    )


def test_dense_failed_logins_match_original_detectors():
    events = [make_event(i, f"user{i % 7}") for i in range(100)]

    expected = reference_findings(events)
    actual = run_ssh_detections(iter(events))

    assert actual == expected
    assert {item.rule_id for item in actual} >= {
        "LT-SSH-001",
        "LT-SSH-003",
    }


def test_dense_success_correlation_matches_original():
    events = [make_event(i, "admin") for i in range(30)]
    events.append(make_event(30, "admin", success=True))

    assert run_ssh_detections(iter(events)) == reference_findings(events)


def test_dense_success_only_has_no_findings():
    events = (make_event(i, "admin", success=True) for i in range(1000))

    assert run_ssh_detections(events) == []


def test_dense_input_order_does_not_change_findings():
    events = [make_event(i, f"user{i % 7}") for i in range(100)]

    assert run_ssh_detections(reversed(events)) == reference_findings(events)
