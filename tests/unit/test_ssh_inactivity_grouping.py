"""Regression tests for inactivity-gap SSH grouping."""

from datetime import UTC, datetime, timedelta
from hashlib import sha256

from linuxtrace.detection.config import DetectionConfig
from linuxtrace.detection.registry import get_registered_rules
from linuxtrace.detection.runner import run_ssh_detections
from linuxtrace.models.normalized_event import NormalizedEvent
from linuxtrace.models.raw_event import RawEvent


def make_event(index, minute, username="admin", success=False):
    content = f"ssh-inactivity-test-{index}"
    digest = sha256(content.encode()).hexdigest()

    return NormalizedEvent(
        event_id=digest,
        raw_event=RawEvent(
            source="auth",
            source_file="/tmp/auth.log",
            source_line=index + 1,
            raw_log=content,
            evidence_hash=digest,
        ),
        timestamp=(datetime(2026, 11, 28, 10, 0, tzinfo=UTC) + timedelta(minutes=minute)),
        hostname="test-server",
        event_category="authentication",
        event_type=("ssh_login_success" if success else "ssh_login_failed"),
        severity="low",
        username=username,
        source_ip="192.0.2.15",
        outcome="success" if success else "failure",
        description=content,
    )


def original_detector_results(events, config):
    findings = []

    for rule in get_registered_rules():
        if not rule.uses_window:
            continue

        settings = getattr(config, rule.config_key)

        if not settings.enabled:
            continue

        findings.extend(
            rule.detector(
                events,
                threshold=settings.threshold,
                window_minutes=settings.window_minutes,
            )
        )

    return sorted(
        findings,
        key=lambda item: (
            item.start_time,
            item.rule_id,
            item.finding_id,
        ),
    )


def test_sparse_single_ip_matches_original():
    events = [make_event(index, minute=index * 11) for index in range(100)]

    config = DetectionConfig()

    assert run_ssh_detections(events, config=config) == (original_detector_results(events, config))


def test_attack_after_long_inactivity_gap():
    events = [make_event(0, 0)]

    events.extend(make_event(index + 1, 100 + index, f"user{index}") for index in range(5))

    config = DetectionConfig()

    expected = original_detector_results(events, config)
    actual = run_ssh_detections(events, config=config)

    assert actual == expected
    assert "LT-SSH-001" in {item.rule_id for item in actual}
    assert "LT-SSH-003" in {item.rule_id for item in actual}


def test_success_after_failures_across_event_sequence():
    events = [make_event(index, index, username="admin") for index in range(5)]
    events.append(make_event(5, 5, username="admin", success=True))

    config = DetectionConfig()

    expected = original_detector_results(events, config)
    actual = run_ssh_detections(reversed(events), config=config)

    assert actual == expected
    assert "LT-SSH-002" in {item.rule_id for item in actual}


def test_exact_window_boundary_is_preserved():
    events = [make_event(index, index * 2, username=f"user{index}") for index in range(5)]

    config = DetectionConfig()

    expected = original_detector_results(events, config)
    actual = run_ssh_detections(events, config=config)

    assert actual == expected
    assert "LT-SSH-003" in {item.rule_id for item in actual}


def test_custom_long_window_preserves_correlation():
    events = [make_event(index, index * 3) for index in range(5)]

    config = DetectionConfig.model_validate(
        {
            "version": 1,
            "ssh_bruteforce": {
                "threshold": 5,
                "window_minutes": 15,
            },
            "ssh_success_after_failures": {"enabled": False},
            "ssh_password_spraying": {"enabled": False},
        }
    )

    expected = original_detector_results(events, config)
    actual = run_ssh_detections(events, config=config)

    assert actual == expected
    assert len(actual) == 1
