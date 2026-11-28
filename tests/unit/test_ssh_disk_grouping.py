"""Verify disk-backed grouping preserves SSH detection results."""

from datetime import UTC, datetime, timedelta
from hashlib import sha256

from linuxtrace.detection.config import DetectionConfig
from linuxtrace.detection.registry import get_registered_rules
from linuxtrace.detection.runner import run_ssh_detections
from linuxtrace.models.normalized_event import NormalizedEvent
from linuxtrace.models.raw_event import RawEvent


def make_ssh_event(index, ip, username, minute, success=False):
    content = f"ssh-group-test-{index}"
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
        source_ip=ip,
        outcome="success" if success else "failure",
        description=content,
    )


def build_events():
    events = []

    for index in range(5):
        events.append(
            make_ssh_event(
                index,
                "192.0.2.15",
                f"user{index}",
                index,
            )
        )
        events.append(
            make_ssh_event(
                index + 100,
                "192.0.2.16",
                "admin",
                index,
            )
        )

    events.append(
        make_ssh_event(
            200,
            "192.0.2.15",
            "admin",
            5,
            success=True,
        )
    )

    return events


def expected_findings(events, config):
    findings = []

    for rule in get_registered_rules():
        if not rule.uses_window:
            continue

        settings = getattr(config, rule.config_key)
        if settings.enabled:
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


def test_disk_grouping_matches_original_detectors():
    events = build_events()
    config = DetectionConfig()

    expected = expected_findings(events, config)
    actual = run_ssh_detections(events, config=config)

    assert actual == expected
    assert {finding.rule_id for finding in actual} == {
        "LT-SSH-001",
        "LT-SSH-002",
        "LT-SSH-003",
    }


def test_reversed_input_preserves_findings():
    events = build_events()
    config = DetectionConfig()

    expected = expected_findings(events, config)
    actual = run_ssh_detections(reversed(events), config=config)

    assert actual == expected


def test_duplicate_events_preserve_finding_ids():
    events = build_events()
    config = DetectionConfig()

    expected = expected_findings(events, config)
    actual = run_ssh_detections(
        iter(events + [events[0], events[1]]),
        config=config,
    )

    assert actual == expected
