"""Regression tests for stateful SSH correlation integration."""

from datetime import timedelta

from test_ssh_disk_grouping import (
    build_events,
    expected_findings,
)

from linuxtrace.detection.config import DetectionConfig
from linuxtrace.detection.runner import run_ssh_detections


def test_runner_matches_all_original_ssh_rules():
    events = build_events()
    config = DetectionConfig()

    expected = expected_findings(events, config)
    actual = run_ssh_detections(iter(events), config=config)

    assert actual == expected
    assert "LT-SSH-002" in {item.rule_id for item in actual}


def test_duplicate_events_preserve_correlation():
    events = build_events()
    events.extend([events[0], events[1]])

    config = DetectionConfig()

    expected = expected_findings(events, config)
    actual = run_ssh_detections(events, config=config)

    assert actual == expected


def test_correlation_after_long_inactivity():
    events = build_events()

    shifted = [
        event.model_copy(
            update={
                "event_id": (f"{index + 1000:064x}"),
                "timestamp": event.timestamp + timedelta(hours=2),
            }
        )
        for index, event in enumerate(events)
    ]

    combined = events + shifted
    config = DetectionConfig()

    expected = expected_findings(combined, config)
    actual = run_ssh_detections(reversed(combined), config=config)

    assert actual == expected
    assert sum(finding.rule_id == "LT-SSH-002" for finding in actual) == 2
