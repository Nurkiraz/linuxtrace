"""Integration regression tests for stateful brute-force execution."""

from datetime import timedelta

from test_ssh_disk_grouping import (
    build_events,
    expected_findings,
)

from linuxtrace.detection.config import DetectionConfig
from linuxtrace.detection.runner import run_ssh_detections


def test_stateful_runner_matches_original_rules():
    events = build_events()
    config = DetectionConfig()

    expected = expected_findings(events, config)
    actual = run_ssh_detections(iter(events), config=config)

    assert actual == expected
    assert "LT-SSH-001" in {item.rule_id for item in actual}


def test_duplicate_id_with_newer_record_matches_original():
    events = build_events()

    # The original detector keeps the final event for a repeated ID.
    newer = events[0].model_copy(update={"timestamp": events[0].timestamp + timedelta(seconds=10)})
    events.append(newer)

    config = DetectionConfig()

    expected = expected_findings(events, config)
    actual = run_ssh_detections(events, config=config)

    assert actual == expected
