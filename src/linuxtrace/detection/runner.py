"""Run registered security detection rules."""

from collections.abc import Iterable

from linuxtrace.detection.config import DetectionConfig
from linuxtrace.detection.models import SecurityFinding
from linuxtrace.detection.registry import get_registered_rules
from linuxtrace.models.normalized_event import NormalizedEvent


def run_ssh_detections(
    events: Iterable[NormalizedEvent],
    *,
    threshold: int = 5,
    window_minutes: int = 5,
    config: DetectionConfig | None = None,
) -> list[SecurityFinding]:
    """Execute enabled rules against normalized events."""

    if not 2 <= threshold <= 10000:
        raise ValueError("threshold must be between 2 and 10000")

    if not 1 <= window_minutes <= 1440:
        raise ValueError("window_minutes must be between 1 and 1440")

    if config is None:
        config = DetectionConfig(
            ssh_bruteforce={
                "threshold": threshold,
                "window_minutes": window_minutes,
            },
            ssh_success_after_failures={
                "threshold": threshold,
                "window_minutes": window_minutes,
            },
            ssh_password_spraying={
                "threshold": threshold,
                "window_minutes": 10,
            },
        )

    findings = []
    ssh_events = []
    audit_batch = []
    audit_batch_size = 500

    enabled_rules = [
        rule for rule in get_registered_rules() if getattr(config, rule.config_key).enabled
    ]

    ssh_rules = [rule for rule in enabled_rules if rule.uses_window]
    audit_rules = [rule for rule in enabled_rules if not rule.uses_window]

    def process_audit_batch():
        if not audit_batch:
            return

        for rule in audit_rules:
            findings.extend(rule.detector(audit_batch))

        audit_batch.clear()

    for event in events:
        if event.event_type == "audit_syscall":
            if audit_rules:
                audit_batch.append(event)

                if len(audit_batch) >= audit_batch_size:
                    process_audit_batch()

        elif event.event_type in {
            "ssh_login_failed",
            "ssh_invalid_user",
            "ssh_login_success",
        }:
            if ssh_rules:
                ssh_events.append(event)

    process_audit_batch()

    for rule in ssh_rules:
        settings = getattr(config, rule.config_key)

        findings.extend(
            rule.detector(
                ssh_events,
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
