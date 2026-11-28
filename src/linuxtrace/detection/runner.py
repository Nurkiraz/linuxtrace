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

    materialized = list(events)
    findings = []

    for rule in get_registered_rules():
        settings = getattr(config, rule.config_key)

        if not settings.enabled:
            continue

        if rule.uses_window:
            findings.extend(
                rule.detector(
                    materialized,
                    threshold=settings.threshold,
                    window_minutes=settings.window_minutes,
                )
            )
        else:
            findings.extend(rule.detector(materialized))

    return sorted(
        findings,
        key=lambda finding: (
            finding.start_time,
            finding.rule_id,
            finding.finding_id,
        ),
    )
