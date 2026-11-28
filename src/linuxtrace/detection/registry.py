"""Central registry for supported detection rules."""

from collections.abc import Callable
from dataclasses import dataclass

from linuxtrace.detection.audit_commands import detect_suspicious_audit_commands
from linuxtrace.detection.models import SecurityFinding
from linuxtrace.detection.ssh_bruteforce import detect_ssh_bruteforce
from linuxtrace.detection.ssh_correlation import (
    detect_ssh_success_after_failures,
)
from linuxtrace.detection.ssh_password_spraying import (
    detect_ssh_password_spraying,
)

Detector = Callable[..., list[SecurityFinding]]


@dataclass(frozen=True)
class DetectionRule:
    """Metadata and execution handler for a detection rule."""

    rule_id: str
    name: str
    severity: str
    mitre_techniques: tuple[str, ...]
    config_key: str
    detector: Detector
    uses_window: bool = True


RULES = (
    DetectionRule(
        rule_id="LT-SSH-001",
        name="SSH Brute-Force",
        severity="high",
        mitre_techniques=("T1110",),
        config_key="ssh_bruteforce",
        detector=detect_ssh_bruteforce,
    ),
    DetectionRule(
        rule_id="LT-SSH-002",
        name="SSH Login Success After Failures",
        severity="critical",
        mitre_techniques=("T1110",),
        config_key="ssh_success_after_failures",
        detector=detect_ssh_success_after_failures,
    ),
    DetectionRule(
        rule_id="LT-SSH-003",
        name="SSH Password Spraying",
        severity="high",
        mitre_techniques=("T1110.003",),
        config_key="ssh_password_spraying",
        detector=detect_ssh_password_spraying,
    ),
    DetectionRule(
        rule_id="LT-AUDIT-001",
        name="Suspicious Remote Script Execution",
        severity="high",
        mitre_techniques=("T1059.004",),
        config_key="audit_suspicious_commands",
        detector=detect_suspicious_audit_commands,
        uses_window=False,
    ),
)


def get_registered_rules() -> tuple[DetectionRule, ...]:
    """Return all registered detection rules."""

    return RULES
