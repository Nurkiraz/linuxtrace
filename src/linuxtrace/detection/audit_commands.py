"""Detect selected suspicious shell command patterns in auditd events."""

import shlex
from collections.abc import Iterable
from hashlib import sha256
from pathlib import PurePosixPath

from linuxtrace.detection.models import FindingSeverity, SecurityFinding
from linuxtrace.models.normalized_event import NormalizedEvent

RULE_ID = "LT-AUDIT-001"


def has_remote_shell_pipeline(script: str) -> bool:
    """Detect a direct download-to-shell pipeline in a shell script."""

    try:
        lexer = shlex.shlex(
            script,
            posix=True,
            punctuation_chars="|;&",
        )
        lexer.whitespace_split = True
        lexer.commenters = "#"
        tokens = list(lexer)
    except ValueError:
        return False

    separators = {"|", "||", ";", "&&", "&"}

    for index, token in enumerate(tokens):
        if token != "|":
            continue

        left = index - 1
        while left >= 0 and tokens[left] not in separators:
            left -= 1

        right = index + 1
        while right < len(tokens) and tokens[right] not in separators:
            right += 1

        producer = tokens[left + 1 : index]
        consumer = tokens[index + 1 : right]

        if not producer or not consumer:
            continue

        producer_name = PurePosixPath(producer[0]).name
        consumer_name = PurePosixPath(consumer[0]).name

        if producer_name not in {"curl", "wget"}:
            continue

        if consumer_name not in {"sh", "bash"}:
            continue

        if any(arg.startswith(("http://", "https://")) for arg in producer[1:]):
            return True

    return False


def detect_suspicious_audit_commands(
    events: Iterable[NormalizedEvent],
) -> list[SecurityFinding]:
    """Identify remote download-to-shell patterns in audit syscall events."""

    findings = {}

    for event in events:
        if (
            event.event_type != "audit_syscall"
            or event.raw_event.source != "auditd"
            or event.timestamp is None
            or not event.command
            or event.outcome == "failure"
        ):
            continue

        try:
            argv = shlex.split(event.command)
        except ValueError:
            continue

        if len(argv) < 3:
            continue

        executable = PurePosixPath(argv[0]).name
        if executable not in {"sh", "bash"}:
            continue

        if argv[1] != "-c":
            continue

        script = argv[2]
        if not has_remote_shell_pipeline(script):
            continue

        identity = f"{RULE_ID}|{event.event_id}"
        finding_id = sha256(identity.encode()).hexdigest()

        findings[finding_id] = SecurityFinding(
            finding_id=finding_id,
            rule_id=RULE_ID,
            title="Suspicious Remote Script Execution",
            description=(
                "Auditd recorded a shell command containing a "
                "remote download-to-shell pipeline. Review the "
                "original command and related audit evidence."
            ),
            severity=FindingSeverity.HIGH,
            start_time=event.timestamp,
            end_time=event.timestamp,
            username=event.username,
            related_event_ids=[event.event_id],
            mitre_techniques=["T1059.004"],
        )

    return sorted(
        findings.values(),
        key=lambda finding: (finding.start_time, finding.finding_id),
    )
