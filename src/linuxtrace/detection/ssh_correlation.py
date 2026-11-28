"""Correlate failed SSH logins followed by a successful login."""

from collections import defaultdict
from collections.abc import Iterable
from datetime import timedelta
from hashlib import sha256
from ipaddress import ip_address

from linuxtrace.detection.models import FindingSeverity, SecurityFinding
from linuxtrace.detection.ssh_bruteforce import FAILED_TYPES
from linuxtrace.models.normalized_event import NormalizedEvent

RULE_ID = "LT-SSH-002"


def detect_ssh_success_after_failures(
    events: Iterable[NormalizedEvent],
    *,
    threshold: int = 5,
    window_minutes: int = 5,
) -> list[SecurityFinding]:
    """Detect SSH successes preceded by repeated failures from one IP."""

    if threshold < 2:
        raise ValueError("threshold must be at least 2")
    if window_minutes < 1:
        raise ValueError("window_minutes must be positive")

    groups = defaultdict(dict)

    for event in events:
        if event.timestamp is None or not event.source_ip:
            continue

        is_failure = event.event_type in FAILED_TYPES and event.outcome == "failure"
        is_success = event.event_type == "ssh_login_success" and event.outcome == "success"

        if not (is_failure or is_success):
            continue

        try:
            source_ip = str(ip_address(event.source_ip))
        except ValueError:
            continue

        key = (event.hostname or "", source_ip)
        groups[key][event.event_id] = event

    findings = []
    window = timedelta(minutes=window_minutes)

    for (hostname, source_ip), unique in sorted(groups.items()):
        ordered = sorted(
            unique.values(),
            key=lambda e: (e.timestamp, e.event_id),
        )

        failures = []
        used_failures = set()

        for event in ordered:
            if event.event_type in FAILED_TYPES:
                if event.outcome == "failure":
                    failures.append(event)
                continue

            # The current event is an SSH login success.
            recent = [
                failed
                for failed in failures
                if failed.event_id not in used_failures
                and timedelta(0) <= event.timestamp - failed.timestamp <= window
            ]

            if len(recent) < threshold:
                continue

            matched = [*recent, event]
            ids = sorted(item.event_id for item in matched)

            identity = "|".join([RULE_ID, hostname, source_ip, *ids])
            finding_id = sha256(identity.encode()).hexdigest()

            findings.append(
                SecurityFinding(
                    finding_id=finding_id,
                    rule_id=RULE_ID,
                    title="SSH Login Success After Repeated Failures",
                    description=(
                        f"{len(recent)} failed SSH attempts from "
                        f"{source_ip} were followed by a successful "
                        f"login for {event.username or 'unknown user'} "
                        f"on {hostname or 'unknown host'}."
                    ),
                    severity=FindingSeverity.CRITICAL,
                    start_time=recent[0].timestamp,
                    end_time=event.timestamp,
                    source_ip=source_ip,
                    username=event.username,
                    related_event_ids=ids,
                    mitre_techniques=["T1110"],
                )
            )

            used_failures.update(failed.event_id for failed in recent)

    return sorted(
        findings,
        key=lambda finding: (
            finding.start_time,
            finding.finding_id,
        ),
    )
