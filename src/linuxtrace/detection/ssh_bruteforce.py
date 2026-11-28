"""Detect repeated failed SSH authentication attempts."""

from collections import defaultdict
from collections.abc import Iterable
from datetime import timedelta
from hashlib import sha256
from ipaddress import ip_address

from linuxtrace.detection.models import FindingSeverity, SecurityFinding
from linuxtrace.models.normalized_event import NormalizedEvent

RULE_ID = "LT-SSH-001"
FAILED_TYPES = frozenset({"ssh_login_failed", "ssh_invalid_user"})


def detect_ssh_bruteforce(
    events: Iterable[NormalizedEvent],
    *,
    threshold: int = 5,
    window_minutes: int = 5,
) -> list[SecurityFinding]:
    """Detect SSH failure bursts for each source IP and host."""

    if threshold < 2:
        raise ValueError("threshold must be at least 2")

    if window_minutes < 1:
        raise ValueError("window_minutes must be positive")

    groups: dict[tuple[str, str], dict[str, NormalizedEvent]] = defaultdict(dict)

    for event in events:
        if (
            event.event_type not in FAILED_TYPES
            or event.outcome != "failure"
            or event.timestamp is None
            or not event.source_ip
        ):
            continue

        try:
            source_ip = str(ip_address(event.source_ip))
        except ValueError:
            continue

        key = (event.hostname or "", source_ip)
        groups[key][event.event_id] = event

    findings = []
    window = timedelta(minutes=window_minutes)

    for (hostname, source_ip), unique_events in sorted(groups.items()):
        ordered = sorted(
            unique_events.values(),
            key=lambda event: (event.timestamp, event.event_id),
        )

        start = 0
        index = 0

        while index < len(ordered):
            current = ordered[index]

            while current.timestamp - ordered[start].timestamp > window:
                start += 1

            if index - start + 1 < threshold:
                index += 1
                continue

            matched = ordered[start : index + 1]
            first = matched[0]
            last = matched[-1]

            ids = sorted(event.event_id for event in matched)
            identity = "|".join([RULE_ID, hostname, source_ip, *ids])
            finding_id = sha256(identity.encode("utf-8")).hexdigest()

            findings.append(
                SecurityFinding(
                    finding_id=finding_id,
                    rule_id=RULE_ID,
                    title="SSH Brute-Force Detected",
                    description=(
                        f"{len(matched)} failed SSH authentication attempts "
                        f"from {source_ip} on {hostname or 'unknown host'} "
                        f"within {window_minutes} minutes."
                    ),
                    severity=FindingSeverity.HIGH,
                    start_time=first.timestamp,
                    end_time=last.timestamp,
                    source_ip=source_ip,
                    related_event_ids=ids,
                    mitre_techniques=["T1110"],
                )
            )

            # Avoid overlapping findings for the same matched events.
            index += 1
            start = index

    return sorted(
        findings,
        key=lambda finding: (
            finding.start_time,
            finding.finding_id,
        ),
    )
