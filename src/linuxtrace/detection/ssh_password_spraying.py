"""Detect SSH password spraying against multiple usernames."""

from collections import defaultdict, deque
from collections.abc import Iterable
from datetime import timedelta
from hashlib import sha256
from ipaddress import ip_address

from linuxtrace.detection.models import FindingSeverity, SecurityFinding
from linuxtrace.detection.ssh_bruteforce import FAILED_TYPES
from linuxtrace.models.normalized_event import NormalizedEvent

RULE_ID = "LT-SSH-003"


def detect_ssh_password_spraying(
    events: Iterable[NormalizedEvent],
    *,
    threshold: int = 5,
    window_minutes: int = 10,
) -> list[SecurityFinding]:
    """Detect failures targeting distinct users from one IP and host."""

    if not 2 <= threshold <= 10000:
        raise ValueError("threshold must be between 2 and 10000")

    if not 1 <= window_minutes <= 1440:
        raise ValueError("window_minutes must be between 1 and 1440")

    groups = defaultdict(dict)

    for event in events:
        if (
            event.event_type not in FAILED_TYPES
            or event.outcome != "failure"
            or event.timestamp is None
            or not event.source_ip
            or not event.username
        ):
            continue

        try:
            source_ip = str(ip_address(event.source_ip))
        except ValueError:
            continue

        key = (event.hostname or "", source_ip)
        groups[key][event.event_id] = event

    window = timedelta(minutes=window_minutes)
    findings = []

    for (hostname, source_ip), unique in sorted(groups.items()):
        ordered = sorted(
            unique.values(),
            key=lambda event: (event.timestamp, event.event_id),
        )

        active = deque()
        usernames = defaultdict(int)

        for event in ordered:
            active.append(event)
            usernames[event.username] += 1

            while active and event.timestamp - active[0].timestamp > window:
                expired = active.popleft()
                usernames[expired.username] -= 1

                if usernames[expired.username] == 0:
                    del usernames[expired.username]

            if len(usernames) < threshold:
                continue

            matched = list(active)
            event_ids = sorted(item.event_id for item in matched)

            identity = "|".join([RULE_ID, hostname, source_ip, *event_ids])
            finding_id = sha256(identity.encode("utf-8")).hexdigest()

            findings.append(
                SecurityFinding(
                    finding_id=finding_id,
                    rule_id=RULE_ID,
                    title="SSH Password Spraying Detected",
                    description=(
                        f"Failed SSH attempts from {source_ip} targeted "
                        f"{len(usernames)} distinct usernames on "
                        f"{hostname or 'unknown host'} within "
                        f"{window_minutes} minutes."
                    ),
                    severity=FindingSeverity.HIGH,
                    start_time=matched[0].timestamp,
                    end_time=matched[-1].timestamp,
                    source_ip=source_ip,
                    related_event_ids=event_ids,
                    mitre_techniques=["T1110.003"],
                )
            )

            # Start a new detection batch to prevent overlapping findings.
            active.clear()
            usernames.clear()

    return sorted(
        findings,
        key=lambda finding: (
            finding.start_time,
            finding.finding_id,
        ),
    )
