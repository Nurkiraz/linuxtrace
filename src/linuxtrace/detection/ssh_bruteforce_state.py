"""Stateful SSH brute-force detection for ordered, unique events."""

from collections import deque
from datetime import timedelta
from hashlib import sha256
from ipaddress import ip_address

from linuxtrace.detection.models import FindingSeverity, SecurityFinding
from linuxtrace.detection.ssh_bruteforce import FAILED_TYPES, RULE_ID
from linuxtrace.models.normalized_event import NormalizedEvent


class SSHBruteForceState:
    """Detect SSH failure bursts within one host and source-IP group.

    Input requirements:
    - Events belong to one host/source-IP group.
    - Events are ordered by (timestamp, event_id).
    - Event IDs are unique within the group.

    SQLite grouping must enforce these requirements before integration.
    """

    def __init__(
        self,
        hostname: str,
        source_ip: str,
        *,
        threshold: int = 5,
        window_minutes: int = 5,
    ):
        if threshold < 2:
            raise ValueError("threshold must be at least 2")

        if window_minutes < 1:
            raise ValueError("window_minutes must be positive")

        self.hostname = hostname or ""
        self.source_ip = str(ip_address(source_ip))
        self.threshold = threshold
        self.window_minutes = window_minutes
        self.window = timedelta(minutes=window_minutes)

        self.active = deque()
        self.last_key = None

    def process(
        self,
        event: NormalizedEvent,
    ) -> SecurityFinding | None:
        """Consume an event and optionally emit one finding."""

        if (
            event.event_type not in FAILED_TYPES
            or event.outcome != "failure"
            or event.timestamp is None
            or not event.source_ip
        ):
            return None

        event_ip = str(ip_address(event.source_ip))
        if (event.hostname or "", event_ip) != (
            self.hostname,
            self.source_ip,
        ):
            raise ValueError("Event belongs to a different SSH group")

        key = (event.timestamp, event.event_id)

        if self.last_key is not None and key <= self.last_key:
            raise ValueError("Events must be unique and strictly ordered by (timestamp, event_id)")

        self.last_key = key

        while self.active and event.timestamp - self.active[0].timestamp > self.window:
            self.active.popleft()

        self.active.append(event)

        if len(self.active) < self.threshold:
            return None

        matched = list(self.active)
        self.active.clear()

        ids = sorted(item.event_id for item in matched)
        identity = "|".join([RULE_ID, self.hostname, self.source_ip, *ids])
        finding_id = sha256(identity.encode("utf-8")).hexdigest()

        return SecurityFinding(
            finding_id=finding_id,
            rule_id=RULE_ID,
            title="SSH Brute-Force Detected",
            description=(
                f"{len(matched)} failed SSH authentication attempts "
                f"from {self.source_ip} on "
                f"{self.hostname or 'unknown host'} "
                f"within {self.window_minutes} minutes."
            ),
            severity=FindingSeverity.HIGH,
            start_time=matched[0].timestamp,
            end_time=matched[-1].timestamp,
            source_ip=self.source_ip,
            related_event_ids=ids,
            mitre_techniques=["T1110"],
        )
