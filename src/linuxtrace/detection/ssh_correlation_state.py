"""Stateful SSH success-after-failures detection."""

from collections import deque
from datetime import timedelta
from hashlib import sha256
from ipaddress import ip_address

from linuxtrace.detection.models import FindingSeverity, SecurityFinding
from linuxtrace.detection.ssh_bruteforce import FAILED_TYPES
from linuxtrace.detection.ssh_correlation import RULE_ID
from linuxtrace.models.normalized_event import NormalizedEvent


class SSHSuccessCorrelationState:
    """Correlate ordered, unique SSH events from one source group.

    Input requirements:
    - A single hostname/source-IP group.
    - Strict order by (timestamp, event_id).
    - Unique event IDs within the group.
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

        self.failures = deque()
        self.last_key = None

    def process(
        self,
        event: NormalizedEvent,
    ) -> SecurityFinding | None:
        """Consume an event and optionally emit a correlation finding."""

        if event.timestamp is None or not event.source_ip:
            return None

        is_failure = event.event_type in FAILED_TYPES and event.outcome == "failure"
        is_success = event.event_type == "ssh_login_success" and event.outcome == "success"

        if not (is_failure or is_success):
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

        while self.failures and event.timestamp - self.failures[0].timestamp > self.window:
            self.failures.popleft()

        if is_failure:
            self.failures.append(event)
            return None

        if len(self.failures) < self.threshold:
            return None

        recent = list(self.failures)
        matched = [*recent, event]
        ids = sorted(item.event_id for item in matched)

        identity = "|".join([RULE_ID, self.hostname, self.source_ip, *ids])
        finding_id = sha256(identity.encode()).hexdigest()

        finding = SecurityFinding(
            finding_id=finding_id,
            rule_id=RULE_ID,
            title="SSH Login Success After Repeated Failures",
            description=(
                f"{len(recent)} failed SSH attempts from "
                f"{self.source_ip} were followed by a successful "
                f"login for {event.username or 'unknown user'} "
                f"on {self.hostname or 'unknown host'}."
            ),
            severity=FindingSeverity.CRITICAL,
            start_time=recent[0].timestamp,
            end_time=event.timestamp,
            source_ip=self.source_ip,
            username=event.username,
            related_event_ids=ids,
            mitre_techniques=["T1110"],
        )

        # These failures must not contribute to another finding.
        self.failures.clear()

        return finding
