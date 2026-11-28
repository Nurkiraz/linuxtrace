"""Run registered security detection rules with bounded SSH grouping."""

import sqlite3
from collections.abc import Iterable
from contextlib import closing
from datetime import timedelta
from ipaddress import ip_address
from pathlib import Path
from tempfile import TemporaryDirectory

from linuxtrace.detection.config import DetectionConfig
from linuxtrace.detection.models import SecurityFinding
from linuxtrace.detection.registry import get_registered_rules
from linuxtrace.detection.ssh_bruteforce import FAILED_TYPES
from linuxtrace.detection.ssh_bruteforce_state import SSHBruteForceState
from linuxtrace.detection.ssh_correlation_state import SSHSuccessCorrelationState
from linuxtrace.models.normalized_event import NormalizedEvent

AUDIT_BATCH_SIZE = 500
SSH_EVENT_TYPES = frozenset(
    {
        "ssh_login_failed",
        "ssh_invalid_user",
        "ssh_login_success",
    }
)


def _run_ssh_groups(connection, rules, config):
    """Execute stateful SSH rules and legacy group-based rules."""

    findings = []
    current_key = None
    last_timestamp = None
    group = []

    stateful_ids = {"LT-SSH-001", "LT-SSH-002"}

    brute_rule = next(
        (rule for rule in rules if rule.rule_id == "LT-SSH-001"),
        None,
    )
    correlation_rule = next(
        (rule for rule in rules if rule.rule_id == "LT-SSH-002"),
        None,
    )
    other_rules = [rule for rule in rules if rule.rule_id not in stateful_ids]

    max_window = timedelta(
        minutes=max(getattr(config, rule.config_key).window_minutes for rule in rules)
    )

    brute_state = None
    correlation_state = None

    def flush():
        if not group:
            return

        for rule in other_rules:
            settings = getattr(config, rule.config_key)
            findings.extend(
                rule.detector(
                    group,
                    threshold=settings.threshold,
                    window_minutes=settings.window_minutes,
                )
            )

        group.clear()

    cursor = connection.execute(
        """
        SELECT hostname, source_ip, event_json
        FROM ssh_events
        WHERE rowid IN (
            SELECT MAX(rowid)
            FROM ssh_events
            GROUP BY hostname, source_ip, event_id
        )
        ORDER BY hostname, source_ip, timestamp, event_id
        """
    )

    for hostname, source_ip, event_json in cursor:
        event = NormalizedEvent.model_validate_json(event_json)
        key = (hostname, source_ip)

        source_changed = current_key is not None and key != current_key
        inactive = (
            not source_changed
            and last_timestamp is not None
            and event.timestamp - last_timestamp > max_window
        )

        if source_changed or inactive:
            flush()
            brute_state = None
            correlation_state = None

        if brute_rule is not None:
            if brute_state is None:
                settings = getattr(config, brute_rule.config_key)
                brute_state = SSHBruteForceState(
                    hostname,
                    source_ip,
                    threshold=settings.threshold,
                    window_minutes=settings.window_minutes,
                )

            if event.event_type in FAILED_TYPES and event.outcome == "failure":
                finding = brute_state.process(event)
                if finding is not None:
                    findings.append(finding)

        if correlation_rule is not None:
            if correlation_state is None:
                settings = getattr(config, correlation_rule.config_key)
                correlation_state = SSHSuccessCorrelationState(
                    hostname,
                    source_ip,
                    threshold=settings.threshold,
                    window_minutes=settings.window_minutes,
                )

            finding = correlation_state.process(event)
            if finding is not None:
                findings.append(finding)

        if other_rules:
            group.append(event)

        current_key = key
        last_timestamp = event.timestamp

    flush()
    return findings


def run_ssh_detections(
    events: Iterable[NormalizedEvent],
    *,
    threshold: int = 5,
    window_minutes: int = 5,
    config: DetectionConfig | None = None,
) -> list[SecurityFinding]:
    """Execute enabled rules without retaining all SSH events in RAM."""

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

    enabled_rules = [
        rule for rule in get_registered_rules() if getattr(config, rule.config_key).enabled
    ]

    ssh_rules = [rule for rule in enabled_rules if rule.uses_window]
    audit_rules = [rule for rule in enabled_rules if not rule.uses_window]

    findings = []
    audit_batch = []

    def flush_audit():
        if not audit_batch:
            return

        for rule in audit_rules:
            findings.extend(rule.detector(audit_batch))

        audit_batch.clear()

    with TemporaryDirectory(prefix="linuxtrace-detection-") as directory:
        spool_path = Path(directory) / "ssh-events.db"

        with closing(sqlite3.connect(spool_path)) as connection:
            connection.execute("PRAGMA temp_store=FILE")
            connection.execute("PRAGMA cache_size=-2048")
            connection.execute(
                """
                CREATE TABLE ssh_events (
                    hostname TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    event_json TEXT NOT NULL
                )
                """
            )

            with connection:
                for event in events:
                    if event.event_type == "audit_syscall":
                        if audit_rules:
                            audit_batch.append(event)

                            if len(audit_batch) >= AUDIT_BATCH_SIZE:
                                flush_audit()

                    elif event.event_type in SSH_EVENT_TYPES and ssh_rules:
                        if not event.source_ip or event.timestamp is None:
                            continue

                        try:
                            canonical_ip = str(ip_address(event.source_ip))
                        except ValueError:
                            continue

                        connection.execute(
                            """
                            INSERT INTO ssh_events (
                                hostname,
                                source_ip,
                                timestamp,
                                event_id,
                                event_json
                            )
                            VALUES (?, ?, ?, ?, ?)
                            """,
                            (
                                event.hostname or "",
                                canonical_ip,
                                event.timestamp.isoformat(),
                                event.event_id,
                                event.model_dump_json(),
                            ),
                        )

            flush_audit()

            if ssh_rules:
                connection.execute(
                    """
                    CREATE INDEX idx_ssh_group_order
                    ON ssh_events (
                        hostname,
                        source_ip,
                        timestamp,
                        event_id
                    )
                    """
                )

                findings.extend(_run_ssh_groups(connection, ssh_rules, config))

    return sorted(
        findings,
        key=lambda finding: (
            finding.start_time,
            finding.rule_id,
            finding.finding_id,
        ),
    )
