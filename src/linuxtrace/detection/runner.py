"""Run registered security detection rules with bounded SSH grouping."""

import sqlite3
from collections.abc import Iterable
from contextlib import closing
from ipaddress import ip_address
from pathlib import Path
from tempfile import TemporaryDirectory

from linuxtrace.detection.config import DetectionConfig
from linuxtrace.detection.models import SecurityFinding
from linuxtrace.detection.registry import get_registered_rules
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
    """Process one SSH source group at a time."""

    findings = []
    current_key = None
    group = []

    def flush():
        if not group:
            return

        for rule in rules:
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
        ORDER BY hostname, source_ip, timestamp, event_id
        """
    )

    for hostname, source_ip, event_json in cursor:
        key = (hostname, source_ip)

        if current_key is not None and key != current_key:
            flush()

        current_key = key
        group.append(NormalizedEvent.model_validate_json(event_json))

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
