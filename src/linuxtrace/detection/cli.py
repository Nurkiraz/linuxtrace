"""CLI commands for security detections."""

import json
import sqlite3
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from linuxtrace.detection.repository import FindingRepository
from linuxtrace.detection.ssh_bruteforce import detect_ssh_bruteforce
from linuxtrace.models.normalized_event import NormalizedEvent
from linuxtrace.storage.database import Database

detect_app = typer.Typer(
    help="Analyze collected events for suspicious activity.",
    no_args_is_help=True,
)


def load_ssh_failures(db_path: Path):
    """Read SSH failure events without modifying the database."""

    if not db_path.is_file():
        raise ValueError(f"Database not found: {db_path}")

    connection = sqlite3.connect(
        db_path.resolve().as_uri() + "?mode=ro",
        uri=True,
    )

    try:
        cursor = connection.execute(
            """
            SELECT event_json
            FROM events
            WHERE event_type IN (?, ?)
              AND outcome = ?
              AND timestamp IS NOT NULL
              AND source_ip IS NOT NULL
            ORDER BY timestamp, event_id
            """,
            ("ssh_login_failed", "ssh_invalid_user", "failure"),
        )

        while batch := cursor.fetchmany(500):
            for (event_json,) in batch:
                yield NormalizedEvent.model_validate_json(event_json)
    finally:
        connection.close()


@detect_app.command("ssh-bruteforce")
def ssh_bruteforce_command(
    db_path: Annotated[
        Path,
        typer.Option("--db", help="Existing SQLite database."),
    ] = Path("data/linuxtrace.db"),
    threshold: Annotated[
        int,
        typer.Option("--threshold", min=2),
    ] = 5,
    window: Annotated[
        int,
        typer.Option("--window", min=1, help="Window in minutes."),
    ] = 5,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output findings as JSON."),
    ] = False,
    save: Annotated[
        bool,
        typer.Option("--save", help="Save findings to SQLite."),
    ] = False,
):
    """Detect repeated failed SSH authentication attempts."""

    try:
        findings = detect_ssh_bruteforce(
            load_ssh_failures(db_path),
            threshold=threshold,
            window_minutes=window,
        )
        saved = 0

        if save:
            repository = FindingRepository(Database(db_path))
            repository.initialize()

            for finding in findings:
                if repository.save(finding):
                    saved += 1

    except (sqlite3.Error, OSError, ValueError, ValidationError) as exc:
        typer.echo(f"Detection failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "rule_id": "LT-SSH-001",
                    "total_findings": len(findings),
                    "saved_findings": saved,
                    "findings": [finding.model_dump(mode="json") for finding in findings],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return

    typer.echo("LinuxTrace - SSH Brute-Force Detection")
    typer.echo(f"Threshold: {threshold} attempts")
    typer.echo(f"Window: {window} minutes")
    typer.echo(f"Findings: {len(findings)}")
    if save:
        typer.echo(f"Saved findings: {saved}")

    for finding in findings:
        typer.echo("")
        typer.echo(f"[{finding.severity.value.upper()}] {finding.title}")
        typer.echo(f"Finding ID: {finding.finding_id}")
        typer.echo(f"Source IP: {finding.source_ip}")
        typer.echo(f"Start: {finding.start_time.isoformat()}")
        typer.echo(f"End: {finding.end_time.isoformat()}")
        typer.echo(f"Events: {len(finding.related_event_ids)}")
        typer.echo(f"MITRE: {', '.join(finding.mitre_techniques)}")


def register_detection_commands(app: typer.Typer) -> None:
    """Register the detection CLI group."""

    app.add_typer(detect_app, name="detect")


def load_ssh_authentication_events(db_path: Path):
    """Read SSH success and failure events from SQLite."""

    if not db_path.is_file():
        raise ValueError(f"Database not found: {db_path}")

    connection = sqlite3.connect(
        db_path.resolve().as_uri() + "?mode=ro",
        uri=True,
    )

    try:
        cursor = connection.execute(
            """
            SELECT event_json
            FROM events
            WHERE event_type IN (?, ?, ?)
              AND timestamp IS NOT NULL
              AND source_ip IS NOT NULL
            ORDER BY timestamp, event_id
            """,
            (
                "ssh_login_failed",
                "ssh_invalid_user",
                "ssh_login_success",
            ),
        )

        while batch := cursor.fetchmany(500):
            for (event_json,) in batch:
                yield NormalizedEvent.model_validate_json(event_json)
    finally:
        connection.close()


@detect_app.command("ssh-success-after-failures")
def ssh_success_after_failures_command(
    db_path: Annotated[
        Path,
        typer.Option("--db", help="Existing SQLite database."),
    ] = Path("data/linuxtrace.db"),
    threshold: Annotated[
        int,
        typer.Option("--threshold", min=2),
    ] = 5,
    window: Annotated[
        int,
        typer.Option("--window", min=1, help="Window in minutes."),
    ] = 5,
    save: Annotated[
        bool,
        typer.Option("--save", help="Save findings to SQLite."),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output findings as JSON."),
    ] = False,
):
    """Detect successful SSH logins after repeated failures."""

    from linuxtrace.detection.ssh_correlation import (
        detect_ssh_success_after_failures,
    )

    try:
        findings = detect_ssh_success_after_failures(
            load_ssh_authentication_events(db_path),
            threshold=threshold,
            window_minutes=window,
        )

        saved = 0

        if save:
            repository = FindingRepository(Database(db_path))
            repository.initialize()

            for finding in findings:
                if repository.save(finding):
                    saved += 1

    except (sqlite3.Error, OSError, ValueError, ValidationError) as exc:
        typer.echo(f"Correlation failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "rule_id": "LT-SSH-002",
                    "total_findings": len(findings),
                    "saved_findings": saved,
                    "findings": [finding.model_dump(mode="json") for finding in findings],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    typer.echo("LinuxTrace - SSH Authentication Correlation")
    typer.echo(f"Threshold: {threshold} failures")
    typer.echo(f"Window: {window} minutes")
    typer.echo(f"Findings: {len(findings)}")

    if save:
        typer.echo(f"Saved findings: {saved}")

    for finding in findings:
        typer.echo("")
        typer.echo(f"[{finding.severity.value.upper()}] {finding.title}")
        typer.echo(f"Finding ID: {finding.finding_id}")
        typer.echo(f"Source IP: {finding.source_ip}")
        typer.echo(f"Username: {finding.username or '-'}")
        typer.echo(f"Start: {finding.start_time.isoformat()}")
        typer.echo(f"End: {finding.end_time.isoformat()}")
        typer.echo(f"Related events: {len(finding.related_event_ids)}")
        typer.echo(f"MITRE: {', '.join(finding.mitre_techniques)}")


def load_detection_events(db_path: Path):
    """Load supported SSH and auditd events without database writes."""

    if not db_path.is_file():
        raise ValueError(f"Database not found: {db_path}")

    connection = sqlite3.connect(
        db_path.resolve().as_uri() + "?mode=ro",
        uri=True,
    )

    try:
        cursor = connection.execute(
            """
            SELECT event_json
            FROM events
            WHERE event_type IN (?, ?, ?, ?)
              AND timestamp IS NOT NULL
            ORDER BY timestamp, event_id
            """,
            (
                "ssh_login_failed",
                "ssh_invalid_user",
                "ssh_login_success",
                "audit_syscall",
            ),
        )

        while batch := cursor.fetchmany(500):
            for (event_json,) in batch:
                yield NormalizedEvent.model_validate_json(event_json)
    finally:
        connection.close()


@detect_app.command("run")
def detect_run_command(
    db_path: Annotated[
        Path,
        typer.Option("--db", help="Existing SQLite database."),
    ] = Path("data/linuxtrace.db"),
    threshold: Annotated[
        int,
        typer.Option("--threshold", min=2),
    ] = 5,
    window: Annotated[
        int,
        typer.Option("--window", min=1),
    ] = 5,
    save: Annotated[
        bool,
        typer.Option("--save", help="Persist findings."),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output JSON."),
    ] = False,
    config_path: Annotated[
        Path | None,
        typer.Option("--config", help="YAML detection configuration."),
    ] = None,
):
    """Run all enabled SSH detection rules."""

    from linuxtrace.detection.config import load_detection_config
    from linuxtrace.detection.registry import get_registered_rules
    from linuxtrace.detection.runner import run_ssh_detections

    try:
        config = load_detection_config(config_path) if config_path is not None else None

        findings = run_ssh_detections(
            load_detection_events(db_path),
            threshold=threshold,
            window_minutes=window,
            config=config,
        )

        saved = 0

        if save:
            repository = FindingRepository(Database(db_path))
            repository.initialize()

            for finding in findings:
                if repository.save(finding):
                    saved += 1

    except (sqlite3.Error, OSError, ValueError, ValidationError) as exc:
        typer.echo(f"Detection run failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "rules": [
                        rule.rule_id
                        for rule in get_registered_rules()
                        if config is None or getattr(config, rule.config_key).enabled
                    ],
                    "total_findings": len(findings),
                    "saved_findings": saved,
                    "findings": [finding.model_dump(mode="json") for finding in findings],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    typer.echo("LinuxTrace - Unified Detection Runner")
    enabled = [
        rule.rule_id
        for rule in get_registered_rules()
        if config is None or getattr(config, rule.config_key).enabled
    ]
    typer.echo(f"Rules: {', '.join(enabled) or 'none'}")
    typer.echo(f"Findings: {len(findings)}")

    if save:
        typer.echo(f"Saved findings: {saved}")

    for finding in findings:
        typer.echo(
            f"[{finding.severity.value.upper()}] "
            f"{finding.rule_id} | {finding.source_ip} | "
            f"{finding.finding_id}"
        )


@detect_app.command("rules")
def detection_rules_command(
    config_path: Annotated[
        Path | None,
        typer.Option("--config", help="YAML detection configuration."),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output rule catalog as JSON."),
    ] = False,
):
    """List available detection rules and their configuration."""

    from linuxtrace.detection.config import (
        DetectionConfig,
        load_detection_config,
    )
    from linuxtrace.detection.rule_catalog import list_detection_rules

    try:
        config = (
            load_detection_config(config_path) if config_path is not None else DetectionConfig()
        )
        rules = list_detection_rules(config)
    except (OSError, ValueError) as exc:
        typer.echo(f"Rule configuration failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "total_rules": len(rules),
                    "enabled_rules": sum(rule["enabled"] for rule in rules),
                    "rules": rules,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    typer.echo("LinuxTrace - Detection Rules")
    typer.echo(f"Total rules: {len(rules)}")
    typer.echo(f"Enabled rules: {sum(rule['enabled'] for rule in rules)}")

    for rule in rules:
        typer.echo("")
        typer.echo(f"Rule: {rule['rule_id']}")
        typer.echo(f"Name: {rule['name']}")
        typer.echo(f"Severity: {rule['severity'].upper()}")
        typer.echo(f"Status: {'ENABLED' if rule['enabled'] else 'DISABLED'}")
        if "threshold" in rule:
            typer.echo(f"Threshold: {rule['threshold']}")
            typer.echo(f"Window: {rule['window_minutes']} minutes")
        typer.echo(f"MITRE: {', '.join(rule['mitre_techniques'])}")
