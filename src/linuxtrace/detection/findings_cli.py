"""CLI for inspecting stored security findings."""

import json
import sqlite3
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from linuxtrace.detection.models import FindingSeverity
from linuxtrace.detection.repository import FindingRepository
from linuxtrace.storage.database import Database

findings_app = typer.Typer(
    help="Inspect stored security detection findings.",
    no_args_is_help=True,
)


def open_findings(db_path: Path) -> FindingRepository:
    """Open an existing forensic database."""

    if not db_path.is_file():
        raise ValueError(f"Database not found: {db_path}")

    return FindingRepository(Database(db_path))


@findings_app.command("list")
def findings_list(
    db_path: Annotated[
        Path,
        typer.Option("--db", help="Existing SQLite database."),
    ] = Path("data/linuxtrace.db"),
    severity: Annotated[
        FindingSeverity | None,
        typer.Option("--severity", help="Filter by severity."),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", min=1, max=10000),
    ] = 100,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output JSON."),
    ] = False,
):
    """List saved detection findings."""

    try:
        repository = open_findings(db_path)
        findings = repository.list_findings(
            severity=severity,
            limit=limit,
        )
    except (sqlite3.Error, OSError, ValueError, ValidationError) as exc:
        typer.echo(f"Findings query failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "total_findings": len(findings),
                    "findings": [finding.model_dump(mode="json") for finding in findings],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    typer.echo("LinuxTrace - Security Findings")
    typer.echo(f"Findings: {len(findings)}")

    for finding in findings:
        typer.echo("")
        typer.echo(f"[{finding.severity.value.upper()}] {finding.title}")
        typer.echo(f"Finding ID: {finding.finding_id}")
        typer.echo(f"Rule: {finding.rule_id}")
        typer.echo(f"Source IP: {finding.source_ip or '-'}")
        typer.echo(f"Start: {finding.start_time.isoformat()}")
        typer.echo(f"Related events: {len(finding.related_event_ids)}")


@findings_app.command("show")
def findings_show(
    finding_id: Annotated[
        str,
        typer.Argument(help="SHA-256 finding identifier."),
    ],
    db_path: Annotated[
        Path,
        typer.Option("--db", help="Existing SQLite database."),
    ] = Path("data/linuxtrace.db"),
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output JSON."),
    ] = False,
    events: Annotated[
        bool,
        typer.Option("--events", help="Inspect linked forensic events."),
    ] = False,
):
    """Show one finding and its related forensic event IDs."""

    try:
        repository = open_findings(db_path)
        finding = repository.get(finding_id)
    except (sqlite3.Error, OSError, ValueError, ValidationError) as exc:
        typer.echo(f"Finding query failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if finding is None:
        typer.echo("Finding not found.", err=True)
        raise typer.Exit(code=1)

    evidence = None

    if events:
        from linuxtrace.detection.evidence import inspect_finding_events

        try:
            evidence = inspect_finding_events(db_path, finding)
        except (sqlite3.Error, OSError, ValueError) as exc:
            typer.echo(f"Evidence inspection failed: {exc}", err=True)
            raise typer.Exit(code=1) from exc

    if json_output:
        payload = finding.model_dump(mode="json")

        if evidence is not None:
            payload["linked_evidence"] = evidence

        typer.echo(
            json.dumps(
                payload,
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    typer.echo("LinuxTrace - Finding Details")
    typer.echo(f"Finding ID: {finding.finding_id}")
    typer.echo(f"Rule: {finding.rule_id}")
    typer.echo(f"Title: {finding.title}")
    typer.echo(f"Severity: {finding.severity.value.upper()}")
    typer.echo(f"Description: {finding.description}")
    typer.echo(f"Source IP: {finding.source_ip or '-'}")
    typer.echo(f"Start: {finding.start_time.isoformat()}")
    typer.echo(f"End: {finding.end_time.isoformat()}")
    typer.echo(f"MITRE: {', '.join(finding.mitre_techniques) or '-'}")

    typer.echo("")
    typer.echo("Related forensic events:")

    for event_id in finding.related_event_ids:
        typer.echo(f"  {event_id}")

    if evidence is not None:
        typer.echo("")
        typer.echo("Linked Evidence Verification")
        typer.echo(f"Expected events: {evidence['expected_events']}")
        typer.echo(f"Verified events: {evidence['verified_events']}")
        typer.echo(
            "Reference status: " + ("VALID" if evidence["all_references_valid"] else "WARNING")
        )

        for event in evidence["events"]:
            typer.echo("")
            typer.echo(f"Event: {event['event_id']}")
            typer.echo(f"Type: {event['event_type']}")
            typer.echo(f"Source: {event['source_file']}:{event['source_line']}")
            typer.echo(f"Description: {event['description']}")

        for event_id in evidence["missing_event_ids"]:
            typer.echo(f"WARNING: Missing event {event_id}", err=True)

        for event_id in evidence["invalid_event_ids"]:
            typer.echo(f"WARNING: Invalid event {event_id}", err=True)

        if not evidence["all_references_valid"]:
            raise typer.Exit(code=2)


def register_findings_commands(app: typer.Typer) -> None:
    """Register the findings command group."""

    app.add_typer(findings_app, name="findings")
