import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from linuxtrace import __version__
from linuxtrace.detection.cli import register_detection_commands
from linuxtrace.detection.findings_cli import register_findings_commands
from linuxtrace.doctor import run_doctor
from linuxtrace.storage.database import Database
from linuxtrace.storage.event_group_query import EventGroupQuery
from linuxtrace.storage.event_query import EventQuery
from linuxtrace.timeline import display_timeline
from linuxtrace.timeline_grouping import display_grouped_counts
from linuxtrace.utils.time_filter import get_time_range

app = typer.Typer(
    name="linuxtrace",
    help="Linux Incident Timeline and Forensic Analysis Tool.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()

register_detection_commands(app)
register_findings_commands(app)


@app.callback()
def main():
    """Linux forensic analysis command-line interface."""


@app.command()
def version():
    """Display the LinuxTrace version."""
    console.print(f"[bold cyan]LinuxTrace[/bold cyan] v{__version__}")


@app.command()
def doctor():
    """Check system compatibility and discover log sources."""
    run_doctor()


collect_app = typer.Typer(help="Collect Linux forensic evidence.")
app.add_typer(collect_app, name="collect")


@collect_app.command("syslog")
def collect_syslog_command(
    root: Annotated[Path, typer.Option("--root", help="Evidence root.")],
    year: Annotated[int, typer.Option("--year", min=1970, max=9999)],
    timezone: Annotated[str, typer.Option("--timezone")],
    db_path: Annotated[str, typer.Option("--db")] = "data/linuxtrace.db",
    incremental: Annotated[
        bool,
        typer.Option("--incremental", help="Skip unchanged syslog files."),
    ] = False,
):
    """Collect Linux syslog files into SQLite."""
    import sqlite3
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    from linuxtrace.collectors.incremental_syslog import (
        collect_incremental_syslog,
    )
    from linuxtrace.collectors.syslog_import import import_syslog
    from linuxtrace.storage.event_repository import EventRepository
    from linuxtrace.storage.incremental import IncrementalTracker

    if not root.is_dir():
        typer.echo(f"Evidence directory not found: {root}", err=True)
        raise typer.Exit(code=1)

    try:
        ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError):
        typer.echo(f"Invalid timezone: {timezone}", err=True)
        raise typer.Exit(code=2) from None

    try:
        if incremental:
            database = Database(Path(db_path))
            database.initialize()

            repository = EventRepository(database)
            tracker = IncrementalTracker(database)
            tracker.initialize()

            result = collect_incremental_syslog(
                root=root,
                repository=repository,
                tracker=tracker,
                year=year,
                source_timezone=timezone,
            )

            if result.errors:
                for error in result.errors:
                    typer.echo(f"Collection error: {error}", err=True)
                raise typer.Exit(code=1)

            typer.echo("LinuxTrace - Incremental Syslog Collection")
            typer.echo(f"Processed files: {result.processed_files}")
            typer.echo(f"Skipped files: {result.skipped_files}")
            typer.echo(f"Read events: {result.events_read}")
            typer.echo(f"Inserted events: {result.events_inserted}")

        else:
            result = import_syslog(
                root=root,
                db_path=Path(db_path),
                year=year,
                source_timezone=timezone,
            )

            if result.errors:
                for error in result.errors:
                    typer.echo(f"Collection error: {error}", err=True)
                raise typer.Exit(code=1)

            typer.echo("LinuxTrace - Syslog Collection")
            typer.echo(f"Read events: {result.read}")
            typer.echo(f"Inserted events: {result.inserted}")
            typer.echo(f"Existing events: {result.read - result.inserted}")

    except (OSError, ValueError, sqlite3.Error) as exc:
        typer.echo(f"Collection failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


def _collect_system_source(
    source: str,
    root: Path,
    year: int,
    timezone: str,
    db_path: str,
) -> None:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    from linuxtrace.collectors.system_file_import import import_system_file

    if not root.is_dir():
        typer.echo(f"Evidence directory not found: {root}", err=True)
        raise typer.Exit(code=1)

    try:
        ZoneInfo(timezone)
    except (ValueError, ZoneInfoNotFoundError):
        typer.echo(f"Invalid timezone: {timezone}", err=True)
        raise typer.Exit(code=2) from None

    try:
        result = import_system_file(
            root=root,
            db_path=Path(db_path),
            source=source,
            year=year,
            source_timezone=timezone,
        )
    except (OSError, ValueError) as exc:
        typer.echo(f"Collection failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if result.errors:
        for error in result.errors:
            typer.echo(f"Collection error: {error}", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"LinuxTrace - {source.title()} Collection")
    typer.echo(f"Read events: {result.read}")
    typer.echo(f"Inserted events: {result.inserted}")
    typer.echo(f"Existing events: {result.read - result.inserted}")


@collect_app.command("kernel")
def collect_kernel_command(
    root: Annotated[Path, typer.Option("--root")],
    year: Annotated[int, typer.Option("--year", min=1970, max=9999)],
    timezone: Annotated[str, typer.Option("--timezone")],
    db_path: Annotated[str, typer.Option("--db")] = "data/linuxtrace.db",
):
    """Collect standalone kernel log files."""
    _collect_system_source("kernel", root, year, timezone, db_path)


@collect_app.command("cron")
def collect_cron_command(
    root: Annotated[Path, typer.Option("--root")],
    year: Annotated[int, typer.Option("--year", min=1970, max=9999)],
    timezone: Annotated[str, typer.Option("--timezone")],
    db_path: Annotated[str, typer.Option("--db")] = "data/linuxtrace.db",
):
    """Collect standalone Cron log files."""
    _collect_system_source("cron", root, year, timezone, db_path)


@collect_app.command("audit")
def collect_audit_command(
    root: Annotated[Path, typer.Option("--root")],
    db_path: Annotated[str, typer.Option("--db")] = "data/linuxtrace.db",
):
    """Collect and correlate Linux auditd records."""
    import sqlite3

    from linuxtrace.collectors.audit_import import import_audit

    if not root.is_dir():
        typer.echo(f"Evidence directory not found: {root}", err=True)
        raise typer.Exit(code=1)

    try:
        result = import_audit(
            root=root,
            db_path=Path(db_path),
        )
    except (OSError, ValueError, sqlite3.Error) as exc:
        typer.echo(f"Audit collection failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if result.errors:
        for error in result.errors:
            typer.echo(f"Collection error: {error}", err=True)
        raise typer.Exit(code=1)

    typer.echo("LinuxTrace - Auditd Collection")
    typer.echo(f"Raw records: {result.records_read}")
    typer.echo(f"Grouped events: {result.groups_read}")
    typer.echo(f"Inserted events: {result.events_inserted}")
    typer.echo(f"Inserted evidence: {result.evidence_inserted}")


event_app = typer.Typer(help="Inspect individual forensic events.")
app.add_typer(event_app, name="event")


@event_app.command("evidence")
def event_evidence_command(
    event_id: str,
    db_path: Annotated[
        Path,
        typer.Option("--db", help="SQLite database path."),
    ] = Path("data/linuxtrace.db"),
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output evidence as JSON."),
    ] = False,
):
    """Display stored audit evidence linked to an event."""
    import json
    from dataclasses import asdict

    from linuxtrace.storage.audit_evidence import (
        AuditEvidenceError,
        get_audit_evidence,
    )

    try:
        records = get_audit_evidence(db_path, event_id)
    except AuditEvidenceError as exc:
        typer.echo(f"Evidence error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if not records:
        typer.echo(
            f"No audit evidence found for event: {event_id}",
            err=True,
        )
        raise typer.Exit(code=1)

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "event_id": event_id,
                    "evidence_count": len(records),
                    "all_hashes_valid": all(record.hash_valid for record in records),
                    "evidence": [asdict(record) for record in records],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return

    typer.echo("LinuxTrace - Audit Evidence")
    typer.echo(f"Event ID: {event_id}")
    typer.echo(f"Evidence records: {len(records)}")

    for number, record in enumerate(records, start=1):
        status = "VALID" if record.hash_valid else "MISMATCH"

        typer.echo("")
        typer.echo(f"[{number}] {record.record_type}")
        typer.echo(f"Audit serial: {record.audit_serial}")
        typer.echo(f"Source: {record.source_file}:{record.source_line}")
        typer.echo(f"SHA-256: {record.evidence_hash}")
        typer.echo(f"Hash verification: {status}")
        typer.echo(f"Raw: {record.raw_log}")

    if any(not record.hash_valid for record in records):
        typer.echo(
            "WARNING: Stored evidence hash mismatch detected.",
            err=True,
        )
        raise typer.Exit(code=2)


if __name__ == "__main__":
    app()


@app.command()
def timeline(
    user: str | None = typer.Option(None, "--user"),
    ip: str | None = typer.Option(None, "--ip"),
    category: str | None = typer.Option(None, "--category"),
    event_type: str | None = typer.Option(None, "--type"),
    severity: str | None = typer.Option(None, "--severity"),
    last: str | None = typer.Option(None, "--last"),
    start: str | None = typer.Option(None, "--from"),
    end: str | None = typer.Option(None, "--to"),
    group_by: str | None = typer.Option(None, "--group-by"),
    limit: int = typer.Option(100, "--limit", min=1, max=10000),
    json_output: bool = typer.Option(False, "--json", help="Output JSON instead of a Rich table."),
    no_color: bool = typer.Option(False, "--no-color"),
    db_path: str = typer.Option("data/linuxtrace.db", "--db"),
):
    """Display and filter forensic timeline events."""

    if not Path(db_path).is_file():
        console.print(f"[red]Database not found:[/red] {db_path}")
        raise typer.Exit(code=1)

    try:
        start_time, end_time = get_time_range(
            last=last,
            start=start,
            end=end,
        )

        database = Database(Path(db_path))
        query = EventQuery(database)

        if group_by is not None:
            groups = EventGroupQuery(database).group_counts(
                group_by=group_by,
                username=user,
                source_ip=ip,
                category=category,
                event_type=event_type,
                severity=severity,
                start=start_time,
                end=end_time,
            )
        else:
            events = query.search(
                username=user,
                source_ip=ip,
                category=category,
                event_type=event_type,
                severity=severity,
                start=start_time,
                end=end_time,
                limit=limit,
            )

    except ValueError as exc:
        console.print(f"[red]Invalid filter:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if json_output:
        if group_by is not None:
            payload = {
                "group_by": group_by,
                "timezone": "UTC",
                "total_events": sum(count for _, count in groups),
                "groups": [{"time_bucket": bucket, "count": count} for bucket, count in groups],
            }
        else:
            payload = {
                "total_events": len(events),
                "events": [event.model_dump(mode="json") for event in events],
            }

        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
    elif group_by is not None:
        display_grouped_counts(groups, group_by, no_color=no_color)
    else:
        display_timeline(events, no_color=no_color)


@event_app.command("show")
def event_show(
    event_id: str = typer.Argument(help="SHA-256 event identifier."),
    db_path: str = typer.Option("data/linuxtrace.db", "--db"),
    json_output: bool = typer.Option(False, "--json"),
    no_color: bool = typer.Option(False, "--no-color"),
    evidence: bool = typer.Option(
        False,
        "--evidence",
        help="Include related auditd evidence.",
    ),
):
    """Show details of one stored forensic event."""
    from dataclasses import asdict

    from linuxtrace.event_detail import display_event_detail, get_event_by_id
    from linuxtrace.storage.audit_evidence import (
        AuditEvidenceError,
        get_audit_evidence,
    )

    database_path = Path(db_path)

    if not database_path.is_file():
        console.print(f"[red]Database not found:[/red] {db_path}")
        raise typer.Exit(code=1)

    try:
        event = get_event_by_id(Database(database_path), event_id)
    except ValueError as exc:
        console.print(f"[red]Invalid Event ID:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if event is None:
        console.print("[red]Event not found.[/red]")
        raise typer.Exit(code=1)

    evidence_records = []

    if evidence and event.raw_event.source == "auditd":
        try:
            evidence_records = get_audit_evidence(
                database_path,
                event_id,
            )
        except AuditEvidenceError as exc:
            typer.echo(f"Evidence error: {exc}", err=True)
            raise typer.Exit(code=1) from exc

    hashes_valid = all(record.hash_valid for record in evidence_records)

    if json_output:
        payload = event.model_dump(mode="json")

        if evidence:
            payload["audit_evidence"] = {
                "count": len(evidence_records),
                "all_hashes_valid": hashes_valid,
                "records": [asdict(record) for record in evidence_records],
            }

        typer.echo(
            json.dumps(
                payload,
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        display_event_detail(event, no_color=no_color)

        if evidence:
            typer.echo("")
            typer.echo("LinuxTrace - Related Audit Evidence")
            typer.echo(f"Evidence records: {len(evidence_records)}")

            for number, record in enumerate(
                evidence_records,
                start=1,
            ):
                status = "VALID" if record.hash_valid else "MISMATCH"

                typer.echo("")
                typer.echo(f"[{number}] {record.record_type}")
                typer.echo(f"Audit serial: {record.audit_serial}")
                typer.echo(f"Source: {record.source_file}:{record.source_line}")
                typer.echo(f"SHA-256: {record.evidence_hash}")
                typer.echo(f"Hash verification: {status}")
                typer.echo(f"Raw: {record.raw_log}")

    if not hashes_valid:
        typer.echo(
            "WARNING: Stored evidence hash mismatch detected.",
            err=True,
        )
        raise typer.Exit(code=2)
