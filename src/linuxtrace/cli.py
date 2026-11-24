import json
from pathlib import Path

import typer
from rich.console import Console

from linuxtrace import __version__
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


event_app = typer.Typer(help="Inspect individual forensic events.")
app.add_typer(event_app, name="event")


@event_app.command("show")
def event_show(
    event_id: str = typer.Argument(help="SHA-256 event identifier."),
    db_path: str = typer.Option("data/linuxtrace.db", "--db"),
    json_output: bool = typer.Option(False, "--json"),
    no_color: bool = typer.Option(False, "--no-color"),
):
    """Show details of one stored forensic event."""
    from linuxtrace.event_detail import display_event_detail, get_event_by_id

    if not Path(db_path).is_file():
        console.print(f"[red]Database not found:[/red] {db_path}")
        raise typer.Exit(code=1)

    try:
        event = get_event_by_id(Database(Path(db_path)), event_id)
    except ValueError as exc:
        console.print(f"[red]Invalid Event ID:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if event is None:
        console.print("[red]Event not found.[/red]")
        raise typer.Exit(code=1)

    if json_output:
        typer.echo(
            json.dumps(
                event.model_dump(mode="json"),
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        display_event_detail(event, no_color=no_color)
