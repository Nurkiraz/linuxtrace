import re
from contextlib import closing

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from linuxtrace.models.normalized_event import NormalizedEvent
from linuxtrace.storage.database import Database


def get_event_by_id(
    database: Database,
    event_id: str,
) -> NormalizedEvent | None:
    """Retrieve an event by its SHA-256 identifier."""

    if re.fullmatch(r"[0-9a-fA-F]{64}", event_id) is None:
        raise ValueError("Event ID must be a 64-character SHA-256 hex string")

    with closing(database.connect()) as connection:
        row = connection.execute(
            "SELECT event_json FROM events WHERE event_id = ?",
            (event_id.lower(),),
        ).fetchone()

    if row is None:
        return None

    return NormalizedEvent.model_validate_json(row["event_json"])


def display_event_detail(
    event: NormalizedEvent,
    no_color: bool = False,
) -> None:
    """Display forensic details without interpreting raw log markup."""

    console = Console(no_color=no_color)
    raw = event.raw_event

    table = Table(
        title="LinuxTrace - Event Detail",
        show_header=False,
    )

    table.add_column("Field", style="cyan")
    table.add_column("Value", overflow="fold")

    fields = [
        ("Event ID", event.event_id),
        ("UTC Timestamp", event.timestamp),
        ("Event Type", event.event_type),
        ("Category", event.event_category),
        ("Severity", event.severity),
        ("Username", event.username),
        ("Source IP", event.source_ip),
        ("Hostname", event.hostname),
        ("Log Source", raw.source),
        ("Source File", raw.source_file),
        ("Source Line", raw.source_line),
        ("Evidence SHA-256", raw.evidence_hash),
    ]

    for label, value in fields:
        table.add_row(
            label,
            str(value) if value is not None else "-",
        )

    console.print(table)
    console.print(
        Panel(
            Text(raw.raw_log),
            title="Original Log Entry",
            border_style="cyan",
        )
    )
