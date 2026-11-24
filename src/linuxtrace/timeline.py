from rich.console import Console
from rich.table import Table

from linuxtrace.models.normalized_event import NormalizedEvent

console = Console()

SEVERITY_COLORS = {
    "info": "cyan",
    "low": "green",
    "medium": "yellow",
    "high": "red",
    "critical": "bold red",
}


def display_timeline(
    events: list[NormalizedEvent],
    no_color: bool = False,
) -> None:
    """Display forensic events in a chronological table."""

    console = Console(no_color=no_color)

    table = Table(
        title="LinuxTrace - Incident Timeline",
        show_lines=False,
        expand=True,
    )

    table.add_column("Timestamp", style="cyan", no_wrap=True)
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Event")
    table.add_column("User")
    table.add_column("Source IP")
    table.add_column("Source")

    for event in events:
        timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S") if event.timestamp else "Unknown"

        color = SEVERITY_COLORS.get(event.severity, "white")

        table.add_row(
            timestamp,
            f"[{color}]{event.severity.upper()}[/{color}]",
            event.event_category,
            event.event_type,
            event.username or "-",
            event.source_ip or "-",
            event.raw_event.source,
        )

    console.print(table)
    console.print(f"\n[bold]Total events:[/bold] {len(events)}")
