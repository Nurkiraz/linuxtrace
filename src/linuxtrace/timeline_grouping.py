from collections import Counter
from datetime import UTC
from typing import Literal

from rich.console import Console
from rich.table import Table

from linuxtrace.models.normalized_event import NormalizedEvent

GroupBy = Literal["hour", "day"]


def group_events(
    events: list[NormalizedEvent],
    group_by: GroupBy,
) -> list[tuple[str, int]]:
    """Count events by UTC hour or day."""

    if group_by not in ("hour", "day"):
        raise ValueError("Grouping must be 'hour' or 'day'")

    counts: Counter[str] = Counter()

    for event in events:
        if event.timestamp is None:
            continue

        if event.timestamp.tzinfo is None:
            raise ValueError("Event timestamp must be timezone-aware")

        timestamp = event.timestamp.astimezone(UTC)

        if group_by == "hour":
            bucket = timestamp.strftime("%Y-%m-%d %H:00")
        else:
            bucket = timestamp.strftime("%Y-%m-%d")

        counts[bucket] += 1

    return sorted(counts.items())


def display_grouped_timeline(
    events: list[NormalizedEvent],
    group_by: GroupBy,
) -> None:
    """Display UTC event counts as a Rich table."""

    groups = group_events(events, group_by)

    table = Table(title=f"LinuxTrace - Timeline by {group_by} (UTC)")
    table.add_column("Time (UTC)", style="cyan")
    table.add_column("Event Count", justify="right")

    for bucket, count in groups:
        table.add_row(bucket, str(count))

    Console().print(table)
    Console().print(f"Total events: {sum(count for _, count in groups)}")


def display_grouped_counts(
    groups: list[tuple[str, int]],
    group_by: GroupBy,
    no_color: bool = False,
) -> None:
    """Display database-aggregated timeline counts."""

    if group_by not in ("hour", "day"):
        raise ValueError("Invalid grouping")

    table = Table(title=f"LinuxTrace - Timeline by {group_by} (UTC)")
    table.add_column("Time (UTC)", style="cyan")
    table.add_column("Event Count", justify="right")

    for bucket, count in groups:
        table.add_row(bucket, str(count))

    console = Console(no_color=no_color)
    console.print(table)
    console.print(f"Total events: {sum(count for _, count in groups)}")
