from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from linuxtrace.utils.discovery import (
    discover_logs,
    discover_rotated_logs,
)
from linuxtrace.utils.system import get_system_info

console = Console()

STATUS_COLORS = {
    "available": "green",
    "missing": "dim",
    "permission_denied": "yellow",
    "unsafe_path": "red",
    "error": "red",
}


def run_doctor() -> None:
    """Display system information and log availability."""

    system = get_system_info()
    active_logs = discover_logs()
    rotated_logs = discover_rotated_logs()

    console.print(
        Panel(
            "[bold cyan]LinuxTrace[/bold cyan]\nLinux Incident Timeline & Forensic Analysis Tool",
            border_style="cyan",
        )
    )

    system_table = Table(title="System Information")

    system_table.add_column("Property", style="cyan")
    system_table.add_column("Value")

    for key, value in system.items():
        system_table.add_row(
            key.replace("_", " ").title(),
            str(value),
        )

    console.print(system_table)

    logs = active_logs + rotated_logs

    log_table = Table(title="Log Source Discovery")

    log_table.add_column("Category", style="cyan")
    log_table.add_column("Source")
    log_table.add_column("Status")
    log_table.add_column("Rotated")
    log_table.add_column("Compressed")

    for log in logs:
        status = log["status"]
        color = STATUS_COLORS.get(status, "white")

        log_table.add_row(
            log["category"],
            log["path"],
            f"[{color}]{status}[/{color}]",
            "Yes" if log.get("rotated") else "No",
            "Yes" if log.get("compressed") else "No",
        )

    console.print(log_table)

    available = sum(log["status"] == "available" for log in logs)

    denied = sum(log["status"] == "permission_denied" for log in logs)

    missing = sum(log["status"] == "missing" for log in logs)

    other = len(logs) - available - denied - missing

    console.print(
        Panel(
            f"Total sources: {len(logs)}\n"
            f"[green]Available: {available}[/green]\n"
            f"[yellow]Permission denied: {denied}[/yellow]\n"
            f"[dim]Missing: {missing}[/dim]\n"
            f"Other issues: {other}\n"
            f"Rotated logs: {len(rotated_logs)}",
            title="Discovery Summary",
            border_style="cyan",
        )
    )
