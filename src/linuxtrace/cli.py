import typer
from rich.console import Console

from linuxtrace import __version__
from linuxtrace.doctor import run_doctor

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
