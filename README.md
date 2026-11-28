# LinuxTrace

**Linux Incident Timeline & Forensic Analysis Tool**

LinuxTrace is an open-source Python CLI application for investigating
historical Linux system and security events.

It helps security analysts and system administrators collect supported
log records, examine activity timelines, detect suspicious SSH and auditd
behavior, and inspect stored forensic evidence.

## Features

- Linux environment and log discovery
- SSH, PAM and sudo authentication analysis
- Systemd journal support
- Syslog, kernel and cron collection
- Auditd record grouping and analysis
- UTC event normalization
- SQLite event storage
- Forensic timeline and event filtering
- Four security detection rules
- YAML detection configuration
- Security finding inspection and persistence
- SHA-256 evidence consistency checks
- JSON output for supported commands

## Installation

Requirements: Linux and Python 3.11+

Clone the repository:

    git clone https://github.com/Nurkiraz/linuxtrace.git
    cd linuxtrace

Create a virtual environment and install:

    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install -e .

Check the installation:

    linuxtrace version
    linuxtrace doctor
    linuxtrace --help

## Quick Start

Collect auditd evidence:

    linuxtrace collect audit --root /path/to/evidence --db data/linuxtrace.db

Inspect the timeline:

    linuxtrace timeline --db data/linuxtrace.db

List available detection rules:

    linuxtrace detect rules --config rules/default.yaml

Run detection:

    linuxtrace detect run --db data/linuxtrace.db --config rules/default.yaml

Save security findings:

    linuxtrace detect run --db data/linuxtrace.db --save

List findings:

    linuxtrace findings list --db data/linuxtrace.db

Inspect a finding:

    linuxtrace findings show FINDING_ID --db data/linuxtrace.db --events

Run `linuxtrace --help` to explore available commands.

## Detection Rules

| Rule ID | Detection | Severity |
| --- | --- | --- |
| LT-SSH-001 | SSH Brute-Force | High |
| LT-SSH-002 | SSH Success After Failures | Critical |
| LT-SSH-003 | SSH Password Spraying | High |
| LT-AUDIT-001 | Suspicious Remote Script Execution | High |

Detection thresholds and enabled rules are configured in
`rules/default.yaml`.

## Documentation

- [System Log Collection and Auditd](docs/phase5.md)
- [Detection Engine and Usage Guide](docs/phase6.md)

## Development and Testing

Install development dependencies:

    python -m pip install -e ".[dev]"

Run checks:

    ruff check src/ tests/
    ruff format --check src/ tests/
    pytest -q

## Forensic Limitations

LinuxTrace is intended to assist security investigations.
Findings indicate suspicious behavior and require analyst review.

Evidence hash verification checks stored data consistency; it does
not establish a complete forensic chain of custody.

The project does not provide real-time attack blocking, EDR
protection or comprehensive SIEM functionality.

## License

MIT License.
