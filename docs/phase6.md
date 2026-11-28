# LinuxTrace v0.6.0 — Detection Engine

LinuxTrace is a Python-based command-line tool for investigating
historical Linux security events.

It supports forensic event collection, SQLite storage, timeline
inspection, detection rules, and evidence integrity checks.

## Installation

Requirements:
- Linux
- Python 3.11 or newer

From the repository:

    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install -e .

For development and testing:

    python -m pip install -e ".[dev]"

## Getting Started

Check the installation:

    linuxtrace version
    linuxtrace doctor
    linuxtrace --help

## Supported Detection Rules

| Rule | Description | Severity |
| --- | --- | --- |
| LT-SSH-001 | SSH brute-force attempts | High |
| LT-SSH-002 | SSH login success after repeated failures | Critical |
| LT-SSH-003 | SSH password spraying | High |
| LT-AUDIT-001 | Suspicious remote script execution | High |

The detection rules identify suspicious patterns. A finding does not
automatically mean that a system has been compromised.

## Collecting Audit Evidence

    linuxtrace collect audit --root /path/to/evidence --db data/linuxtrace.db

## Investigating Events

    linuxtrace timeline --db data/linuxtrace.db
    linuxtrace timeline --type audit_syscall --db data/linuxtrace.db

## Running Detection

Display configured rules:

    linuxtrace detect rules --config rules/default.yaml

Analyze existing events:

    linuxtrace detect run --db data/linuxtrace.db --config rules/default.yaml

Generate machine-readable results:

    linuxtrace detect run --db data/linuxtrace.db --json

Persist findings:

    linuxtrace detect run --db data/linuxtrace.db --save

## Inspecting Findings

    linuxtrace findings list --db data/linuxtrace.db

    linuxtrace findings show FINDING_ID --db data/linuxtrace.db --events

## Detection Configuration

Rules are configured through rules/default.yaml.

SSH rules support:
- enabled
- threshold
- window_minutes

The audit command detection rule supports:
- enabled

## Evidence Integrity

LinuxTrace preserves evidence references and supports SHA-256
consistency checks.

Hash verification does not independently prove the authenticity
of the original source or provide a complete chain of custody.

## Known Limitations

- Detection rules cover selected SSH and auditd behaviors.
- Not all Linux distributions or log formats are supported.
- SSH grouping uses temporary SQLite storage.
- Dense event groups and large finding sets can increase RAM usage.
- Some suspicious shell command patterns may not be detected.
- False positives are possible.
- This is an investigation aid, not a replacement for an EDR or SIEM.
- Detection does not modify or block suspicious activity.

## Testing

    ruff check src/ tests/
    ruff format --check src/ tests/
    pytest -q

## License

MIT.
