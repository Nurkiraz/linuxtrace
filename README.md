# LinuxTrace

Linux Incident Timeline & Forensic Analysis Tool.

## Project Overview

LinuxTrace is an open-source Linux forensic analysis tool designed
to collect, normalize and correlate system and security events
from multiple Linux log sources.

The project aims to help SOC analysts, incident responders,
system administrators and security researchers investigate
historical Linux activity.

## Current Development Status

Version: 0.2.0

Phase 2 - Authentication and Journal Collectors.

112 automated tests passed.

## Implemented Features

- Linux distribution detection
- System information discovery
- Log source discovery
- Permission checks
- Rotated log discovery
- Compressed log discovery
- Evidence root boundary checks in log discovery
- Rich terminal interface
- Automated unit tests
- Streaming log collection
- Gzip log reading
- Authentication log collection
- SSH authentication analysis
- PAM session analysis
- Sudo authorization analysis
- Systemd journal collection
- Journal metadata extraction
- Record-level SHA-256 hashing
- Authentication event classification
- Integration test suite

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
linuxtrace --help
linuxtrace version
linuxtrace doctor
```

## Testing

```bash
pytest -v
ruff check src/ tests/
ruff format --check src/ tests/
```

## Development Environment

- Kali Linux Rolling 2025.4
- Python 3.13.9
- systemd 259

## Initial Test Results

- Total tests: 11
- Passed: 11
- Failed: 0
- Execution time: 0.31 seconds

## Forensic Considerations

LinuxTrace is designed to operate without modifying source logs.

Current discovery checks do not guarantee that every discovered
log source can be successfully collected.

## Roadmap

- Authentication log collection
- Systemd journal collection
- Event normalization
- SQLite event storage
- Incident timeline
- Auditd analysis
- Detection engine
- Correlation engine
- HTML reporting

## License

MIT License.

## Phase 5 Documentation

Learn about Syslog, Kernel, Cron, and Auditd collection:

- [System Log Collection and Auditd Analysis](docs/phase5.md)
