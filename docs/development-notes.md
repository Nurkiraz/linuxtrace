# LinuxTrace Development Notes

## Phase 1 - Project Setup and Architecture

Date: 2026-11-18

### Development Environment

- OS: Kali GNU/Linux Rolling 2025.4
- Kernel: 6.16.8+kali-amd64
- Python: 3.13.9
- Architecture: x86_64
- systemd: 259

### Implemented Components

- Python package architecture
- Typer CLI
- Rich terminal output
- Linux distribution detection
- System information module
- Log source discovery
- Rotated and compressed log discovery
- Permission status reporting
- Symlink boundary checks in discovery
- Pytest test suite

### Real System Findings

The doctor command identified 22 log sources.

- Available: 8
- Permission denied: 6
- Missing: 8
- Rotated logs: 6
- Other issues: 0

Traditional authentication log files were not present.
Systemd journal directories were detected.

This demonstrates the importance of dynamic log discovery
instead of assuming that all Linux distributions use
the same logging architecture.

### Test Results

11 automated tests passed in 0.31 seconds.

Ruff lint checks passed.

### Current Limitations

- Log contents are not collected yet.
- Journal directory access does not guarantee journal entry access.
- Gzip content parsing is not implemented.
- Offline CLI analysis is not implemented.
- Offline os-release symlink validation is not implemented.
- Discovery checks are not a complete forensic security boundary.
- Detection and correlation engines are not implemented.

### Next Phase

Authentication and systemd journal collectors.

## Phase 2 - Authentication and Journal Collectors

Date: 2026-11-18

### Implemented Components

- Streaming log reader
- Plain text and gzip log support
- Log line and output size limits
- Evidence root boundary validation
- RawEvent and ParsedEvent models
- Authentication Collector
- Traditional syslog header parser
- SSH authentication parser
- PAM authentication and session parser
- Sudo authorization parser
- Systemd Journal Collector
- Journal metadata enrichment
- Authentication parser dispatcher
- SHA-256 record hashing
- Unclassified authentication event preservation

### Real System Findings

LinuxTrace successfully collected real journal records
from a Kali Linux system.

The journal collector retrieved 100 records without
reported collector errors.

Normal user privileges limited access to system-wide
journal records.

### Technical Decisions

- Generator-based log reading reduces memory consumption.
- Journal collection uses structured JSON output.
- Subprocess execution does not use a shell.
- Original log messages are preserved.
- Sudo authorization is distinguished from command execution.
- Unsupported authentication messages are preserved.
- Missing timestamps are not fabricated.

### Test Results

Total automated tests: 112

- Phase 1: 11
- Log Reader: 12
- SSH Parser: 14
- PAM Parser: 15
- Sudo Parser: 15
- Journal Parser: 12
- Journal Collector: 15
- Authentication Collector: 13
- Integration: 5

All 112 tests passed.

### Current Limitations

- UTC timestamp normalization is not implemented.
- SQLite storage is not implemented.
- Duplicate detection is not implemented.
- File-level evidence hashing is not implemented.
- Record hashing differs between text and journal sources.
- Journal collection is limited by user permissions.
- Journal subprocess timeout handling requires improvement.
- Offline journal collection is not implemented.
- Some syslog and authentication formats remain unsupported.
- Full forensic acquisition integrity is not guaranteed.

### Next Phase

Event normalization and SQLite event storage.
