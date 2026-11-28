# LinuxTrace - Phase 5: System Log Collection

## Overview

Phase 5 introduces Syslog, Kernel, Cron, and Auditd collection,
event correlation, and forensic evidence preservation.

## Supported Sources

| Source | Supported Files | Features |
| --- | --- | --- |
| Syslog | syslog, messages | System events, incremental collection |
| Kernel | kern.log | Kernel message analysis |
| Cron | cron | Scheduled task analysis |
| Auditd | audit.log | Event correlation, evidence verification |

Supported rotated and gzip-compressed log files are also processed.

## Collection Commands

### Syslog

    linuxtrace collect syslog --root /path/to/evidence --year 2026 --timezone UTC

### Incremental Syslog

    linuxtrace collect syslog --root /path/to/evidence --year 2026 --timezone UTC --incremental

### Kernel

    linuxtrace collect kernel --root /path/to/evidence --year 2026 --timezone UTC

### Cron

    linuxtrace collect cron --root /path/to/evidence --year 2026 --timezone UTC

### Auditd

    linuxtrace collect audit --root /path/to/evidence

## Timeline Investigation

    linuxtrace timeline --group-by day
    linuxtrace timeline --type audit_syscall
    linuxtrace timeline --type cron_execution

## Audit Evidence

    linuxtrace event show EVENT_ID --evidence
    linuxtrace event show EVENT_ID --evidence --json
    linuxtrace event evidence EVENT_ID

Audit records are correlated using their node, timestamp, and serial
number. Original evidence records are preserved separately in SQLite.

## Evidence Integrity

- SHA-256 hashes are stored with raw evidence.
- Source file paths and line numbers are preserved.
- Supported processing failures trigger SQLite transaction rollback.
- Source changes are checked during collection.
- Auditd timestamps are normalized to UTC.

Hash verification checks consistency between stored raw data and
stored hashes. It does not establish a complete chain of custody.

## Performance

Auditd collection uses disk-backed SQLite grouping to reduce memory
consumption. Very large individual event groups can still require
significant RAM and temporary disk space.

## Known Limitations

- Not all Linux log formats are supported.
- Incremental Syslog collection operates at file level.
- File rotation can result in separate records for identical content.
- Source checks do not provide immutable forensic snapshots.
- Previously stored events are not automatically migrated.

## Development

    ruff format --check src/ tests/
    ruff check src/ tests/
    pytest -q

## Repository

https://github.com/Nurkiraz/linuxtrace
