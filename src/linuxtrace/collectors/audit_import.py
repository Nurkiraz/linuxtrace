import hashlib
import shlex
import sqlite3
from contextlib import closing
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path

from linuxtrace.collectors.syslog_import import (
    INSERT_EVENT_SQL,
)
from linuxtrace.models.parsed_event import ParsedEvent
from linuxtrace.normalizers.event import normalize_event
from linuxtrace.parsers.audit_groups import (
    AuditEventGroup,
)
from linuxtrace.storage.database import Database
from linuxtrace.storage.event_repository import EventRepository

AUDIT_EVIDENCE_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_event_evidence (
    event_id TEXT NOT NULL,
    source_file TEXT NOT NULL,
    source_line INTEGER NOT NULL,
    evidence_hash TEXT NOT NULL,
    record_type TEXT NOT NULL,
    audit_serial INTEGER NOT NULL,
    raw_log TEXT NOT NULL,
    PRIMARY KEY (
        event_id,
        source_file,
        source_line,
        evidence_hash
    ),
    FOREIGN KEY (event_id) REFERENCES events(event_id)
);

CREATE INDEX IF NOT EXISTS idx_audit_evidence_event
ON audit_event_evidence(event_id);

CREATE INDEX IF NOT EXISTS idx_audit_evidence_serial
ON audit_event_evidence(audit_serial);
"""

INSERT_AUDIT_EVIDENCE = """
INSERT OR IGNORE INTO audit_event_evidence (
    event_id,
    source_file,
    source_line,
    evidence_hash,
    record_type,
    audit_serial,
    raw_log
)
VALUES (?, ?, ?, ?, ?, ?, ?)
"""


@dataclass
class AuditImportResult:
    records_read: int = 0
    groups_read: int = 0
    events_inserted: int = 0
    evidence_inserted: int = 0
    errors: list[str] = field(default_factory=list)


class AuditCollectionFailure(Exception):
    """Audit collection could not be committed safely."""


def optional_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def build_audit_event(group: AuditEventGroup):
    """Normalize one audit group into one timeline event."""

    syscall = group.fields_for("SYSCALL")
    execve = group.fields_for("EXECVE")
    login = group.fields_for("USER_LOGIN")
    cwd = group.fields_for("CWD")
    paths = group.fields_for("PATH")

    syscall_fields = syscall[0] if syscall else {}
    execve_fields = execve[0] if execve else {}
    login_fields = login[0] if login else {}

    primary = next(
        (item for item in group.records if item.parsed.record_type == "SYSCALL"),
        group.records[0],
    )

    command = None
    argc = optional_int(execve_fields.get("argc"))

    if argc is not None and 0 <= argc <= 1024:
        arguments = [execve_fields.get(f"a{index}") for index in range(argc)]
        if all(arg is not None for arg in arguments):
            command = shlex.join(arguments)

    process_name = syscall_fields.get("comm") or syscall_fields.get("exe")

    pid = optional_int(syscall_fields.get("pid") or login_fields.get("pid"))

    uid = optional_int(syscall_fields.get("uid") or login_fields.get("uid"))

    outcome = login_fields.get("res") or syscall_fields.get("success")

    if outcome == "yes":
        outcome = "success"
    elif outcome == "no":
        outcome = "failure"

    file_paths = [entry["name"] for entry in paths if "name" in entry]

    if syscall:
        event_type = "audit_syscall"
        event_category = "process"
    elif login:
        event_type = "audit_user_login"
        event_category = "authentication"
    else:
        event_type = "audit_event"
        event_category = "system"

    description_parts = [
        f"Audit event serial={group.serial}",
        f"types={','.join(group.record_types)}",
    ]

    if command:
        description_parts.append(f"command={command}")

    if file_paths:
        description_parts.append(f"paths={','.join(file_paths)}")

    timestamp_us = int(group.timestamp * Decimal(1_000_000))

    parsed = ParsedEvent(
        raw_event=primary.raw,
        timestamp_original=str(group.timestamp),
        timestamp_unix_us=timestamp_us,
        hostname=group.node,
        event_category=event_category,
        event_type=event_type,
        severity="info",
        process_name=process_name,
        process_id=pid,
        user_id=uid,
        command=command,
        outcome=outcome,
        working_directory=(cwd[0].get("cwd") if cwd else None),
        description="; ".join(description_parts),
    )

    # Audit timestamps are Unix epoch values with microsecond precision.
    from datetime import UTC, datetime, timedelta

    normalized = normalize_event(
        parsed,
        source_timezone="UTC",
    )

    timestamp = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=timestamp_us)

    confidence_type = type(normalized.timestamp_confidence)
    high_confidence = next(
        (member for member in confidence_type if str(member.value).lower() in ("high", "exact")),
        None,
    )

    if high_confidence is None:
        raise ValueError("No high-confidence timestamp level exists")

    warnings = [
        warning
        for warning in normalized.normalization_warnings
        if warning != "Syslog requires explicit year and timezone"
    ]

    return normalized.model_copy(
        update={
            "timestamp": timestamp,
            "timezone": "UTC",
            "timestamp_confidence": high_confidence,
            "timestamp_method": "audit_unix_epoch",
            "normalization_warnings": warnings,
        }
    )


def spool_fingerprint(spool_path: Path) -> bytes:
    """Hash stored source records in their collection order."""
    digest = hashlib.sha256()

    with closing(sqlite3.connect(spool_path)) as connection:
        rows = connection.execute(
            """
            SELECT raw_json
            FROM audit_records
            ORDER BY id
            """
        )

        for (raw_json,) in rows:
            payload = raw_json.encode("utf-8")
            digest.update(len(payload).to_bytes(8, "big"))
            digest.update(payload)

    return digest.digest()


def import_audit(
    root: Path,
    db_path: Path,
) -> AuditImportResult:
    """Import audit groups using disk-backed, atomic processing."""

    from tempfile import TemporaryDirectory

    from linuxtrace.collectors.audit_spool import (
        iter_spooled_groups,
        spool_audit_records,
    )

    result = AuditImportResult()
    root = Path(root).resolve()

    try:
        with TemporaryDirectory(prefix="linuxtrace-audit-") as temp_dir:
            workdir = Path(temp_dir)
            before_path = workdir / "before.db"
            after_path = workdir / "after.db"

            # First pass: collect, validate, and fingerprint.
            before = spool_audit_records(root, before_path)

            result.records_read = before.records_read
            result.groups_read = before.groups_read

            if before.errors:
                result.errors.extend(before.errors)
                return result

            before_hash = spool_fingerprint(before_path)

            # Validate every group before writing to main storage.
            for group in iter_spooled_groups(before_path):
                build_audit_event(group)

            database = Database(Path(db_path))
            database.initialize()
            repository = EventRepository(database)

            with closing(database.connect()) as connection:
                # DDL is executed before the explicit transaction.
                connection.executescript(AUDIT_EVIDENCE_SCHEMA)

                with connection:
                    connection.execute("BEGIN IMMEDIATE")

                    # Second pass: detect changes in source evidence.
                    after = spool_audit_records(root, after_path)

                    if after.errors:
                        raise AuditCollectionFailure("; ".join(after.errors))

                    if (
                        before.records_read != after.records_read
                        or before.groups_read != after.groups_read
                        or before_hash != spool_fingerprint(after_path)
                    ):
                        raise AuditCollectionFailure("Audit evidence changed during collection")

                    # Insert complete groups one at a time.
                    for group in iter_spooled_groups(after_path):
                        event = build_audit_event(group)

                        cursor = connection.execute(
                            INSERT_EVENT_SQL,
                            repository._event_values(event),
                        )
                        result.events_inserted += cursor.rowcount

                        for item in group.records:
                            raw = item.raw

                            cursor = connection.execute(
                                INSERT_AUDIT_EVIDENCE,
                                (
                                    event.event_id,
                                    raw.source_file,
                                    raw.source_line,
                                    raw.evidence_hash,
                                    item.parsed.record_type,
                                    group.serial,
                                    raw.raw_log,
                                ),
                            )

                            result.evidence_inserted += cursor.rowcount

        return result

    except (
        AuditCollectionFailure,
        sqlite3.Error,
        OSError,
        ValueError,
        TypeError,
        OverflowError,
    ) as exc:
        result.events_inserted = 0
        result.evidence_inserted = 0
        result.errors.append(str(exc))
        return result
