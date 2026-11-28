from dataclasses import dataclass, field
from decimal import Decimal

from linuxtrace.models.raw_event import RawEvent
from linuxtrace.parsers.audit import AuditRecord, parse_audit_record


@dataclass(frozen=True)
class AuditEvidence:
    """Preserve parsed record and original evidence metadata."""

    raw: RawEvent
    parsed: AuditRecord


@dataclass
class AuditEventGroup:
    """Records belonging to one Linux audit event."""

    node: str | None
    timestamp: Decimal
    serial: int
    records: list[AuditEvidence] = field(default_factory=list)

    @property
    def record_types(self) -> list[str]:
        return [evidence.parsed.record_type for evidence in self.records]

    def fields_for(self, record_type: str) -> list[dict[str, str]]:
        """Return fields for every matching record type."""

        return [
            evidence.parsed.fields
            for evidence in self.records
            if evidence.parsed.record_type == record_type
        ]


@dataclass
class AuditGroupingResult:
    groups: list[AuditEventGroup] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def group_audit_events(
    raw_events: list[RawEvent],
) -> AuditGroupingResult:
    """Group audit records while preserving every raw record."""

    groups: dict[
        tuple[str | None, Decimal, int],
        AuditEventGroup,
    ] = {}

    errors: list[str] = []

    for raw in raw_events:
        try:
            parsed = parse_audit_record(raw.raw_log)
        except ValueError as exc:
            errors.append(f"{raw.source_file}:{raw.source_line}: {exc}")
            continue

        if parsed is None:
            errors.append(f"{raw.source_file}:{raw.source_line}: Unrecognized audit record")
            continue

        key = (
            parsed.node,
            parsed.timestamp,
            parsed.serial,
        )

        if key not in groups:
            groups[key] = AuditEventGroup(
                node=parsed.node,
                timestamp=parsed.timestamp,
                serial=parsed.serial,
            )

        groups[key].records.append(
            AuditEvidence(
                raw=raw,
                parsed=parsed,
            )
        )

    return AuditGroupingResult(
        groups=list(groups.values()),
        errors=errors,
    )
