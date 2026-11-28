import re
import shlex
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

AUDIT_HEADER = re.compile(
    r"^(?:node=(?P<node>\S+)\s+)?"
    r"type=(?P<record_type>[A-Z0-9_]+)\s+"
    r"msg=audit\("
    r"(?P<timestamp>\d+(?:\.\d+)?):"
    r"(?P<serial>\d+)\):"
    r"\s*(?P<body>.*)$"
)


@dataclass(frozen=True)
class AuditRecord:
    """A single parsed Linux audit record."""

    record_type: str
    timestamp: Decimal
    serial: int
    node: str | None
    fields: dict[str, str]
    raw_log: str


def parse_audit_record(line: str) -> AuditRecord | None:
    """Parse one audit record without modifying its raw content."""

    match = AUDIT_HEADER.fullmatch(line.strip())

    if match is None:
        return None

    try:
        timestamp = Decimal(match.group("timestamp"))
        serial = int(match.group("serial"))

        tokens = shlex.split(
            match.group("body"),
            posix=True,
        )
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"Malformed audit record: {exc}") from exc

    fields = {}

    for token in tokens:
        if "=" not in token:
            continue

        key, value = token.split("=", 1)
        fields[key] = value

    return AuditRecord(
        record_type=match.group("record_type"),
        timestamp=timestamp,
        serial=serial,
        node=match.group("node"),
        fields=fields,
        raw_log=line,
    )
