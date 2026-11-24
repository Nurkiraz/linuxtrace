import hashlib
import json

from linuxtrace.models.parsed_event import ParsedEvent


def generate_event_id(event: ParsedEvent) -> str:
    """Generate a deterministic ID for a source event."""

    raw = event.raw_event

    identity = {
        "source": raw.source,
        "source_file": raw.source_file,
        "source_line": raw.source_line,
        "evidence_hash": raw.evidence_hash,
        "journal_cursor": raw.metadata.get("__CURSOR"),
    }

    serialized = json.dumps(
        identity,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )

    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
