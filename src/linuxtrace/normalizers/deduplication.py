import hashlib
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from linuxtrace.models.normalized_event import NormalizedEvent


@dataclass(frozen=True)
class DuplicateCandidate:
    """Represent a possible duplicate event pair."""

    first_event_id: str
    second_event_id: str
    reason: str
    confidence: str


def content_fingerprint(event: NormalizedEvent) -> str:
    """Calculate a fingerprint of the raw log text."""

    content = event.raw_event.raw_log.encode("utf-8")

    return hashlib.sha256(content).hexdigest()


def find_duplicate_candidates(
    events: Iterable[NormalizedEvent],
) -> list[DuplicateCandidate]:
    """Find possible duplicates without deleting events."""

    groups = defaultdict(list)
    candidates = []

    for event in events:
        fingerprint = content_fingerprint(event)

        key = (
            event.raw_event.source,
            event.hostname,
            fingerprint,
        )

        for previous in groups[key]:
            if previous.event_id == event.event_id:
                continue

            candidates.append(
                DuplicateCandidate(
                    first_event_id=previous.event_id,
                    second_event_id=event.event_id,
                    reason=("Identical raw log content, source type and hostname"),
                    confidence="medium",
                )
            )

        groups[key].append(event)

    return candidates
