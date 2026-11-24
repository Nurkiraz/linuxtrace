import hashlib

from linuxtrace.models.raw_event import RawEvent
from linuxtrace.normalizers.deduplication import (
    content_fingerprint,
    find_duplicate_candidates,
)
from linuxtrace.normalizers.event import normalize_event
from linuxtrace.parsers.authentication import parse_authentication


def make_event(
    message: str,
    source_file: str,
    line_number: int = 1,
):
    raw = RawEvent(
        source="authentication",
        source_file=source_file,
        source_line=line_number,
        raw_log=message,
        evidence_hash=hashlib.sha256(message.encode()).hexdigest(),
    )

    return normalize_event(
        parse_authentication(raw),
        year=2026,
        source_timezone="Europe/Istanbul",
    )


MESSAGE = (
    "Nov 18 10:00:01 lab-server sshd[1201]: "
    "Accepted password for analyst from "
    "192.0.2.10 port 51234 ssh2"
)


def test_identical_content_fingerprint():
    first = make_event(MESSAGE, "/var/log/auth.log")
    second = make_event(MESSAGE, "/var/log/auth.log.1")

    assert content_fingerprint(first) == content_fingerprint(second)


def test_different_content_fingerprint():
    first = make_event(MESSAGE, "/var/log/auth.log")
    second = make_event(
        MESSAGE.replace("192.0.2.10", "192.0.2.11"),
        "/var/log/auth.log.1",
    )

    assert content_fingerprint(first) != content_fingerprint(second)


def test_rotated_log_duplicate_candidate():
    first = make_event(MESSAGE, "/var/log/auth.log")
    second = make_event(MESSAGE, "/var/log/auth.log.1")

    candidates = find_duplicate_candidates([first, second])

    assert len(candidates) == 1
    assert candidates[0].confidence == "medium"


def test_same_event_id_not_reported():
    event = make_event(MESSAGE, "/var/log/auth.log")

    candidates = find_duplicate_candidates([event, event])

    assert candidates == []


def test_unrelated_events_not_reported():
    first = make_event(MESSAGE, "/var/log/auth.log")
    second = make_event(
        MESSAGE.replace("Accepted", "Failed"),
        "/var/log/auth.log.1",
    )

    assert find_duplicate_candidates([first, second]) == []


def test_empty_events():
    assert find_duplicate_candidates([]) == []


def test_original_events_unchanged():
    first = make_event(MESSAGE, "/var/log/auth.log")
    second = make_event(MESSAGE, "/var/log/auth.log.1")

    original = first.model_dump()

    find_duplicate_candidates([first, second])

    assert first.model_dump() == original
