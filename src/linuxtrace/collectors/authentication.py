import hashlib
from collections.abc import Iterator
from pathlib import Path

from linuxtrace.models.raw_event import RawEvent
from linuxtrace.utils.discovery import (
    discover_logs,
    discover_rotated_logs,
)
from linuxtrace.utils.log_reader import (
    LogReadError,
    read_log,
)


class AuthenticationCollector:
    """Collect raw authentication logs."""

    def __init__(self, root: Path = Path("/")):
        self.root = root.resolve()
        self.errors: list[str] = []

    def collect(self) -> Iterator[RawEvent]:
        """Yield authentication records."""

        self.errors.clear()

        sources = discover_logs(self.root) + discover_rotated_logs(self.root)

        for source in sources:
            if source["category"] != "authentication":
                continue

            if source["status"] != "available":
                self.errors.append(f"{source['path']}: {source['status']}")
                continue

            path = Path(source["path"])

            try:
                for line_number, line in read_log(path, root=self.root):
                    if not line.strip():
                        continue

                    evidence_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()

                    yield RawEvent(
                        source="authentication",
                        source_file=str(path),
                        source_line=line_number,
                        raw_log=line,
                        evidence_hash=evidence_hash,
                    )

            except LogReadError as exc:
                self.errors.append(str(exc))
