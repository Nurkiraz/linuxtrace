import hashlib
import re
from collections.abc import Iterator
from pathlib import Path

from linuxtrace.models.raw_event import RawEvent
from linuxtrace.utils.log_reader import LogReadError, read_log

SYSLOG_FILENAME = re.compile(r"^(syslog|messages)(?:\.\d+)?(?:\.gz)?$")


class SyslogCollector:
    """Collect system logs from an offline evidence root."""

    def __init__(self, root: Path = Path("/")):
        self.root = Path(root).resolve()
        self.errors: list[str] = []

    def collect(self) -> Iterator[RawEvent]:
        """Yield raw records from traditional Linux system logs."""

        self.errors.clear()
        log_dir = self.root / "var/log"

        try:
            if not log_dir.is_dir():
                return

            paths = sorted(
                (
                    path
                    for path in log_dir.iterdir()
                    if SYSLOG_FILENAME.fullmatch(path.name) and path.is_file()
                ),
                key=lambda path: path.name,
            )
        except OSError as exc:
            self.errors.append(f"Unable to discover syslog files: {exc}")
            return

        for path in paths:
            try:
                for line_number, line in read_log(path, root=self.root):
                    if not line.strip():
                        continue

                    yield RawEvent(
                        source="syslog",
                        source_file=str(path),
                        source_line=line_number,
                        raw_log=line,
                        evidence_hash=hashlib.sha256(line.encode("utf-8")).hexdigest(),
                    )

            except LogReadError as exc:
                self.errors.append(str(exc))
