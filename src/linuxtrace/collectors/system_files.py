import hashlib
import re
import stat
from collections.abc import Iterator
from pathlib import Path

from linuxtrace.models.raw_event import RawEvent
from linuxtrace.utils.log_reader import LogReadError, read_log

SOURCE_PATTERNS = {
    "kernel": re.compile(r"^kern\.log(?:\.\d+)?(?:\.gz)?$"),
    "cron": re.compile(r"^cron(?:\.\d+)?(?:\.gz)?$"),
}


class SystemFileCollector:
    """Collect independent kernel or cron log files."""

    def __init__(self, root: Path, source: str):
        if source not in SOURCE_PATTERNS:
            raise ValueError(f"Unsupported source: {source}")

        self.root = Path(root).resolve()
        self.source = source
        self.errors: list[str] = []

    def collect(self) -> Iterator[RawEvent]:
        """Read matching files without modifying evidence."""

        self.errors.clear()
        log_dir = self.root / "var/log"

        if log_dir.is_symlink():
            self.errors.append(f"Symbolic log directory rejected: {log_dir}")
            return

        try:
            if not log_dir.is_dir():
                return

            paths = sorted(
                path
                for path in log_dir.iterdir()
                if SOURCE_PATTERNS[self.source].fullmatch(path.name)
            )
        except OSError as exc:
            self.errors.append(f"Log discovery failed: {exc}")
            return

        for path in paths:
            try:
                if path.is_symlink():
                    raise LogReadError(f"Symbolic link rejected: {path}")

                if not stat.S_ISREG(path.stat().st_mode):
                    raise LogReadError(f"Not a regular file: {path}")

                for line_number, line in read_log(
                    path,
                    root=self.root,
                ):
                    if not line.strip():
                        continue

                    yield RawEvent(
                        source=self.source,
                        source_file=str(path),
                        source_line=line_number,
                        raw_log=line,
                        evidence_hash=hashlib.sha256(line.encode("utf-8")).hexdigest(),
                    )

            except (LogReadError, OSError) as exc:
                self.errors.append(str(exc))
