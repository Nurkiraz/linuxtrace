import hashlib
import re
import stat
from collections.abc import Iterator
from pathlib import Path

from linuxtrace.models.raw_event import RawEvent
from linuxtrace.utils.log_reader import LogReadError, read_log

AUDIT_FILENAME = re.compile(r"^audit\.log(?:\.\d+)?(?:\.gz)?$")


class AuditCollector:
    """Collect Linux auditd records without modifying evidence."""

    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.errors: list[str] = []

    def collect(self) -> Iterator[RawEvent]:
        """Stream audit.log and supported rotated audit files."""

        self.errors.clear()
        audit_dir = self.root / "var/log/audit"

        if audit_dir.is_symlink():
            self.errors.append(f"Symbolic audit directory rejected: {audit_dir}")
            return

        try:
            if not audit_dir.is_dir():
                return

            paths = sorted(
                (path for path in audit_dir.iterdir() if AUDIT_FILENAME.fullmatch(path.name)),
                key=lambda path: path.name,
            )
        except OSError as exc:
            self.errors.append(f"Audit discovery failed: {exc}")
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
                        source="auditd",
                        source_file=str(path),
                        source_line=line_number,
                        raw_log=line,
                        evidence_hash=hashlib.sha256(line.encode("utf-8")).hexdigest(),
                    )

            except (LogReadError, OSError) as exc:
                self.errors.append(str(exc))
