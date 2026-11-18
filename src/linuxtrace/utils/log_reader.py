import gzip
import stat
from collections.abc import Iterator
from pathlib import Path

MAX_LINE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024


class LogReadError(Exception):
    """Raised when a log source cannot be safely read."""


def read_log(
    path: Path,
    root: Path = Path("/"),
) -> Iterator[tuple[int, str]]:
    """Read plain or gzip log files line by line."""

    try:
        root = root.resolve()
        path = path.resolve(strict=True)

        if not path.is_relative_to(root):
            raise LogReadError(f"Path outside evidence root: {path}")

        if not stat.S_ISREG(path.stat().st_mode):
            raise LogReadError(f"Not a regular file: {path}")

        opener = gzip.open if path.suffix == ".gz" else open

        total_bytes = 0

        with opener(path, "rb") as file:
            line_number = 0

            while True:
                raw_line = file.readline(MAX_LINE_BYTES + 1)

                if not raw_line:
                    break

                line_number += 1
                total_bytes += len(raw_line)

                if len(raw_line) > MAX_LINE_BYTES:
                    raise LogReadError(f"Line size limit exceeded: {path}")

                if total_bytes > MAX_TOTAL_BYTES:
                    raise LogReadError(f"Read size limit exceeded: {path}")

                line = raw_line.decode(
                    "utf-8",
                    errors="replace",
                )

                yield line_number, line.rstrip("\r\n")

    except (OSError, EOFError, RuntimeError) as exc:
        raise LogReadError(f"Unable to read {path}: {exc}") from exc
