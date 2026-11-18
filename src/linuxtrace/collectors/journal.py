import hashlib
import json
import shutil
import subprocess
from collections.abc import Iterator

from linuxtrace.models.raw_event import RawEvent

MAX_JOURNAL_RECORDS = 10000
MAX_OUTPUT_BYTES = 32 * 1024 * 1024


class JournalCollector:
    """Collect structured systemd journal records."""

    def __init__(self):
        self.errors: list[str] = []

    def collect(
        self,
        limit: int = 1000,
        since: str | None = None,
        until: str | None = None,
        identifier: str | None = None,
    ) -> Iterator[RawEvent]:
        """Collect journal entries as raw events."""

        self.errors.clear()

        executable = shutil.which("journalctl")

        if executable is None:
            self.errors.append("journalctl is not available")
            return

        if not 1 <= limit <= MAX_JOURNAL_RECORDS:
            self.errors.append("Invalid journal record limit")
            return

        command = [
            executable,
            "--no-pager",
            "--output=json",
            f"--lines={limit}",
        ]

        if since:
            command.extend(["--since", since])

        if until:
            command.extend(["--until", until])

        if identifier:
            command.extend(["--identifier", identifier])

        try:
            with subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=None,
                shell=False,
            ) as process:
                if process.stdout is None:
                    self.errors.append("Journal output is unavailable")
                    return

                total_bytes = 0
                line_number = 0

                try:
                    while True:
                        line = process.stdout.readline(1024 * 1024 + 1)

                        if not line:
                            break

                        total_bytes += len(line)
                        line_number += 1

                        if len(line) > 1024 * 1024:
                            self.errors.append("Journal record size limit exceeded")
                            break

                        if total_bytes > MAX_OUTPUT_BYTES:
                            self.errors.append("Journal output limit exceeded")
                            break

                        try:
                            data = json.loads(line)

                            if not isinstance(data, dict):
                                raise ValueError("Expected JSON object")

                        except (ValueError, UnicodeError):
                            self.errors.append(f"Invalid JSON at line {line_number}")
                            continue

                        raw_log = line.decode(
                            "utf-8",
                            errors="replace",
                        ).rstrip("\r\n")

                        evidence_hash = hashlib.sha256(line).hexdigest()

                        yield RawEvent(
                            source="journal",
                            source_file="systemd-journal",
                            source_line=line_number,
                            raw_log=raw_log,
                            evidence_hash=evidence_hash,
                            metadata=data,
                        )

                finally:
                    if process.poll() is None:
                        process.stdout.close()

                        try:
                            process.wait(timeout=5)

                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()

                if process.returncode != 0:
                    self.errors.append(f"journalctl exited with code {process.returncode}")

        except OSError as exc:
            self.errors.append(str(exc))
