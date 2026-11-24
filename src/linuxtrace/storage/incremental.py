import hashlib
import stat
from datetime import UTC, datetime
from pathlib import Path

from linuxtrace.storage.database import Database

CHUNK_SIZE = 1024 * 1024

TRACKING_SCHEMA = """
CREATE TABLE IF NOT EXISTS collected_files (
    source_path TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    collected_at TEXT NOT NULL
);
"""


class IncrementalTracker:
    """Track previously processed log files."""

    def __init__(self, database: Database):
        self.database = database

    def initialize(self) -> None:
        """Create the collection tracking table."""

        with self.database.connect() as connection:
            connection.execute(TRACKING_SCHEMA)

    @staticmethod
    def calculate_hash(path: Path) -> str:
        """Calculate a file hash using streaming reads."""

        path = Path(path)

        if path.is_symlink():
            raise ValueError("Symbolic links are not supported")

        if not stat.S_ISREG(path.stat().st_mode):
            raise ValueError("Source must be a regular file")

        digest = hashlib.sha256()

        with path.open("rb") as file:
            while chunk := file.read(CHUNK_SIZE):
                digest.update(chunk)

        return digest.hexdigest()

    def needs_collection(self, path: Path) -> bool:
        """Check whether a file is new or has changed."""

        path = Path(path)
        if path.is_symlink():
            raise ValueError("Symbolic links are not supported")
        path = path.resolve(strict=True)
        current_hash = self.calculate_hash(path)

        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT sha256
                FROM collected_files
                WHERE source_path = ?
                """,
                (str(path),),
            ).fetchone()

        return row is None or row["sha256"] != current_hash

    def mark_collected(self, path: Path) -> None:
        """Mark a successfully processed file."""

        path = Path(path)
        if path.is_symlink():
            raise ValueError("Symbolic links are not supported")
        path = path.resolve(strict=True)
        current_hash = self.calculate_hash(path)
        file_size = path.stat().st_size

        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO collected_files (
                    source_path,
                    sha256,
                    file_size,
                    collected_at
                )
                VALUES (?, ?, ?, ?)
                ON CONFLICT(source_path)
                DO UPDATE SET
                    sha256 = excluded.sha256,
                    file_size = excluded.file_size,
                    collected_at = excluded.collected_at
                """,
                (
                    str(path),
                    current_hash,
                    file_size,
                    datetime.now(UTC).isoformat(),
                ),
            )

    def count_tracked_files(self) -> int:
        """Return the number of tracked files."""

        with self.database.connect() as connection:
            row = connection.execute("SELECT COUNT(*) FROM collected_files").fetchone()

        return row[0]
