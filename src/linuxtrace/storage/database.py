import sqlite3
from pathlib import Path

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT,
    timestamp_original TEXT,
    timezone TEXT,
    timestamp_confidence TEXT NOT NULL,
    hostname TEXT,
    source TEXT NOT NULL,
    source_file TEXT NOT NULL,
    source_line INTEGER NOT NULL,
    event_category TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    username TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    process_name TEXT,
    process_id INTEGER,
    command TEXT,
    outcome TEXT,
    description TEXT NOT NULL,
    evidence_hash TEXT NOT NULL,
    raw_log TEXT NOT NULL,
    event_json TEXT NOT NULL,
    collected_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp
    ON events(timestamp);

CREATE INDEX IF NOT EXISTS idx_events_username
    ON events(username);

CREATE INDEX IF NOT EXISTS idx_events_source_ip
    ON events(source_ip);

CREATE INDEX IF NOT EXISTS idx_events_type
    ON events(event_type);

CREATE INDEX IF NOT EXISTS idx_events_category
    ON events(event_category);

CREATE TABLE IF NOT EXISTS collection_runs (
    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL,
    records_collected INTEGER NOT NULL DEFAULT 0,
    records_inserted INTEGER NOT NULL DEFAULT 0,
    errors_json TEXT
);
"""


class Database:
    """Manage the local LinuxTrace SQLite database."""

    def __init__(self, path: Path):
        self.path = Path(path).expanduser()

    def connect(self) -> sqlite3.Connection:
        """Open a SQLite database connection."""

        connection = sqlite3.connect(self.path)

        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")

        return connection

    def initialize(self) -> None:
        """Create database tables and indexes."""

        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
            mode=0o700,
        )

        with self.connect() as connection:
            connection.executescript(SCHEMA)

            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
