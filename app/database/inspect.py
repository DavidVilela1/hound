"""Side-effect-free inspection of SQLite database files (used by doctor, backup and restore)."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from urllib.parse import quote

from sqlalchemy.engine import make_url

from app.core.config import Settings
from app.database.migrations import baseline_fingerprint, latest_version, schema_fingerprint


def sqlite_path(settings: Settings) -> Path | None:
    """The configured SQLite file, or ``None`` for in-memory/non-SQLite databases."""
    url = make_url(settings.resolved_database_url)
    if url.get_backend_name() != "sqlite" or not url.database or url.database == ":memory:":
        return None
    return Path(url.database)


def open_read_only(path: Path) -> sqlite3.Connection:
    """Open ``path`` without creating or changing any file.

    Without a WAL file the database is fully checkpointed: ``immutable`` then reads it without
    creating ``-wal``/``-shm`` files. With a WAL file present (server running or unclean stop),
    plain read-only mode is needed to see the latest committed state.
    """
    wal_present = Path(f"{path}-wal").exists()
    options = "mode=ro" if wal_present else "mode=ro&immutable=1"
    # Canonical SQLite URI: file:///home/u/hound.db (POSIX), file:///C:/Users/u/hound.db (Windows).
    location = quote(path.as_posix(), safe="/:").lstrip("/")
    return sqlite3.connect(f"file:///{location}?{options}", uri=True)


class Compatibility(StrEnum):
    CURRENT = "current"  # this Hound's schema version
    UPGRADE = "upgrade"  # older version: migrated on start
    ADOPT = "adopt"  # created before versioning, structure matches: adopted as v1 on start
    EMPTY = "empty"  # a valid SQLite file without tables
    NEWER = "newer"  # written by a newer Hound: refused
    FOREIGN = "foreign"  # tables that are not a Hound database: refused


@dataclass(frozen=True, slots=True)
class DatabaseInfo:
    version: int
    compatibility: Compatibility
    events: int | None  # rows in ``events`` when that table exists


def inspect_connection(connection: sqlite3.Connection) -> DatabaseInfo:
    cursor = connection.cursor()
    version = int(cursor.execute("PRAGMA user_version").fetchone()[0])
    tables = {
        row[0]
        for row in cursor.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
    }
    target = latest_version()
    if version > target:
        compatibility = Compatibility.NEWER
    elif version == 0 and not tables:
        compatibility = Compatibility.EMPTY
    elif version == 0:
        adopt = schema_fingerprint(cursor) == baseline_fingerprint()
        compatibility = Compatibility.ADOPT if adopt else Compatibility.FOREIGN
    else:
        compatibility = Compatibility.CURRENT if version == target else Compatibility.UPGRADE
    events = int(cursor.execute("SELECT count(*) FROM events").fetchone()[0]) if "events" in tables else None
    return DatabaseInfo(version, compatibility, events)


def inspect_database(path: Path) -> DatabaseInfo:
    """Classify ``path`` read-only. Raises :class:`sqlite3.DatabaseError` for non-SQLite files."""
    connection = open_read_only(path)
    try:
        return inspect_connection(connection)
    finally:
        connection.close()
