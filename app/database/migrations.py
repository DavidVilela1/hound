"""Versioned SQLite schema: a frozen baseline plus ordered, atomic migration steps.

How it works
------------
* The schema version lives in the database header (``PRAGMA user_version``).
* Every database — new or old — reaches the latest version through the same path:
  :data:`MIGRATIONS`, applied in order. Version 1 is the frozen baseline DDL.
* Each step runs in its own ``BEGIN IMMEDIATE`` transaction together with the version
  bump, so a failing step leaves the database exactly as it was. The version is read
  *inside* the transaction, so two processes starting at once cannot both migrate.
* Databases created before versioning existed (``user_version`` 0 with tables) are
  adopted as version 1 only if their structure matches the baseline exactly.
* A database newer than this code, or a file that is not a Hound database, is refused.

Adding a migration
------------------
Never edit :data:`BASELINE_V1_DDL` or an existing step. Append
``Migration(N + 1, "what changes", apply)`` to :data:`MIGRATIONS` and update the ORM models
in ``tables.py`` to match. ``tests/test_migrations.py`` fails if the migrated schema and
the ORM models ever disagree. SQLite cannot drop or alter most column properties in
place; use the documented table-rebuild pattern (create new table, copy, drop, rename)
inside ``apply``.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class SchemaVersionError(Exception):
    """The database cannot be used with this version of Hound (message is user-facing)."""


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    description: str
    apply: Callable[[sqlite3.Cursor], None]


@dataclass(frozen=True, slots=True)
class MigrationResult:
    from_version: int
    to_version: int
    adopted_legacy: bool = False

    @property
    def changed(self) -> bool:
        return self.adopted_legacy or self.from_version != self.to_version


# Schema version 1, exactly as created by Hound 1.0.0 (SQLAlchemy create_all for SQLite).
# FROZEN — never edit; add a new migration instead.
BASELINE_V1_DDL: tuple[str, ...] = (
    """CREATE TABLE devices (
    id INTEGER NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    event_count INTEGER NOT NULL,
    dns_query_count INTEGER NOT NULL,
    connection_attempt_count INTEGER NOT NULL,
    suspicious_event_count INTEGER NOT NULL,
    dangerous_event_count INTEGER NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level VARCHAR(16) NOT NULL,
    risk_updated_at DATETIME,
    observations JSON NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (source_ip)
)""",
    "CREATE INDEX ix_devices_last_seen ON devices (last_seen)",
    "CREATE INDEX ix_devices_risk_score ON devices (risk_score)",
    """CREATE TABLE events (
    id INTEGER NOT NULL,
    timestamp DATETIME NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    source_port INTEGER,
    destination_ip VARCHAR(45) NOT NULL,
    destination_port INTEGER,
    protocol VARCHAR(8) NOT NULL,
    packet_type VARCHAR(16) NOT NULL,
    domain VARCHAR(253),
    domain_source VARCHAR(16),
    interface VARCHAR(64),
    dns_query_type VARCHAR(16),
    country VARCHAR(16),
    risk_score INTEGER NOT NULL,
    risk_level VARCHAR(16) NOT NULL,
    risk_reasons JSON NOT NULL,
    blocklist_match VARCHAR(253),
    PRIMARY KEY (id)
)""",
    "CREATE INDEX ix_events_country ON events (country)",
    "CREATE INDEX ix_events_destination_ip ON events (destination_ip)",
    "CREATE INDEX ix_events_domain ON events (domain)",
    "CREATE INDEX ix_events_packet_type ON events (packet_type)",
    "CREATE INDEX ix_events_risk_level_timestamp ON events (risk_level, timestamp)",
    "CREATE INDEX ix_events_source_ip_timestamp ON events (source_ip, timestamp)",
    "CREATE INDEX ix_events_timestamp ON events (timestamp)",
)


def _execute_all(statements: Sequence[str]) -> Callable[[sqlite3.Cursor], None]:
    def apply(cursor: sqlite3.Cursor) -> None:
        for statement in statements:
            cursor.execute(statement)

    return apply


MIGRATIONS: tuple[Migration, ...] = (
    Migration(1, "Baseline schema: events and devices", _execute_all(BASELINE_V1_DDL)),
)


def latest_version(migrations: Sequence[Migration] = MIGRATIONS) -> int:
    return migrations[-1].version if migrations else 0


# ---------------------------------------------------------------------------- introspection
Fingerprint = tuple[tuple[str, tuple[tuple[object, ...], ...], tuple[tuple[object, ...], ...]], ...]


def schema_fingerprint(cursor: sqlite3.Cursor) -> Fingerprint:
    """Comparable description of all user tables: columns and indexes (names, types, flags)."""
    tables = [
        row[0]
        for row in cursor.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]
    result = []
    for table in tables:
        quoted = table.replace('"', '""')
        columns = tuple(
            (name, col_type.upper(), bool(notnull), default, pk)
            for _cid, name, col_type, notnull, default, pk in cursor.execute(f'PRAGMA table_info("{quoted}")')
        )
        indexes = []
        for _seq, index_name, unique, origin, _partial in cursor.execute(f'PRAGMA index_list("{quoted}")').fetchall():
            quoted_index = index_name.replace('"', '""')
            index_columns = tuple(row[2] for row in cursor.execute(f'PRAGMA index_info("{quoted_index}")'))
            indexes.append((index_name, bool(unique), origin, index_columns))
        result.append((table, columns, tuple(sorted(indexes))))
    return tuple(result)


def baseline_fingerprint() -> Fingerprint:
    """Fingerprint of a database created from :data:`BASELINE_V1_DDL`."""
    probe = sqlite3.connect(":memory:")
    try:
        cursor = probe.cursor()
        _execute_all(BASELINE_V1_DDL)(cursor)
        return schema_fingerprint(cursor)
    finally:
        probe.close()


# ---------------------------------------------------------------------------- runner
def _user_version(cursor: sqlite3.Cursor) -> int:
    return int(cursor.execute("PRAGMA user_version").fetchone()[0])


def _set_user_version(cursor: sqlite3.Cursor, version: int) -> None:
    cursor.execute(f"PRAGMA user_version = {int(version)}")  # PRAGMA cannot take bound parameters


def _has_user_tables(cursor: sqlite3.Cursor) -> bool:
    row = cursor.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    ).fetchone()
    return bool(row[0])


@contextmanager
def _immediate_transaction(cursor: sqlite3.Cursor) -> Iterator[None]:
    cursor.execute("BEGIN IMMEDIATE")  # take the write lock before reading the version
    try:
        yield
    except BaseException:
        if cursor.connection.in_transaction:  # SQLite may already have rolled back (e.g. disk full)
            cursor.execute("ROLLBACK")
        raise
    cursor.execute("COMMIT")


def _check_sequence(migrations: Sequence[Migration]) -> None:
    expected = list(range(1, len(migrations) + 1))
    if [m.version for m in migrations] != expected:
        raise ValueError(f"migration versions must be contiguous from 1, got {[m.version for m in migrations]}")


def migrate(connection: sqlite3.Connection, migrations: Sequence[Migration] = MIGRATIONS) -> MigrationResult:
    """Bring ``connection``'s database to the latest schema version.

    Raises:
        SchemaVersionError: the database is newer than this code or is not a Hound database.
        sqlite3.Error: a migration step failed (that step was rolled back).
    """
    _check_sequence(migrations)
    target = latest_version(migrations)
    previous_isolation = connection.isolation_level
    connection.isolation_level = None  # manage transactions explicitly (DDL included)
    cursor = connection.cursor()
    try:
        with _immediate_transaction(cursor):
            start = _user_version(cursor)
            if start > target:
                raise SchemaVersionError(
                    f"The database uses schema version {start}, but this version of Hound supports up to "
                    f"version {target}. Upgrade Hound, or point HOUND_DATABASE_URL at a different file."
                )
            adopted = False
            if start == 0 and _has_user_tables(cursor):
                if schema_fingerprint(cursor) != baseline_fingerprint():
                    raise SchemaVersionError(
                        "The database file already contains tables that do not match any Hound schema. "
                        "Move or back up the file, or point HOUND_DATABASE_URL at a different file."
                    )
                _set_user_version(cursor, 1)
                adopted = True
                logger.info("Adopted pre-versioning database as schema version 1")

        for step in migrations:
            with _immediate_transaction(cursor):
                if _user_version(cursor) >= step.version:
                    continue
                step.apply(cursor)
                _set_user_version(cursor, step.version)
            logger.info("Applied database migration", extra={"version": step.version, "migration": step.description})

        return MigrationResult(from_version=start, to_version=_user_version(cursor), adopted_legacy=adopted)
    finally:
        cursor.close()
        connection.isolation_level = previous_isolation
