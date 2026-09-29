"""Consistent backups of the SQLite database, and a guarded restore (ADR-024).

``create_backup`` uses SQLite's online backup API, so it is safe while the server is
writing (WAL readers do not block writers). The copy is created owner-only before any
data is written, converted to a single self-contained file (no ``-wal``), and passes
``PRAGMA integrity_check`` — otherwise it is deleted and an error raised.

``restore_backup`` refuses anything that is not a usable Hound database (corrupt, newer
schema, foreign tables, empty) and never deletes the current database: it is moved aside,
together with its ``-wal``/``-shm`` files, before the backup is copied into place. The
caller must make sure the server is stopped (the CLI checks this).
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from app.database.inspect import Compatibility, DatabaseInfo, inspect_connection, open_read_only

REFUSED = {
    Compatibility.NEWER: "was written by a newer Hound",
    Compatibility.FOREIGN: "is not a Hound database",
    Compatibility.EMPTY: "contains no Hound data",
}


class BackupError(RuntimeError):
    """A backup or restore could not be done; nothing was changed."""


@dataclass(frozen=True, slots=True)
class BackupResult:
    path: Path
    size_bytes: int
    info: DatabaseInfo
    seconds: float


@dataclass(frozen=True, slots=True)
class RestoreResult:
    restored_from: Path
    database: Path
    previous_saved_as: Path | None
    info: DatabaseInfo


def default_backup_path(database: Path, now: datetime) -> Path:
    return database.parent / "backups" / f"{database.stem}-{now:%Y%m%d-%H%M%S}.db"


def _owner_only(path: Path) -> None:
    if os.name == "posix":
        path.chmod(0o600)


def create_backup(database: Path, destination: Path) -> BackupResult:
    if not database.is_file():
        raise BackupError(f"There is no database at {database} yet (start Hound once first).")
    if destination.exists():
        raise BackupError(f"{destination} already exists; choose another name (backups are never overwritten).")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    started = time.monotonic()
    try:
        # Create the file owner-only before SQLite writes a single page of browsing history into it.
        os.close(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    except OSError as exc:
        raise BackupError(f"Cannot create {destination}: {exc.strerror}") from exc
    try:
        with closing(sqlite3.connect(database, timeout=30)) as source, closing(sqlite3.connect(destination)) as copy:
            source.backup(copy)  # one step: a consistent snapshot, even while the server writes
            copy.execute("PRAGMA journal_mode=DELETE")  # a single self-contained file, no -wal
            verdict = copy.execute("PRAGMA integrity_check").fetchone()[0]
            if verdict != "ok":
                raise BackupError(f"The copy failed its integrity check ({verdict}); it was deleted.")
            info = inspect_connection(copy)
    except sqlite3.Error as exc:
        _discard(destination)
        raise BackupError(f"Backup failed: {exc}") from exc
    except BaseException:
        _discard(destination)
        raise
    _owner_only(destination)
    return BackupResult(destination, destination.stat().st_size, info, round(time.monotonic() - started, 2))


def _discard(path: Path) -> None:
    for leftover in (path, Path(f"{path}-journal"), Path(f"{path}-wal"), Path(f"{path}-shm")):
        leftover.unlink(missing_ok=True)


def check_backup(backup: Path) -> DatabaseInfo:
    """Validate ``backup`` read-only; raises :class:`BackupError` if it must not be restored."""
    if not backup.is_file():
        raise BackupError(f"There is no backup file at {backup}.")
    try:
        with closing(open_read_only(backup)) as connection:
            verdict = connection.execute("PRAGMA integrity_check").fetchone()[0]
            if verdict != "ok":
                raise BackupError(f"{backup} is damaged ({verdict}); refusing to restore it.")
            info = inspect_connection(connection)
    except sqlite3.DatabaseError as exc:
        raise BackupError(f"{backup} is not a readable SQLite database ({exc}).") from exc
    if info.compatibility in REFUSED:
        raise BackupError(f"{backup} {REFUSED[info.compatibility]} (schema v{info.version}); refusing to restore it.")
    return info


def restore_backup(backup: Path, database: Path, now: datetime) -> RestoreResult:
    """Replace ``database`` with ``backup``. The server must be stopped."""
    info = check_backup(backup)
    if backup.resolve() == database.resolve():
        raise BackupError("That is the live database itself, not a backup.")
    database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    aside = database.with_name(f"{database.name}.before-restore-{now:%Y%m%d-%H%M%S}")
    moved: list[tuple[Path, Path]] = []
    copying = False  # True only once every original file is safely aside
    try:
        for suffix in ("", "-wal", "-shm"):
            current = Path(f"{database}{suffix}")
            if current.exists():
                target = Path(f"{aside}{suffix}")
                os.replace(current, target)
                moved.append((target, current))
        copying = True
        shutil.copyfile(backup, database)
        _owner_only(database)
    except OSError as exc:
        # Only a partial copy may be removed. If the move failed, the file at `database` is
        # still the owner's live database and must not be touched.
        if copying:
            database.unlink(missing_ok=True)
        for target, original in reversed(moved):  # put everything back as it was
            os.replace(target, original)
        raise BackupError(
            f"Cannot replace {database} ({exc.strerror}); is Hound still running? Nothing was changed."
        ) from exc
    return RestoreResult(backup, database, aside if moved else None, info)
