"""``python run.py backup`` / ``restore``: consistent copies, strict validation, nothing lost on restore."""

from __future__ import annotations

import os
import sqlite3
import stat
import sys
import threading
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from app import cli
from app.core.config import Settings
from app.database import backup as backup_module
from app.database.backup import BackupError, check_backup, create_backup, default_backup_path, restore_backup
from app.database.inspect import Compatibility, sqlite_path
from app.services.runtime import HoundRuntime
from tests.conftest import EventFactory
from tests.test_daemon import LiveServer, free_port, start_server

POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
NOW = datetime(2026, 9, 29, 10, 30, 0, tzinfo=UTC)


@pytest.fixture
def live_database(settings: Settings, make_event: EventFactory) -> Iterator[tuple[HoundRuntime, Path]]:
    runtime = HoundRuntime(settings)
    runtime.database.initialize()
    runtime.processor.process_batch([make_event(domain=f"host{n}.example", seconds=n) for n in range(20)])
    path = sqlite_path(settings)
    assert path is not None
    yield runtime, path
    runtime.database.dispose()


def count_events(path: Path) -> int:
    # closing(): sqlite3's own `with` only commits and leaves the file open, which Windows
    # then refuses to move (found by the owner's Windows run).
    with closing(sqlite3.connect(path)) as connection:
        return int(connection.execute("SELECT count(*) FROM events").fetchone()[0])


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


# ------------------------------------------------------------------------------ backup
def test_backup_is_a_verified_self_contained_copy(live_database: tuple[HoundRuntime, Path], tmp_path: Path) -> None:
    _, database = live_database
    result = create_backup(database, tmp_path / "copies" / "b.db")
    assert result.info.events == 20 and result.info.compatibility is Compatibility.CURRENT
    assert result.size_bytes == result.path.stat().st_size > 0
    assert sorted(p.name for p in result.path.parent.iterdir()) == ["b.db"]  # no -wal/-shm/-journal
    with closing(sqlite3.connect(result.path)) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_backup_while_the_server_writes(
    live_database: tuple[HoundRuntime, Path], tmp_path: Path, make_event: EventFactory
) -> None:
    runtime, database = live_database
    stop = threading.Event()

    def keep_writing() -> None:
        second = 100
        while not stop.is_set():
            runtime.processor.process_batch([make_event(domain=f"busy{second}.example", seconds=second)])
            second += 1

    writer = threading.Thread(target=keep_writing)
    writer.start()
    try:
        results = [create_backup(database, tmp_path / f"during-{n}.db") for n in range(5)]
    finally:
        stop.set()
        writer.join()
    counts = [result.info.events or 0 for result in results]
    assert all(20 <= count <= count_events(database) for count in counts)
    assert counts == sorted(counts)  # each snapshot is consistent and at least as new as the last


@POSIX_ONLY
def test_backup_is_owner_only_even_while_being_written(
    live_database: tuple[HoundRuntime, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, database = live_database
    target = tmp_path / "new-folder" / "b.db"
    seen_during: list[int] = []
    original = backup_module.inspect_connection

    def observe(connection: Any) -> Any:
        seen_during.append(mode(target))  # the data is already in the file at this point
        return original(connection)

    monkeypatch.setattr(backup_module, "inspect_connection", observe)
    result = create_backup(database, target)
    assert seen_during == [0o600]
    assert mode(result.path) == 0o600
    assert mode(result.path.parent) == 0o700


def test_backup_refusals(live_database: tuple[HoundRuntime, Path], tmp_path: Path) -> None:
    _, database = live_database
    existing = tmp_path / "exists.db"
    existing.write_bytes(b"keep me")
    with pytest.raises(BackupError, match="never overwritten"):
        create_backup(database, existing)
    assert existing.read_bytes() == b"keep me"
    with pytest.raises(BackupError, match="no database"):
        create_backup(tmp_path / "missing.db", tmp_path / "x.db")
    assert default_backup_path(database, NOW) == database.parent / "backups" / "hound-test-20260929-103000.db"


def test_failed_backup_leaves_nothing_behind(
    live_database: tuple[HoundRuntime, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, database = live_database

    def broken(connection: Any) -> Any:
        raise sqlite3.DatabaseError("simulated failure")

    monkeypatch.setattr(backup_module, "inspect_connection", broken)
    with pytest.raises(BackupError, match="simulated failure"):
        create_backup(database, tmp_path / "out" / "b.db")
    assert list((tmp_path / "out").iterdir()) == []


# ------------------------------------------------------------------------------ validation
def make_file(path: Path, statements: list[str]) -> Path:
    with closing(sqlite3.connect(path)) as connection:
        for statement in statements:
            connection.execute(statement)
        connection.commit()
    return path


@pytest.mark.parametrize(
    ("statements", "message"),
    [
        (["CREATE TABLE events (id INTEGER)", "PRAGMA user_version = 99"], "newer Hound"),
        (["CREATE TABLE recipes (name TEXT)"], "not a Hound database"),
        ([], "contains no Hound data"),
    ],
)
def test_unusable_backups_are_refused(tmp_path: Path, statements: list[str], message: str) -> None:
    with pytest.raises(BackupError, match=message):
        check_backup(make_file(tmp_path / "b.db", statements))


def test_damaged_or_missing_backups_are_refused(tmp_path: Path) -> None:
    garbage = tmp_path / "garbage.db"
    garbage.write_bytes(b"not sqlite at all " * 200)
    with pytest.raises(BackupError, match="not a readable SQLite database"):
        check_backup(garbage)
    with pytest.raises(BackupError, match="no backup file"):
        check_backup(tmp_path / "absent.db")


# ------------------------------------------------------------------------------ restore
def test_restore_brings_back_the_backup_and_keeps_the_current_database(
    live_database: tuple[HoundRuntime, Path], tmp_path: Path, settings: Settings, make_event: EventFactory
) -> None:
    runtime, database = live_database
    snapshot = create_backup(database, tmp_path / "b.db").path
    runtime.processor.process_batch([make_event(domain=f"later{n}.example", seconds=500 + n) for n in range(5)])
    runtime.database.dispose()  # the server is stopped
    assert count_events(database) == 25

    result = restore_backup(snapshot, database, NOW)
    assert count_events(database) == 20
    assert result.previous_saved_as == database.with_name("hound-test.db.before-restore-20260929-103000")
    assert count_events(result.previous_saved_as) == 25  # nothing lost
    assert not Path(f"{database}-wal").exists()

    restarted = HoundRuntime(settings)  # Hound starts normally on the restored file
    restarted.database.initialize()
    assert restarted.stats.stats().total_events == 20
    restarted.database.dispose()


def test_restore_puts_everything_back_if_the_copy_fails(
    live_database: tuple[HoundRuntime, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, database = live_database
    snapshot = create_backup(database, tmp_path / "b.db").path
    runtime.database.dispose()
    before = database.read_bytes()

    def full_disk(*args: Any, **kwargs: Any) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(backup_module.shutil, "copyfile", full_disk)
    with pytest.raises(BackupError, match="Nothing was changed"):
        restore_backup(snapshot, database, NOW)
    assert database.read_bytes() == before
    assert not list(database.parent.glob("*.before-restore-*"))


def test_restore_never_deletes_the_database_when_it_cannot_be_moved(
    live_database: tuple[HoundRuntime, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: a failed move (e.g. file locked on Windows) must leave the live database alone.

    The first version's rollback unlinked ``database`` even when the original had never been
    moved aside, which on Linux would have deleted it (found by the owner's Windows run).
    """
    runtime, database = live_database
    snapshot = create_backup(database, tmp_path / "b.db").path
    runtime.database.dispose()
    before = database.read_bytes()

    def locked(source: Any, target: Any) -> None:
        raise PermissionError(32, "The process cannot access the file because it is being used by another process")

    monkeypatch.setattr(backup_module.os, "replace", locked)
    with pytest.raises(BackupError, match="Nothing was changed"):
        restore_backup(snapshot, database, NOW)
    assert database.exists() and database.read_bytes() == before


def test_restore_refuses_the_live_database_itself(live_database: tuple[HoundRuntime, Path]) -> None:
    runtime, database = live_database
    runtime.database.dispose()
    with pytest.raises(BackupError, match="live database itself"):
        restore_backup(database, database, NOW)


@POSIX_ONLY
def test_restored_database_is_owner_only(live_database: tuple[HoundRuntime, Path], tmp_path: Path) -> None:
    runtime, database = live_database
    snapshot = create_backup(database, tmp_path / "b.db").path
    os.chmod(snapshot, 0o644)
    runtime.database.dispose()
    restore_backup(snapshot, database, NOW)
    assert mode(database) == 0o600


# ------------------------------------------------------------------------------ CLI
@pytest.fixture
def quiet_cli(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> Settings:
    configured = settings.model_copy(update={"port": free_port()})
    monkeypatch.setattr(cli, "load_settings", lambda **_: configured)
    monkeypatch.setattr(cli, "configure_logging", lambda *a, **k: None)
    return configured


def test_cli_backup_and_restore(
    quiet_cli: Settings, live_database: tuple[HoundRuntime, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    runtime, database = live_database
    assert cli.main(["backup"]) == 0
    out = capsys.readouterr().out
    assert "Backup written:" in out and "20 events" in out and "integrity ok" in out
    written = next((database.parent / "backups").iterdir())
    assert cli.main(["backup", str(written)]) == 2  # never overwrites
    assert "never overwritten" in capsys.readouterr().err

    runtime.database.dispose()
    assert cli.main(["restore", str(written)]) == 0
    out = capsys.readouterr().out
    assert "Restored" in out and "The previous database was kept as" in out
    assert list(database.parent.glob("hound-test.db.before-restore-*"))


def test_cli_restore_refuses_while_hound_runs(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    server: LiveServer = start_server(settings, free_port())
    try:
        monkeypatch.setattr(cli, "load_settings", lambda **_: settings.model_copy(update={"port": server.port}))
        monkeypatch.setattr(cli, "configure_logging", lambda *a, **k: None)
        path = sqlite_path(settings)
        assert path is not None
        assert cli.main(["backup", str(tmp_path / "hot.db")]) == 0  # backup is fine while running
        assert cli.main(["restore", str(tmp_path / "hot.db")]) == 2
        assert "Stop the server" in capsys.readouterr().err
        assert path.exists()
    finally:
        server.stop()
