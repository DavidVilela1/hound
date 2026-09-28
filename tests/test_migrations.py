"""Schema versioning: fresh databases, legacy adoption, upgrades, refusals, atomicity."""

from __future__ import annotations

import os
import sqlite3
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import create_engine

from app.database.engine import Database, DatabaseError
from app.database.migrations import (
    MIGRATIONS,
    Migration,
    SchemaVersionError,
    baseline_fingerprint,
    latest_version,
    migrate,
    schema_fingerprint,
)
from app.database.repositories import DeviceRepository, EventFilter, EventRepository
from app.database.tables import Base

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")


def user_version(path: Path) -> int:
    with sqlite3.connect(path) as conn:
        return int(conn.execute("PRAGMA user_version").fetchone()[0])


def orm_fingerprint() -> object:
    """Fingerprint of the schema the ORM models describe (what the code expects)."""
    engine = create_engine("sqlite://")
    with engine.connect() as conn:
        Base.metadata.create_all(conn)
        conn.commit()
        return schema_fingerprint(conn.connection.driver_connection.cursor())


def make_legacy_db(path: Path) -> None:
    """A database as Hound 1.0.0 created it: create_all, user_version 0, with data."""
    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine)
    engine.dispose()
    with sqlite3.connect(path) as conn:
        conn.execute(
            "INSERT INTO devices (source_ip, first_seen, last_seen, event_count, dns_query_count, "
            "connection_attempt_count, suspicious_event_count, dangerous_event_count, risk_score, "
            "risk_level, observations) VALUES ('192.168.1.10', '2026-01-01 00:00:00', "
            "'2026-01-01 00:00:00', 3, 2, 1, 0, 0, 0, 'safe', '[]')"
        )


# --------------------------------------------------------------------------- drift guard


def test_migrated_schema_matches_orm_models(tmp_path: Path) -> None:
    """Fails if tables.py and the migrations ever disagree (e.g. a model changed without a migration)."""
    db = Database(f"sqlite:///{tmp_path / 'h.db'}")
    db.initialize()
    db.dispose()
    with sqlite3.connect(tmp_path / "h.db") as conn:
        assert schema_fingerprint(conn.cursor()) == orm_fingerprint()


def test_frozen_baseline_equals_hound_1_0_schema() -> None:
    # Version 1 is what Hound 1.0.0 created with create_all. Only true while no migration exists
    # beyond 1; afterwards the baseline stays frozen and this documents the adoption contract.
    if latest_version() == 1:
        assert baseline_fingerprint() == orm_fingerprint()


# --------------------------------------------------------------------------- lifecycle


def test_fresh_database_is_created_at_latest_version(tmp_path: Path) -> None:
    db = Database(f"sqlite:///{tmp_path / 'new.db'}")
    db.initialize()
    assert db.schema_version == latest_version()
    db.dispose()
    assert user_version(tmp_path / "new.db") == latest_version()


def test_initialize_is_idempotent(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'h.db'}"
    for _ in range(3):
        db = Database(url)
        db.initialize()
        db.dispose()
    assert user_version(tmp_path / "h.db") == latest_version()


def test_legacy_database_is_adopted_with_data_intact(tmp_path: Path) -> None:
    path = tmp_path / "legacy.db"
    make_legacy_db(path)
    assert user_version(path) == 0
    with sqlite3.connect(path) as conn:
        result = migrate(conn)
    assert result.adopted_legacy and result.from_version == 0 and result.to_version == latest_version()
    db = Database(f"sqlite:///{path}")
    db.initialize()
    with db.session() as session:
        device = DeviceRepository(session).get("192.168.1.10")
        assert device is not None and device.event_count == 3
        assert EventRepository(session).count(EventFilter()) == 0
    db.dispose()


def test_database_newer_than_code_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "future.db"
    Database(f"sqlite:///{path}").initialize()
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA user_version = 99")
    db = Database(f"sqlite:///{path}")
    with pytest.raises(DatabaseError, match="schema version 99"):
        db.initialize()
    db.dispose()
    assert user_version(path) == 99  # untouched


def test_foreign_database_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "other-app.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)")
    db = Database(f"sqlite:///{path}")
    with pytest.raises(DatabaseError, match="do not match any Hound schema"):
        db.initialize()
    db.dispose()
    with sqlite3.connect(path) as conn:  # nothing was added to the foreign file
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert tables == {"notes"} and user_version(path) == 0


def test_partial_legacy_schema_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "damaged.db"
    make_legacy_db(path)
    with sqlite3.connect(path) as conn:
        conn.execute("DROP INDEX ix_events_domain")
    with sqlite3.connect(path) as conn, pytest.raises(SchemaVersionError):
        migrate(conn)


def test_in_memory_database_is_versioned() -> None:
    db = Database("sqlite:///:memory:")
    db.initialize()
    assert db.schema_version == latest_version()
    with db.session() as session:
        assert EventRepository(session).count(EventFilter()) == 0


# --------------------------------------------------------------------------- future migrations


def _add_note_column(cursor: sqlite3.Cursor) -> None:
    cursor.execute("ALTER TABLE devices ADD COLUMN note VARCHAR(64)")


def test_upgrade_applies_new_steps_in_order_and_keeps_data(tmp_path: Path) -> None:
    path = tmp_path / "v1.db"
    Database(f"sqlite:///{path}").initialize()
    with sqlite3.connect(path) as conn:
        conn.execute(
            "INSERT INTO devices (source_ip, first_seen, last_seen, event_count, dns_query_count, "
            "connection_attempt_count, suspicious_event_count, dangerous_event_count, risk_score, "
            "risk_level, observations) VALUES ('10.0.0.5', ?, ?, 1, 1, 0, 0, 0, 0, 'safe', '[]')",
            (datetime.now(UTC).isoformat(), datetime.now(UTC).isoformat()),
        )
    v2 = (*MIGRATIONS, Migration(2, "Add device note", _add_note_column))
    with sqlite3.connect(path) as conn:
        result = migrate(conn, v2)
        assert (result.from_version, result.to_version) == (1, 2)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(devices)")}
        assert "note" in columns
        assert conn.execute("SELECT source_ip FROM devices").fetchall() == [("10.0.0.5",)]
        again = migrate(conn, v2)  # re-running is a no-op
        assert not again.changed


def test_failed_step_is_rolled_back_completely(tmp_path: Path) -> None:
    path = tmp_path / "v1.db"
    Database(f"sqlite:///{path}").initialize()

    def broken(cursor: sqlite3.Cursor) -> None:
        _add_note_column(cursor)
        raise sqlite3.OperationalError("simulated failure half-way through a migration")

    with sqlite3.connect(path) as conn:
        with pytest.raises(sqlite3.OperationalError):
            migrate(conn, (*MIGRATIONS, Migration(2, "Broken", broken)))
        columns = {row[1] for row in conn.execute("PRAGMA table_info(devices)")}
    assert "note" not in columns
    assert user_version(path) == 1


def test_migrations_must_be_contiguous(tmp_path: Path) -> None:
    with sqlite3.connect(tmp_path / "x.db") as conn, pytest.raises(ValueError, match="contiguous"):
        migrate(conn, (*MIGRATIONS, Migration(3, "Gap", _add_note_column)))


def test_new_databases_can_run_future_steps(tmp_path: Path) -> None:
    """A brand-new database goes through every step, not a shortcut."""
    with sqlite3.connect(tmp_path / "fresh.db") as conn:
        result = migrate(conn, (*MIGRATIONS, Migration(2, "Add device note", _add_note_column)))
        assert (result.from_version, result.to_version) == (0, 2)
        assert "note" in {row[1] for row in conn.execute("PRAGMA table_info(devices)")}


# --------------------------------------------------------------------------- permissions (S-8)


@posix_only
def test_database_file_is_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "private.db"
    path.touch(mode=0o644)
    os.chmod(path, 0o644)
    db = Database(f"sqlite:///{path}")
    db.initialize()
    with db.session() as session:
        EventRepository(session).count(EventFilter())  # opens WAL files
    db.initialize()  # re-check after WAL/SHM exist
    db.dispose()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    for suffix in ("-wal", "-shm"):
        side = Path(f"{path}{suffix}")
        if side.exists():
            assert stat.S_IMODE(side.stat().st_mode) & 0o077 == 0


@posix_only
def test_new_data_directory_is_owner_only(tmp_path: Path) -> None:
    db = Database(f"sqlite:///{tmp_path / 'fresh-data' / 'hound.db'}")
    db.initialize()
    db.dispose()
    assert stat.S_IMODE((tmp_path / "fresh-data").stat().st_mode) & 0o077 == 0


def test_cli_refuses_newer_database_before_starting_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn

    import app.cli as cli

    path = tmp_path / "future.db"
    Database(f"sqlite:///{path}").initialize()
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA user_version = 99")
    monkeypatch.setenv("HOUND_DATABASE_URL", f"sqlite:///{path}")
    monkeypatch.setenv("HOUND_INGEST_TOKEN_PATH", str(tmp_path / "token"))
    monkeypatch.setattr(cli, "configure_logging", lambda *a, **k: None)  # keep pytest's log handlers
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: pytest.fail("the web server must not start"))
    assert cli.main(["--no-dashboard"]) == 2
