"""Database engine/session management and automatic schema initialisation."""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.tables import Base

logger = logging.getLogger(__name__)


class DatabaseError(RuntimeError):
    """Raised when the database cannot be initialised or reached."""


def _sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
    if not isinstance(dbapi_connection, sqlite3.Connection):
        return
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")  # concurrent readers while the pipeline writes
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
    finally:
        cursor.close()


class Database:
    """Owns the SQLAlchemy engine and hands out short-lived sessions."""

    def __init__(self, url: str, *, echo: bool = False) -> None:
        self.url = url
        parsed = make_url(url)
        self._is_sqlite = parsed.get_backend_name() == "sqlite"
        self._sqlite_path: Path | None = None
        kwargs: dict[str, Any] = {"echo": echo, "pool_pre_ping": True}
        if self._is_sqlite:
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
            if not parsed.database or parsed.database == ":memory:":
                kwargs["poolclass"] = StaticPool  # share one in-memory DB across threads
            else:
                self._sqlite_path = Path(parsed.database)
        self.engine: Engine = create_engine(url, **kwargs)
        if self._is_sqlite:
            event.listen(self.engine, "connect", _sqlite_pragmas)
        self._session_factory = sessionmaker(self.engine, expire_on_commit=False)

    def initialize(self) -> None:
        """Create the database file/directory and all tables if they do not exist."""
        try:
            if self._sqlite_path is not None:
                self._sqlite_path.parent.mkdir(parents=True, exist_ok=True)
            Base.metadata.create_all(self.engine)
        except (OSError, SQLAlchemyError) as exc:
            raise DatabaseError(f"Could not initialise database: {exc}") from exc
        logger.info("Database ready", extra={"database": self.describe()})

    def describe(self) -> str:
        """Safe, credential-free description for logs."""
        return str(self._sqlite_path) if self._sqlite_path else make_url(self.url).render_as_string()

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Transactional scope: commit on success, roll back on error."""
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def ping(self) -> bool:
        try:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except SQLAlchemyError:
            return False
        return True

    def dispose(self) -> None:
        self.engine.dispose()
