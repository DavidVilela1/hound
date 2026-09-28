"""Shared-secret handling for the capture-daemon → API ingest channel.

The API server (unprivileged) creates a random token in ``data/.ingest_token``
with ``0600`` permissions on first start. The capture daemon (usually run with
elevated privileges) reads the same file, so no manual configuration is needed.
Alternatively, set ``HOUND_INGEST_TOKEN`` for both processes.
"""

from __future__ import annotations

import hmac
import logging
import os
import secrets
from pathlib import Path

from app.core.config import Settings

logger = logging.getLogger(__name__)

MIN_TOKEN_LENGTH = 24
TOKEN_HEADER = "X-Hound-Token"


def _read_token_file(path: Path) -> str | None:
    try:
        token = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    except OSError as exc:
        logger.warning("Cannot read ingest token file", extra={"path": str(path), "error": str(exc)})
        return None
    if len(token) < MIN_TOKEN_LENGTH:
        logger.warning("Ignoring ingest token file: token too short", extra={"path": str(path)})
        return None
    return token


def read_ingest_token(settings: Settings) -> str | None:
    """Return the configured token (env first, then token file) without creating one."""
    if settings.ingest_token is not None:
        value = settings.ingest_token.get_secret_value().strip()
        return value if len(value) >= MIN_TOKEN_LENGTH else None
    return _read_token_file(settings.resolve_path(settings.ingest_token_path))


def load_or_create_ingest_token(settings: Settings) -> str:
    """Return the ingest token, creating a random one in the token file if needed.

    If the file cannot be written (e.g. it belongs to another user), an
    in-memory token is used and remote ingest will only work when
    ``HOUND_INGEST_TOKEN`` is set for the capture daemon as well.
    """
    existing = read_ingest_token(settings)
    if existing:
        return existing
    token = secrets.token_urlsafe(32)
    path = settings.resolve_path(settings.ingest_token_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(token)
        logger.info("Created ingest token file", extra={"path": str(path)})
    except OSError as exc:
        logger.warning(
            "Could not persist ingest token; capture daemon must use HOUND_INGEST_TOKEN",
            extra={"path": str(path), "error": str(exc)},
        )
    return token


def tokens_match(provided: str | None, expected: str | None) -> bool:
    """Constant-time token comparison."""
    if not provided or not expected:
        return False
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))
