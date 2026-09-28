"""Structured logging setup.

Two formats are supported:

* ``text`` – human readable, with any ``extra={...}`` fields appended as ``key=value``;
* ``json`` – one JSON object per line, suitable for log shippers.

Per-packet details are only ever logged at DEBUG level to avoid writing
browsing history into log files by default.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

_STANDARD_ATTRS = frozenset(vars(logging.LogRecord("x", logging.INFO, "x", 0, "x", None, None)).keys()) | {
    "message",
    "asctime",
    "taskName",
}

_NOISY_LOGGERS = {
    "scapy.runtime": logging.ERROR,
    "scapy.loading": logging.ERROR,
    "uvicorn.access": logging.WARNING,
    "httpx": logging.WARNING,
    "httpcore": logging.WARNING,
    "websockets": logging.WARNING,
    "multipart": logging.WARNING,
}


_IGNORED_EXTRAS = frozenset({"color_message"})
_SIMPLE_TYPES = (str, int, float, bool, type(None))


def _extra_fields(record: logging.LogRecord) -> dict[str, Any]:
    """User-supplied ``extra`` fields with simple values (objects are never dumped)."""
    return {
        k: v
        for k, v in vars(record).items()
        if k not in _STANDARD_ATTRS
        and k not in _IGNORED_EXTRAS
        and not k.startswith("_")
        and isinstance(v, _SIMPLE_TYPES)
    }


class KeyValueFormatter(logging.Formatter):
    """``2026-01-01 12:00:00 INFO  hound.x: message key=value``."""

    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        extras = _extra_fields(record)
        if extras:
            base += " " + " ".join(f"{k}={v}" for k, v in sorted(extras.items()))
        return base


class JsonFormatter(logging.Formatter):
    """Serialise log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        payload.update(_extra_fields(record))
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", fmt: str = "text") -> None:
    """Configure the root logger once for the whole process."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter() if fmt == "json" else KeyValueFormatter())
    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level.upper())
    for name, noisy_level in _NOISY_LOGGERS.items():
        logging.getLogger(name).setLevel(max(noisy_level, root.level))
    # Uvicorn installs its own handlers unless told otherwise; route them to root.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True
