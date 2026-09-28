"""Local, file-based domain reputation (a simulated blocklist).

Matching strategy
-----------------
Both blocklist entries and observed domains are normalised with
:func:`app.core.netutils.normalize_domain` (lower-case, trailing dot removed,
URL/port stripped, IDNA-encoded). A domain matches when it **equals** an entry
or is a **subdomain** of an entry, compared on label boundaries:

* entry ``example.com`` matches ``example.com``, ``www.example.com`` and
  ``a.b.example.com``;
* it does **not** match ``notexample.com`` or ``example.com.evil.net``.

Lookups cost one set probe per label, independent of blocklist size.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from app.core.netutils import domain_suffixes, normalize_domain

logger = logging.getLogger(__name__)

_HOSTS_PREFIXES = ("0.0.0.0", "127.0.0.1", "::", "::1")


class DomainReputation(Protocol):
    """Anything that can tell whether a domain is known-bad."""

    def match(self, domain: str | None) -> str | None:
        """Return the matching blocklist entry, or ``None``."""
        ...


def parse_blocklist_line(line: str) -> str | None:
    """Parse one line (plain domain, ``*.domain`` or hosts-file format)."""
    text = line.split("#", 1)[0].strip()
    if not text:
        return None
    parts = text.split()
    if len(parts) >= 2 and parts[0] in _HOSTS_PREFIXES:
        text = parts[1]
    elif len(parts) != 1:
        return None
    if text.startswith("*."):
        text = text[2:]
    return normalize_domain(text)


class Blocklist:
    """In-memory set of blocked domains with parent-domain matching."""

    def __init__(self, domains: Iterable[str] = ()) -> None:
        self._domains: frozenset[str] = frozenset(
            normalized for d in domains if (normalized := normalize_domain(d)) is not None
        )

    @classmethod
    def from_file(cls, path: Path) -> Blocklist:
        """Load a blocklist file; a missing or unreadable file yields an empty list."""
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except FileNotFoundError:
            logger.warning("Blocklist file not found; domain reputation disabled", extra={"path": str(path)})
            return cls()
        except OSError as exc:
            logger.error("Cannot read blocklist file", extra={"path": str(path), "error": str(exc)})
            return cls()
        entries: list[str] = []
        invalid = 0
        for line in lines:
            stripped = line.split("#", 1)[0].strip()
            if not stripped:
                continue
            parsed = parse_blocklist_line(line)
            if parsed is None:
                invalid += 1
            else:
                entries.append(parsed)
        if invalid:
            logger.warning("Ignored invalid blocklist lines", extra={"path": str(path), "invalid": invalid})
        blocklist = cls(entries)
        if not blocklist:
            logger.warning("Blocklist is empty", extra={"path": str(path)})
        else:
            logger.info("Blocklist loaded", extra={"path": str(path), "entries": len(blocklist)})
        return blocklist

    @property
    def domains(self) -> tuple[str, ...]:
        """All normalised entries, sorted (used by demo mode)."""
        return tuple(sorted(self._domains))

    def __len__(self) -> int:
        return len(self._domains)

    def __bool__(self) -> bool:
        return bool(self._domains)

    def __contains__(self, domain: object) -> bool:
        return isinstance(domain, str) and self.match(domain) is not None

    def match(self, domain: str | None) -> str | None:
        if not self._domains or domain is None:
            return None
        normalized = normalize_domain(domain)
        if normalized is None:
            return None
        for candidate in domain_suffixes(normalized):
            if candidate in self._domains:
                return candidate
        return None
