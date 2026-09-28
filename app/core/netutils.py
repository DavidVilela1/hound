"""Pure helpers for IP addresses and domain names (no I/O, no third-party deps)."""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter

MAX_DOMAIN_LENGTH = 253
MAX_LABEL_LENGTH = 63
_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def normalize_ip(value: str) -> str:
    """Return the canonical text form of an IPv4/IPv6 address.

    Raises:
        ValueError: if ``value`` is not a valid IP address.
    """
    if not isinstance(value, str):
        raise ValueError("IP address must be a string")
    return str(ipaddress.ip_address(value.strip()))


def is_valid_ip(value: object) -> bool:
    """``True`` if ``value`` is a syntactically valid IPv4/IPv6 address."""
    try:
        normalize_ip(value)  # type: ignore[arg-type]
    except ValueError:
        return False
    return True


def is_local_address(ip: str) -> bool:
    """``True`` for private, loopback, link-local, multicast and unspecified addresses."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    )


def is_public_address(ip: str) -> bool:
    """``True`` for globally routable unicast addresses."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


def normalize_domain(value: str | None) -> str | None:
    """Normalise a domain name for comparison, or return ``None`` if invalid.

    * lower-cases, trims whitespace and the trailing root dot;
    * strips a URL scheme, credentials, port and path (``https://www.x.com/a`` → ``www.x.com``);
    * converts internationalised names to their IDNA (punycode) form;
    * validates label syntax and length limits (RFC 1035, allowing ``_`` for SRV/DMARC).

    ``www.`` is *not* stripped: ``www.example.com`` and ``example.com`` are distinct
    names; parent-domain matching is handled by the blocklist.
    """
    if value is None or not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    text = _SCHEME_RE.sub("", text)
    text = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    if text.count(":") == 1:  # host:port (IPv6 literals are not domains)
        text = text.split(":", 1)[0]
    text = text.rstrip(".").lower()
    if not text:
        return None
    if not text.isascii():
        try:
            text = text.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    if len(text) > MAX_DOMAIN_LENGTH:
        return None
    labels = text.split(".")
    if any(len(label) > MAX_LABEL_LENGTH or not _LABEL_RE.match(label) for label in labels):
        return None
    return text


def domain_suffixes(domain: str) -> list[str]:
    """``a.b.example.com`` → ``['a.b.example.com', 'b.example.com', 'example.com', 'com']``."""
    labels = domain.split(".")
    return [".".join(labels[i:]) for i in range(len(labels))]


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character (0.0 for empty strings)."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())
