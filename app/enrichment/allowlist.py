"""Owner-maintained allowlist: domains and devices that should not be flagged.

File format (``config/allowlist.txt``, optional; ``#`` starts a comment)::

    cdn.example.com          # a domain: matches it and every subdomain (like the blocklist)
    192.168.1.20             # a device (source IP address)
    192.168.1.64/28          # a range of devices (CIDR)

Policy (applied by the risk engine, see :func:`app.risk.engine.apply_allowlist`):

* an event whose **domain** is allowlisted has none of its indicators counted — the owner
  vouched for that exact name, which also overrides a blocklist entry covering it;
* an event from an allowlisted **device** has its behavioural indicators ignored, but a
  **blocklist hit still counts**: trusting a device's habits must not hide contact with
  known-bad domains (e.g. if that device is compromised).

Nothing is hidden: the event keeps a 0-point ``ALLOWLISTED`` reason naming the entry
and every indicator that was not counted.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterable
from pathlib import Path

from app.enrichment.blocklist import Blocklist, parse_blocklist_line

logger = logging.getLogger(__name__)

Network = ipaddress.IPv4Network | ipaddress.IPv6Network

BROAD_PREFIX = {4: 24, 6: 64}
"""Ranges wider than this (e.g. a /16) are accepted but logged: they silence many devices."""


def parse_allowlist_line(line: str) -> str | Network | None:
    """A domain (normalised), a network, or ``None`` for blank/invalid/too-broad lines."""
    text = line.split("#", 1)[0].strip()
    if not text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        pass
    domain = parse_blocklist_line(text)
    if domain is None or "." not in domain:
        return None  # a bare label such as "com" would silence a whole top-level domain
    return domain


class Allowlist:
    def __init__(self, domains: Iterable[str] = (), networks: Iterable[Network] = ()) -> None:
        self._domains = Blocklist(domains)  # same normalisation and suffix matching
        self._networks: tuple[Network, ...] = tuple(networks)

    @classmethod
    def from_file(cls, path: Path) -> Allowlist:
        """Load the allowlist; a missing file simply means "nothing allowlisted"."""
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except FileNotFoundError:
            logger.info("No allowlist file; nothing is allowlisted", extra={"path": str(path)})
            return cls()
        except OSError as exc:
            logger.error("Cannot read allowlist file", extra={"path": str(path), "error": str(exc)})
            return cls()
        domains: list[str] = []
        networks: list[Network] = []
        invalid = 0
        for line in lines:
            if not line.split("#", 1)[0].strip():
                continue
            entry = parse_allowlist_line(line)
            if entry is None:
                invalid += 1
            elif isinstance(entry, str):
                domains.append(entry)
            else:
                networks.append(entry)
                if entry.prefixlen < BROAD_PREFIX[entry.version]:
                    logger.warning(
                        "Broad allowlist range: every device in it has its behaviour ignored",
                        extra={"path": str(path), "range": str(entry)},
                    )
        if invalid:
            logger.warning(
                "Ignored invalid allowlist lines (not a domain with a dot, IP address or CIDR range)",
                extra={"path": str(path), "invalid": invalid},
            )
        allowlist = cls(domains, networks)
        logger.info(
            "Allowlist loaded", extra={"path": str(path), "domains": len(allowlist._domains), "devices": len(networks)}
        )
        return allowlist

    def __bool__(self) -> bool:
        return bool(self._domains) or bool(self._networks)

    def match_domain(self, domain: str | None) -> str | None:
        """The allowlist entry covering ``domain``, or ``None``."""
        return self._domains.match(domain)

    def match_device(self, ip: str | None) -> str | None:
        """The allowlist entry (address or range) covering the device ``ip``, or ``None``."""
        if not ip or not self._networks:
            return None
        try:
            address = ipaddress.ip_address(ip.split("%", 1)[0])
        except ValueError:
            return None
        for network in self._networks:
            if address.version == network.version and address in network:
                return str(network.network_address) if network.num_addresses == 1 else str(network)
        return None
