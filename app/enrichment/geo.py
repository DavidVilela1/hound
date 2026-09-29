"""IP → country resolution behind a small, replaceable interface.

Real data comes from the DB-IP Lite database (:mod:`app.enrichment.geoip`, ADR-029).
:func:`select_geolocator` picks the source from ``HOUND_GEO_MODE``:

* ``auto`` (default) / ``dbip``: the newest installed DB-IP file. Without one, live modes
  report countries as unknown — never invented — and demo mode (``auto`` only) falls
  back to the simulation.
* ``simulated``: an illustrative CIDR table (``config/geo_ranges.csv``) plus a
  deterministic hash — **not authoritative**, for demos and tests.
* ``mapping_only``: the illustrative table alone.
"""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol

from app.core.netutils import is_public_address, is_valid_ip
from app.enrichment.countries import ISO_COUNTRY_NAMES
from app.enrichment.geoip import LOCAL_NETWORK, GeoDatabaseInfo, GeoIpError, MmdbGeoLocator, installed_databases

if TYPE_CHECKING:
    from app.core.config import Settings

logger = logging.getLogger(__name__)

UNKNOWN = "UNKNOWN"

COUNTRY_NAMES: dict[str, str] = {
    LOCAL_NETWORK: "Local network",
    UNKNOWN: "Unknown",
    "AU": "Australia",
    "BR": "Brazil",
    "CA": "Canada",
    "CH": "Switzerland",
    "CN": "China",
    "DE": "Germany",
    "ES": "Spain",
    "FI": "Finland",
    "FR": "France",
    "GB": "United Kingdom",
    "IE": "Ireland",
    "IN": "India",
    "IT": "Italy",
    "JP": "Japan",
    "KR": "South Korea",
    "NL": "Netherlands",
    "PL": "Poland",
    "PT": "Portugal",
    "RU": "Russia",
    "SE": "Sweden",
    "SG": "Singapore",
    "US": "United States",
    "ZA": "South Africa",
}

# Weighted pool for the deterministic fallback (roughly "typical" home-traffic mix).
_SIMULATED_POOL: tuple[str, ...] = (
    ("US",) * 10
    + ("DE",) * 3
    + ("NL",) * 3
    + ("IE",) * 2
    + ("GB",) * 2
    + ("FR",) * 2
    + ("PT",) * 2
    + ("SG",)
    + ("JP",)
    + ("CA",)
    + ("SE",)
    + ("BR",)
    + ("CN",)
    + ("RU",)
)

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def country_name(code: str | None) -> str:
    if not code:
        return COUNTRY_NAMES[UNKNOWN]
    return COUNTRY_NAMES.get(code) or ISO_COUNTRY_NAMES.get(code, code)


class GeoLocator(Protocol):
    """Resolve an IP address to a country code (or ``None`` if unknown)."""

    def locate(self, ip: str) -> str | None: ...


def load_ranges(path: Path) -> list[tuple[Network, str]]:
    """Read ``cidr,country`` rows; comments (``#``) and invalid rows are skipped."""
    ranges: list[tuple[Network, str]] = []
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            rows: Iterable[list[str]] = csv.reader(line for line in handle if not line.lstrip().startswith("#"))
            for row in rows:
                if len(row) < 2:
                    continue
                cidr, code = row[0].strip(), row[1].strip().upper()
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    logger.warning("Skipping invalid geo range", extra={"cidr": cidr})
                    continue
                if not code.isalpha() or not 2 <= len(code) <= 8:
                    logger.warning("Skipping invalid geo country code", extra={"code": code})
                    continue
                ranges.append((network, code))
    except FileNotFoundError:
        logger.warning("Geo range file not found", extra={"path": str(path)})
    except OSError as exc:
        logger.error("Cannot read geo range file", extra={"path": str(path), "error": str(exc)})
    # Most specific prefix first so nested ranges resolve correctly.
    ranges.sort(key=lambda item: item[0].prefixlen, reverse=True)
    return ranges


class StaticRangeGeoLocator:
    """Longest-prefix lookup over a CIDR → country table.

    Non-global addresses (RFC 1918, loopback, link-local, multicast…) resolve
    to ``"LAN"``. Suitable for tables up to a few thousand rows.
    """

    def __init__(self, ranges: Iterable[tuple[Network, str]]) -> None:
        self._ranges = sorted(ranges, key=lambda item: item[0].prefixlen, reverse=True)

    def locate(self, ip: str) -> str | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if not is_public_address(ip):
            return LOCAL_NETWORK
        for network, code in self._ranges:
            if addr.version == network.version and addr in network:
                return code
        return None


class SimulatedGeoLocator:
    """Static table first, then a deterministic hash of the address's /16 (/48 for IPv6).

    The same IP always maps to the same simulated country, which keeps demos
    and tests reproducible.
    """

    def __init__(self, static: StaticRangeGeoLocator, pool: tuple[str, ...] = _SIMULATED_POOL) -> None:
        self._static = static
        self._pool = pool

    def locate(self, ip: str) -> str | None:
        code = self._static.locate(ip)
        if code is not None:
            return code
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        prefix = 16 if addr.version == 4 else 48
        network = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
        digest = hashlib.blake2b(network.network_address.packed, digest_size=4).digest()
        return self._pool[int.from_bytes(digest, "big") % len(self._pool)]


class LocalOnlyGeoLocator:
    """No database: local addresses are ``"LAN"``, everything else unknown."""

    def locate(self, ip: str) -> str | None:
        if not is_valid_ip(ip):
            return None
        return None if is_public_address(ip) else LOCAL_NETWORK


GeoSource = Literal["dbip", "simulated", "mapping", "none"]


@dataclass(frozen=True, slots=True)
class GeoSelection:
    locator: GeoLocator
    source: GeoSource
    database: GeoDatabaseInfo | None = None


def select_geolocator(settings: Settings, *, demo: bool) -> GeoSelection:
    """The geolocator for this run (the runtime may swap in newer DB-IP files later)."""
    ranges = settings.resolve_path(settings.geo_ranges_path)
    if settings.geo_mode == "simulated":
        return GeoSelection(build_geolocator("simulated", ranges), "simulated")
    if settings.geo_mode == "mapping_only":
        return GeoSelection(build_geolocator("mapping_only", ranges), "mapping")
    for path in installed_databases(settings.resolve_path(settings.geoip_dir)):
        try:
            locator = MmdbGeoLocator.open(path)
        except GeoIpError as exc:
            logger.error("Skipping unusable geolocation database", extra={"error": str(exc)})
            continue
        logger.info("Geolocation database loaded", extra={"file": path.name, "source": "DB-IP Lite"})
        return GeoSelection(locator, "dbip", locator.info)
    if demo and settings.geo_mode == "auto":
        return GeoSelection(build_geolocator("simulated", ranges), "simulated")
    return GeoSelection(LocalOnlyGeoLocator(), "none")


def build_geolocator(mode: str, ranges_path: Path) -> GeoLocator:
    """Illustrative locators (``simulated`` / ``mapping_only``) from the CIDR table."""
    static = StaticRangeGeoLocator(load_ranges(ranges_path))
    if mode == "mapping_only":
        return static
    return SimulatedGeoLocator(static)
