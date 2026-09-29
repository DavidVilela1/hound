"""Real IP → country data: the free DB-IP "IP to Country Lite" database (ADR-029).

* **Format:** a MaxMind DB (``.mmdb``) file, read with ``maxminddb``. Files are named
  ``dbip-country-lite-YYYY-MM.mmdb`` in ``HOUND_GEOIP_DIR`` (default ``data/geoip``); the
  newest valid one is used. Versioned names mean a new file never has to overwrite one
  that is open (Windows refuses that), so updates can be swapped in while running.
* **Updates:** DB-IP publishes a new file monthly. :func:`download_dbip` fetches the current
  month's file (or the previous one early in the month) over HTTPS from
  ``download.db-ip.com`` only, with size limits on the download and on the unpacked file,
  checks that it opens and answers sanity lookups, and only then moves it into place.
  :class:`GeoIpUpdater` does this automatically in the background (hourly check, at most
  one download attempt per six hours) unless ``HOUND_GEOIP_AUTO_UPDATE=false``.
* **Licence:** CC BY 4.0 — the dashboard and README credit "IP Geolocation by DB-IP".
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
import urllib.error
import urllib.request
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import maxminddb

from app import __version__
from app.core.netutils import is_public_address, is_valid_ip

logger = logging.getLogger(__name__)

LOCAL_NETWORK = "LAN"
DOWNLOAD_URL = "https://download.db-ip.com/free/dbip-country-lite-{month}.mmdb.gz"
FILE_NAME = "dbip-country-lite-{month}.mmdb"
FILE_RE = re.compile(r"^dbip-country-lite-(\d{4}-\d{2})\.mmdb$")
ATTRIBUTION = "IP Geolocation by DB-IP"
ATTRIBUTION_URL = "https://db-ip.com"
SANITY_ADDRESSES = ("8.8.8.8", "1.1.1.1")
"""Well-known public resolvers: any real country database has a country for both."""

MAX_DOWNLOAD_BYTES = 64 * 2**20  # the compressed file is ~8 MB
MAX_DATABASE_BYTES = 256 * 2**20  # guards against a decompression bomb
CHUNK = 2**16
DOWNLOAD_TIMEOUT = 60.0
CHECK_EVERY_SECONDS = 3600.0
RETRY_AFTER_SECONDS = 6 * 3600.0
STALE_AFTER_DAYS = 62
"""Older than this (by month label), `doctor` warns: updates have not been arriving."""

UrlOpen = Callable[..., Any]


class GeoIpError(RuntimeError):
    """A geolocation database could not be downloaded, read or trusted."""


@dataclass(frozen=True, slots=True)
class GeoDatabaseInfo:
    path: Path
    month: str  # "YYYY-MM", from the file name
    built: datetime  # from the database's own metadata
    database_type: str


def month_label(day: date) -> str:
    return f"{day.year:04d}-{day.month:02d}"


def previous_month(day: date) -> date:
    return date(day.year - 1, 12, 1) if day.month == 1 else date(day.year, day.month - 1, 1)


def country_code(record: object) -> str | None:
    """ISO code from a DB-IP / GeoLite2-style record, or ``None``."""
    if not isinstance(record, dict):
        return None
    for key in ("country", "registered_country"):
        country = record.get(key)
        if isinstance(country, dict):
            code = country.get("iso_code")
            if isinstance(code, str) and len(code) == 2 and code.isascii() and code.isalpha():
                return code.upper()
    return None


class MmdbGeoLocator:
    """Country lookup in a ``.mmdb`` file; local addresses resolve to ``"LAN"``."""

    def __init__(self, reader: Any, info: GeoDatabaseInfo) -> None:
        self._reader = reader
        self.info = info

    @classmethod
    def open(cls, path: Path) -> MmdbGeoLocator:
        """Open and check a database; raises :class:`GeoIpError` if it is not usable."""
        match = FILE_RE.match(path.name)
        try:
            reader = maxminddb.open_database(str(path))
        except (OSError, ValueError, maxminddb.InvalidDatabaseError) as exc:
            raise GeoIpError(f"{path.name} is not a readable geolocation database ({exc})") from exc
        try:
            metadata = reader.metadata()
            for address in SANITY_ADDRESSES:
                if country_code(reader.get(address)) is None:
                    raise GeoIpError(f"{path.name} has no country for {address}; not a country database?")
        except GeoIpError:
            reader.close()
            raise
        except Exception as exc:  # a damaged file can fail inside the reader in many ways
            reader.close()
            raise GeoIpError(f"{path.name} could not be read ({type(exc).__name__}: {exc})") from exc
        info = GeoDatabaseInfo(
            path=path,
            month=match.group(1) if match else "unknown",
            built=datetime.fromtimestamp(int(metadata.build_epoch), UTC),
            database_type=str(metadata.database_type),
        )
        return cls(reader, info)

    def locate(self, ip: str) -> str | None:
        if not is_valid_ip(ip):
            return None
        if not is_public_address(ip):
            return LOCAL_NETWORK
        try:
            return country_code(self._reader.get(ip))
        except (ValueError, maxminddb.InvalidDatabaseError):
            return None

    def close(self) -> None:
        self._reader.close()


# ------------------------------------------------------------------------------ files
def installed_databases(directory: Path) -> list[Path]:
    """DB-IP files in ``directory``, newest month first (the directory is never created here)."""
    try:
        names = [p for p in directory.iterdir() if p.is_file() and FILE_RE.match(p.name)]
    except OSError:
        return []
    return sorted(names, key=lambda p: p.name, reverse=True)


def remove_older(directory: Path, keep: Path) -> None:
    """Best effort: an older file still open elsewhere (Windows) is left for the next run."""
    for path in installed_databases(directory):
        if path.name < keep.name:
            try:
                path.unlink()
            except OSError:
                logger.debug("Could not remove an old geolocation database yet", extra={"file": path.name})


# ------------------------------------------------------------------------------ download
def download_dbip(directory: Path, today: date, *, urlopen: UrlOpen = urllib.request.urlopen) -> GeoDatabaseInfo:
    """Install this month's DB-IP file (or last month's, if this month's is not out yet)."""
    directory.mkdir(parents=True, exist_ok=True)
    attempts: list[str] = []
    for day in (today, previous_month(today)):
        month = month_label(day)
        target = directory / FILE_NAME.format(month=month)
        if target.exists():
            try:
                locator = MmdbGeoLocator.open(target)
            except GeoIpError:
                target.unlink(missing_ok=True)  # damaged: fetch it again
            else:
                locator.close()
                return locator.info
        url = DOWNLOAD_URL.format(month=month)
        part = target.with_name(target.name + ".part")
        try:
            _fetch(url, part, urlopen)
        except urllib.error.HTTPError as exc:
            part.unlink(missing_ok=True)
            if exc.code == 404:
                attempts.append(f"{month}: not published")
                continue
            raise GeoIpError(f"Download of {url} failed: HTTP {exc.code}") from exc
        except (OSError, zlib.error, GeoIpError) as exc:
            part.unlink(missing_ok=True)
            raise GeoIpError(f"Download of {url} failed: {exc}") from exc
        try:
            locator = MmdbGeoLocator.open(part)
        except GeoIpError:
            part.unlink(missing_ok=True)
            raise
        locator.close()
        os.replace(part, target)
        remove_older(directory, target)
        logger.info("Geolocation database installed", extra={"file": target.name, "source": "DB-IP Lite"})
        return GeoDatabaseInfo(target, month, locator.info.built, locator.info.database_type)
    raise GeoIpError(f"No DB-IP database available ({'; '.join(attempts)})")


def _fetch(url: str, part: Path, urlopen: UrlOpen) -> None:
    """Stream-download and gunzip ``url`` into ``part``, enforcing both size limits."""
    if not url.startswith("https://download.db-ip.com/"):
        raise GeoIpError("refusing to download from anywhere but https://download.db-ip.com/")
    request = urllib.request.Request(url, headers={"User-Agent": f"Hound/{__version__} (home network monitor)"})
    inflater = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)  # gzip framing
    downloaded = written = 0
    logger.info("Downloading geolocation database", extra={"url": url})
    with urlopen(request, timeout=DOWNLOAD_TIMEOUT) as response, part.open("wb") as out:
        while chunk := response.read(CHUNK):
            downloaded += len(chunk)
            if downloaded > MAX_DOWNLOAD_BYTES:
                raise GeoIpError(f"download larger than {MAX_DOWNLOAD_BYTES // 2**20} MB")
            data = inflater.decompress(chunk, MAX_DATABASE_BYTES - written + 1)
            written += len(data)
            if written > MAX_DATABASE_BYTES or inflater.unconsumed_tail:
                raise GeoIpError(f"unpacked file larger than {MAX_DATABASE_BYTES // 2**20} MB")
            out.write(data)
        tail = inflater.flush()
        written += len(tail)
        if written > MAX_DATABASE_BYTES:
            raise GeoIpError(f"unpacked file larger than {MAX_DATABASE_BYTES // 2**20} MB")
        out.write(tail)
    if not inflater.eof:
        raise GeoIpError("download ended early (incomplete file)")


# ------------------------------------------------------------------------------ updater
class GeoIpUpdater:
    """Keeps the newest database loaded: picks up new files, downloads monthly if allowed."""

    def __init__(
        self,
        directory: Path,
        *,
        auto_download: bool,
        loaded: Callable[[], Path | None],
        use: Callable[[MmdbGeoLocator], None],
        download: Callable[[Path, date], GeoDatabaseInfo] = download_dbip,
        today: Callable[[], date] = lambda: datetime.now(UTC).date(),
        check_every: float = CHECK_EVERY_SECONDS,
        retry_after: float = RETRY_AFTER_SECONDS,
    ) -> None:
        self._dir = directory
        self._auto = auto_download
        self._loaded = loaded
        self._use = use
        self._download = download
        self._today = today
        self._check_every = check_every
        self._retry_after = retry_after
        self._last_attempt: float | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_error: str | None = None

    def check(self) -> None:
        newest = next(iter(installed_databases(self._dir)), None)
        current = month_label(self._today())
        outdated = newest is None or FILE_RE.match(newest.name).group(1) < current  # type: ignore[union-attr]
        now = time.monotonic()
        if self._auto and outdated and (self._last_attempt is None or now - self._last_attempt >= self._retry_after):
            self._last_attempt = now
            try:
                self._download(self._dir, self._today())
                self.last_error = None
            except (GeoIpError, OSError) as exc:
                self.last_error = str(exc)
                logger.warning("Geolocation database update failed; will retry later", extra={"error": str(exc)})
        self.refresh_from_disk()

    def refresh_from_disk(self) -> None:
        """Load the newest installed file if it is not the one in use."""
        newest = next(iter(installed_databases(self._dir)), None)
        if newest is not None and newest != self._loaded():
            try:
                self._use(MmdbGeoLocator.open(newest))
            except GeoIpError as exc:
                self.last_error = str(exc)
                logger.error("Geolocation database not usable", extra={"error": str(exc)})

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="hound-geoip", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.check()
            except Exception:
                logger.exception("Geolocation update check failed")
            self._stop.wait(self._check_every)
