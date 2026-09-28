"""``hound doctor``: a read-only check of everything Hound needs from its environment.

Each check returns one :class:`Check` with a status and, for anything that is not OK,
the concrete next step. Nothing here creates or modifies files, databases or tokens:
the database is opened read-only (``immutable`` when no WAL file exists, so SQLite
does not create ``-wal``/``-shm`` files either), and the port check only binds and
releases a socket.

The checks take their inputs as parameters where that makes them testable on any OS
(e.g. the Windows capture-driver check runs in the Linux test suite).
"""

from __future__ import annotations

import ctypes.util
import importlib.metadata
import json
import os
import re
import socket
import sqlite3
import stat
import sys
import urllib.error
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from urllib.parse import quote

from sqlalchemy.engine import make_url

from app import __version__
from app.core.config import PROJECT_ROOT, Settings
from app.core.privileges import is_privileged
from app.core.security import MIN_TOKEN_LENGTH

MIN_PYTHON = (3, 11)
NPCAP_URL = "https://npcap.com"
CLOUD_SYNC_MARKERS = ("onedrive", "dropbox", "icloud drive", "mobile documents", "google drive", "googledrive")
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")
_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")


class Status(StrEnum):
    OK = "ok"
    INFO = "info"
    WARN = "warn"
    FAIL = "fail"


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    status: Status
    detail: str
    fix: str | None = None


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# ------------------------------------------------------------------------------ interpreter & packages
def check_python(version: tuple[int, int, int] | None = None) -> Check:
    version = version or (sys.version_info.major, sys.version_info.minor, sys.version_info.micro)
    shown = ".".join(str(part) for part in version)
    if version[:2] >= MIN_PYTHON:
        return Check("Python", Status.OK, f"{shown} (3.11 or newer required)")
    return Check("Python", Status.FAIL, f"{shown} is too old", "Install Python 3.11 or newer and recreate the venv.")


def _installed_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def check_dependencies(
    requirements: Path = PROJECT_ROOT / "requirements.txt",
    lock: Path = PROJECT_ROOT / "requirements.lock",
    installed: Callable[[str], str | None] = _installed_version,
) -> Check:
    """Direct dependencies installed, at the versions ``requirements.lock`` pins."""
    if not requirements.is_file() or not lock.is_file():
        return Check("Packages", Status.INFO, "requirements files not found (not a source checkout); skipped")
    pins = {
        _canonical(m.group(1)): m.group(2)
        for line in lock.read_text(encoding="utf-8").splitlines()
        if (m := _PIN.match(line))
    }
    names = [
        m.group(1)
        for raw in requirements.read_text(encoding="utf-8").splitlines()
        if (m := _NAME.match(raw.split("#", 1)[0].strip()))
    ]
    missing = [name for name in names if installed(name) is None]
    if missing:
        return Check(
            "Packages",
            Status.FAIL,
            f"not installed: {', '.join(missing)}",
            "Activate the project's venv, then: pip install -r requirements.lock",
        )
    differing = [
        f"{name} {installed(name)} (lock: {pins[_canonical(name)]})"
        for name in names
        if _canonical(name) in pins and installed(name) != pins[_canonical(name)]
    ]
    if differing:
        return Check(
            "Packages",
            Status.WARN,
            f"versions differ from requirements.lock: {'; '.join(differing)}",
            "pip install -r requirements.lock  (installs the tested versions)",
        )
    return Check("Packages", Status.OK, f"all {len(names)} direct dependencies match requirements.lock")


# ------------------------------------------------------------------------------ capture prerequisites
def _scapy_pcap_flags() -> tuple[bool, bool]:
    from scapy.config import conf  # imported lazily: Scapy detects the capture driver on import

    return bool(conf.use_pcap), bool(getattr(conf, "use_npcap", False))


def check_capture_library(
    platform: str = sys.platform,
    pcap_flags: Callable[[], tuple[bool, bool]] = _scapy_pcap_flags,
    find_library: Callable[[str], str | None] = ctypes.util.find_library,
) -> Check:
    name = "Capture driver"
    if platform == "win32":
        use_pcap, use_npcap = pcap_flags()
        if use_npcap:
            return Check(name, Status.OK, "Npcap found")
        if use_pcap:
            return Check(
                name,
                Status.WARN,
                "legacy WinPcap found instead of Npcap",
                f"Uninstall WinPcap, install Npcap ({NPCAP_URL}).",
            )
        return Check(
            name,
            Status.WARN,
            "Npcap not found: live capture is unavailable (demo mode still works)",
            f"Install Npcap from {NPCAP_URL} with the default options, then open a new terminal.",
        )
    library = find_library("pcap")
    if library:
        return Check(name, Status.OK, f"libpcap found ({library})")
    if platform == "darwin":
        return Check(
            name,
            Status.WARN,
            "libpcap not found (it normally ships with macOS)",
            "Reinstall the Xcode command line tools.",
        )
    return Check(
        name,
        Status.WARN,
        "libpcap not found: capture works with the default filter only (filtered in Python, more CPU); "
        "a custom --filter fails",
        "Install libpcap, e.g. 'sudo apt install libpcap0.8' (Debian/Ubuntu) or your distribution's package.",
    )


def check_privileges(privileged: bool, platform: str = sys.platform) -> Check:
    admin = "Administrator" if platform == "win32" else "root"
    if privileged:
        return Check(
            "Privileges",
            Status.INFO,
            f"running as {admin}: fine for the capture daemon; run the server ('python run.py') as a normal user",
        )
    how = (
        "a PowerShell opened with 'Run as administrator'"
        if platform == "win32"
        else "sudo, or grant CAP_NET_RAW (README: Privileges)"
    )
    return Check(
        "Privileges",
        Status.INFO,
        f"not {admin}: fine for the server and demo mode; live capture ('capture' command) needs {how}",
    )


def check_interface(requested: str | None, interfaces: Sequence[object], default: str | None) -> Check:
    """``interfaces`` are :class:`app.ingestion.capture.InterfaceInfo` objects."""
    names = [str(getattr(info, "name", "")) for info in interfaces]
    if requested:
        for info in interfaces:
            if requested in (
                getattr(info, "name", None),
                getattr(info, "description", None),
                getattr(info, "network_name", None),
            ):
                ipv4 = getattr(info, "ipv4", None) or "no IPv4"
                return Check("Interface", Status.OK, f"{requested!r} found ({getattr(info, 'name', '')}, {ipv4})")
        return Check(
            "Interface",
            Status.FAIL,
            f"{requested!r} not found; available: {', '.join(names) or 'none'}",
            "Use a name from 'python run.py interfaces' (on Windows the NAME column, e.g. \"Wi-Fi\").",
        )
    if not interfaces:
        return Check(
            "Interface",
            Status.WARN,
            "no capture interfaces visible",
            "Check the capture driver above; then 'python run.py interfaces'.",
        )
    return Check(
        "Interface", Status.INFO, f"{len(interfaces)} available; default: {default or 'none'} (use -i to check one)"
    )


# ------------------------------------------------------------------------------ server prerequisites
def check_bind_address(settings: Settings) -> Check:
    if settings.is_loopback_bind:
        return Check("Bind address", Status.OK, f"{settings.host} (this computer only)")
    return Check(
        "Bind address",
        Status.WARN,
        f"{settings.host} exposes the unauthenticated API and dashboard to your network",
        "Unless you need remote access, set HOUND_HOST=127.0.0.1.",
    )


def _probe_hound(url: str) -> str | None:
    """Version reported by a Hound server at ``url``, or ``None`` if something else answers."""
    from app.ingestion.forwarder import DIRECT_OPENER  # proxy-free: always talks to the local server

    try:
        with DIRECT_OPENER.open(url.rstrip("/") + "/health", timeout=2) as response:
            payload = json.loads(response.read(65536))
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read(65536))
        except ValueError:
            return None
    except (OSError, ValueError):
        return None
    if isinstance(payload, dict) and isinstance(payload.get("version"), str) and "pipeline" in payload:
        return str(payload["version"])
    return None


def check_port(settings: Settings, probe: Callable[[str], str | None] = _probe_hound) -> Check:
    name = f"Port {settings.port}"
    try:
        infos = socket.getaddrinfo(settings.host, settings.port, type=socket.SOCK_STREAM)
    except OSError as exc:
        return Check(name, Status.FAIL, f"cannot resolve host {settings.host!r}: {exc}", "Check HOUND_HOST.")
    family, _, _, _, address = infos[0]
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        if sys.platform != "win32":  # mirrors uvicorn; on Windows this flag would allow port stealing
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(address)
        except OSError:
            in_use = True
        else:
            in_use = False
    if not in_use:
        return Check(name, Status.OK, f"free on {settings.host} (no server running; the capture daemon needs one)")
    version = probe(settings.api_base_url)
    if version:
        return Check(name, Status.OK, f"Hound {version} is running at {settings.api_base_url}")
    return Check(
        name,
        Status.FAIL,
        f"in use by another program on {settings.host}",
        "Stop that program, or start Hound on another port: python run.py --port 8001 (and --api-url for capture).",
    )


def _sqlite_path(settings: Settings) -> Path | None:
    url = make_url(settings.resolved_database_url)
    if url.get_backend_name() != "sqlite" or not url.database or url.database == ":memory:":
        return None
    return Path(url.database)


def check_storage_location(settings: Settings) -> Check:
    paths = [p for p in (_sqlite_path(settings), settings.resolve_path(settings.ingest_token_path)) if p is not None]
    synced = sorted({str(p.parent) for p in paths if any(m in str(p).lower() for m in CLOUD_SYNC_MARKERS)})
    if synced:
        return Check(
            "Data location",
            Status.WARN,
            f"inside a cloud-synced folder ({'; '.join(synced)}): the database and ingest token are uploaded, "
            "and sync can lock SQLite",
            "Point HOUND_DATABASE_URL and HOUND_INGEST_TOKEN_PATH at an unsynced folder (README: Troubleshooting).",
        )
    shown = paths[0].parent if paths else "(no local database)"
    return Check("Data location", Status.OK, f"{shown} (not a cloud-synced folder)")


def _existing_ancestor(path: Path) -> Path:
    for candidate in (path, *path.parents):
        if candidate.exists():
            return candidate
    return path


def _open_read_only(path: Path) -> sqlite3.Connection:
    # Without a WAL file the database is fully checkpointed: `immutable` then reads it without
    # creating -wal/-shm files. With a WAL file present (server running or unclean stop),
    # plain read-only mode is needed to see the latest committed state.
    wal_present = Path(f"{path}-wal").exists()
    options = "mode=ro" if wal_present else "mode=ro&immutable=1"
    # Canonical SQLite URI: file:///home/u/hound.db (POSIX), file:///C:/Users/u/hound.db (Windows).
    location = quote(path.as_posix(), safe="/:").lstrip("/")
    return sqlite3.connect(f"file:///{location}?{options}", uri=True)


def check_database(settings: Settings) -> Check:
    from app.database.migrations import baseline_fingerprint, latest_version, schema_fingerprint

    path = _sqlite_path(settings)
    if path is None:
        return Check("Database", Status.INFO, "not a local SQLite file; not checked")
    if not path.exists():
        parent = _existing_ancestor(path.parent)
        if parent.is_dir() and _writable(parent):
            return Check("Database", Status.OK, f"{path} will be created on first start")
        return Check(
            "Database",
            Status.FAIL,
            f"cannot create {path}: {parent} is not writable",
            "Fix the folder permissions or set HOUND_DATABASE_URL.",
        )
    target = latest_version()
    try:
        connection = _open_read_only(path)
        try:
            cursor = connection.cursor()
            version = int(cursor.execute("PRAGMA user_version").fetchone()[0])
            has_tables = cursor.execute(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            ).fetchone()[0]
            legacy_matches = version == 0 and has_tables and schema_fingerprint(cursor) == baseline_fingerprint()
        finally:
            connection.close()
    except sqlite3.DatabaseError as exc:
        return Check(
            "Database",
            Status.FAIL,
            f"{path} cannot be read as a Hound database ({exc})",
            "Move the file away or set HOUND_DATABASE_URL.",
        )
    if not _writable(path) or not _writable(path.parent):
        writable_fix = "Run the server as the user that owns the data folder, or fix its permissions."
        return Check("Database", Status.FAIL, f"{path} (schema v{version}) is not writable by this user", writable_fix)
    if version > target:
        return Check(
            "Database",
            Status.FAIL,
            f"schema v{version} was written by a newer Hound (this one supports v{target})",
            "Use the newer Hound, or start fresh with another HOUND_DATABASE_URL (README: Database and upgrades).",
        )
    if version == 0 and has_tables:
        if legacy_matches:
            return Check("Database", Status.INFO, f"{path}: from an earlier build; will be adopted as v1 on start")
        return Check(
            "Database",
            Status.FAIL,
            f"{path} contains tables that are not a Hound database",
            "Move the file away or set HOUND_DATABASE_URL.",
        )
    if version < target:
        return Check("Database", Status.INFO, f"{path}: schema v{version}; will be upgraded to v{target} on start")
    return Check("Database", Status.OK, f"{path} (schema v{version}, current)")


def _writable(path: Path) -> bool:
    return os.access(path, os.W_OK)


def check_ingest_token(settings: Settings, platform: str = sys.platform) -> Check:
    if settings.ingest_token is not None:
        if len(settings.ingest_token.get_secret_value().strip()) >= MIN_TOKEN_LENGTH:
            return Check("Ingest token", Status.OK, "set via HOUND_INGEST_TOKEN")
        return Check(
            "Ingest token",
            Status.FAIL,
            f"HOUND_INGEST_TOKEN is shorter than {MIN_TOKEN_LENGTH} characters",
            'Use a long random value, e.g. python -c "import secrets; print(secrets.token_urlsafe(32))"',
        )
    path = settings.resolve_path(settings.ingest_token_path)
    if not path.exists():
        return Check("Ingest token", Status.INFO, f"{path} does not exist yet; the server creates it on first start")
    try:
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        return Check(
            "Ingest token",
            Status.WARN,
            f"{path} is not readable by this user ({exc.strerror})",
            "Run the capture daemon with the same account that can read the token file, or use HOUND_INGEST_TOKEN.",
        )
    if len(token) < MIN_TOKEN_LENGTH:
        return Check(
            "Ingest token",
            Status.WARN,
            f"{path} holds a token that is too short",
            "Delete it; the server writes a new one.",
        )
    if platform != "win32" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        return Check("Ingest token", Status.WARN, f"{path} is readable by other users", f"chmod 600 {path}")
    return Check("Ingest token", Status.OK, f"{path}")


def check_risk_settings(settings: Settings) -> Check:
    """The risk settings file parses and combines with the environment into a valid config."""
    from app.risk.config import RiskConfig, RiskConfigError, explicit_environment, load_risk_file

    path = settings.resolve_path(settings.risk_config_path)
    try:
        values = load_risk_file(path)
        RiskConfig.from_settings(settings)
    except RiskConfigError as exc:
        return Check("Risk settings", Status.FAIL, str(exc), f"Fix {path.name} (or rename it to use the defaults).")
    count = len(values) - ("weights" in values) + len(values.get("weights", {}))
    detail = f"{path.name}: {count} value(s) changed from the defaults" if count else "built-in defaults"
    overridden = sorted(explicit_environment(settings))
    if overridden:
        return Check(
            "Risk settings",
            Status.INFO,
            f"{detail}; overridden by environment/.env: {', '.join(overridden)}",
        )
    return Check("Risk settings", Status.OK, detail)


# ------------------------------------------------------------------------------ orchestration
def run_checks(settings: Settings, interface: str | None = None) -> list[Check]:
    from app.ingestion.capture import default_interface, list_interfaces

    requested = interface or settings.network_interface
    return [
        check_python(),
        check_dependencies(),
        check_capture_library(),
        check_privileges(is_privileged()),
        check_interface(requested, list_interfaces(), default_interface()),
        check_bind_address(settings),
        check_port(settings),
        check_storage_location(settings),
        check_database(settings),
        check_ingest_token(settings),
        check_risk_settings(settings),
    ]


_LABEL = {Status.OK: "[ OK ]", Status.INFO: "[INFO]", Status.WARN: "[WARN]", Status.FAIL: "[FAIL]"}


def render(checks: Sequence[Check]) -> str:
    """Plain-text report; labels and arrows are ASCII so they print on any console."""
    width = max(len(check.name) for check in checks)
    lines = [f"Hound {__version__} environment check (Python {sys.version.split()[0]}, {sys.platform})", ""]
    for check in checks:
        lines.append(f"{_LABEL[check.status]} {check.name:<{width}}  {check.detail}")
        if check.fix and check.status in (Status.WARN, Status.FAIL):
            lines.append(f"{'':6} {'':<{width}}  -> {check.fix}")
    failures = sum(check.status is Status.FAIL for check in checks)
    warnings = sum(check.status is Status.WARN for check in checks)
    lines += ["", f"{failures} problem(s), {warnings} warning(s)."]
    return "\n".join(lines)


def exit_code(checks: Sequence[Check]) -> int:
    return 1 if any(check.status is Status.FAIL for check in checks) else 0
