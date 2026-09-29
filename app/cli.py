"""Command-line interface.

Commands (``serve`` is the default and may be omitted)::

    python run.py [serve] [--demo | --interface IFACE] [--host H] [--port P] [--no-dashboard]
    python run.py capture --interface IFACE [--api-url URL]
    python run.py interfaces
    python run.py doctor [--interface IFACE]
    python run.py reload [--api-url URL]
    python run.py backup [PATH]
    python run.py restore BACKUP
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from app import __version__
from app.core.config import Settings, load_settings
from app.core.logging_config import configure_logging
from app.core.privileges import is_privileged as _is_privileged

logger = logging.getLogger("hound")

COMMANDS = ("serve", "capture", "interfaces", "doctor", "reload", "backup", "restore", "geo")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hound",
        description="Hound — local home-network monitoring and lightweight security analysis.",
        epilog="Only monitor networks you own or are authorised to monitor.",
    )
    parser.add_argument("--version", action="version", version=f"hound {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="{serve,capture,interfaces,doctor,reload,backup,restore}")

    serve = sub.add_parser("serve", help="Run the API and dashboard (default command).")
    source = serve.add_mutually_exclusive_group()
    source.add_argument("--demo", action="store_true", help="Generate synthetic traffic (no privileges needed).")
    source.add_argument(
        "-i",
        "--interface",
        help="Also capture in-process on this interface (the whole process then needs capture privileges; "
        "prefer the separate 'capture' command).",
    )
    serve.add_argument("--host", help="Bind address (default 127.0.0.1).")
    serve.add_argument("--port", type=int, help="Port (default 8000).")
    serve.add_argument("--no-dashboard", action="store_true", help="Serve the API only.")
    serve.add_argument("--demo-rate", type=float, help="Demo events per second (default 4).")
    serve.add_argument("--log-level", help="DEBUG, INFO, WARNING or ERROR.")

    capture = sub.add_parser(
        "capture", help="Run the privileged capture daemon and forward events to a running Hound server."
    )
    capture.add_argument(
        "-i", "--interface", help="Interface to capture on (default: HOUND_NETWORK_INTERFACE or system default)."
    )
    capture.add_argument("--api-url", help="Hound server URL (default http://127.0.0.1:8000).")
    capture.add_argument("--filter", dest="bpf_filter", help="BPF filter (default from HOUND_BPF_FILTER).")
    capture.add_argument("--log-level", help="DEBUG, INFO, WARNING or ERROR.")

    sub.add_parser("interfaces", help="List network interfaces available for capture.")

    doctor = sub.add_parser(
        "doctor", help="Check this computer's setup (packages, capture driver, port, database) without changing it."
    )
    doctor.add_argument("-i", "--interface", help="Also check that this capture interface exists.")

    reload = sub.add_parser(
        "reload", help="Apply edits to the blocklist, allowlist and risk settings in a running server."
    )
    reload.add_argument("--api-url", help="Hound server URL (default http://127.0.0.1:8000).")

    backup = sub.add_parser("backup", help="Write a consistent copy of the database (safe while Hound runs).")
    backup.add_argument("path", nargs="?", help="Where to write it (default: data/backups/hound-<time>.db).")

    restore = sub.add_parser("restore", help="Replace the database with a backup (Hound must be stopped).")
    restore.add_argument("backup", help="The backup file to restore.")

    geo = sub.add_parser("geo", help="Geolocation database (DB-IP Lite): show it, or download the latest now.")
    geo.add_argument("action", choices=("status", "update"), help="status: what is installed; update: download now.")
    return parser


def normalize_argv(argv: Sequence[str]) -> list[str]:
    """Insert the default ``serve`` command when none is given."""
    args = list(argv)
    if not args or (args[0] not in COMMANDS and args[0] not in ("-h", "--help", "--version")):
        args.insert(0, "serve")
    return args


def cmd_serve(args: argparse.Namespace, settings: Settings) -> int:
    import uvicorn

    from app.api.app import create_app
    from app.database.engine import DatabaseError
    from app.risk.config import RiskConfigError
    from app.services.runtime import HoundRuntime, RunMode

    if not settings.is_loopback_bind:
        logger.warning(
            "Binding to a non-loopback address exposes Hound to your network; the API has no user "
            "authentication. Set HOUND_ALLOWED_HOSTS accordingly.",
            extra={"host": settings.host},
        )
    if args.demo:
        mode = RunMode.DEMO
    elif args.interface or settings.network_interface:
        mode = RunMode.CAPTURE
        if not _is_privileged():
            logger.warning(
                "In-process capture usually needs root/Administrator or CAP_NET_RAW. Consider running "
                "'python run.py' as a normal user and 'sudo python run.py capture -i <iface>' separately."
            )
    else:
        mode = RunMode.IDLE
    try:
        runtime = HoundRuntime(settings, mode, interface=args.interface)
    except RiskConfigError as exc:
        logger.error("Cannot start: %s", exc)
        return 2
    try:
        # Pre-flight before the web server starts, so a refusal (e.g. a database from a newer
        # Hound) is one clear log line instead of a framework traceback.
        runtime.database.initialize()
    except DatabaseError as exc:
        logger.error("Cannot start: %s", exc)
        return 2
    dashboard = settings.enable_dashboard and not args.no_dashboard
    app = create_app(settings, runtime, dashboard=dashboard)
    logger.info(
        "Starting Hound",
        extra={"url": settings.api_base_url, "mode": mode.value, "dashboard": dashboard, "docs": "/docs"},
    )
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_config=None,
        access_log=False,
    )
    return 0


def cmd_capture(args: argparse.Namespace, settings: Settings) -> int:
    from app.core.security import read_ingest_token
    from app.ingestion.daemon import CaptureDaemon

    token = read_ingest_token(settings)
    if not token:
        logger.error(
            "No ingest token found. Start the Hound server first (it creates %s) or set HOUND_INGEST_TOKEN "
            "for both processes.",
            settings.resolve_path(settings.ingest_token_path),
        )
        return 2
    api_url = args.api_url or settings.api_base_url
    daemon = CaptureDaemon(
        settings, interface=args.interface or settings.network_interface, api_url=api_url, token=token
    )
    logger.info("Starting capture daemon", extra={"api_url": api_url})
    return daemon.run()


def cmd_interfaces() -> int:
    from app.ingestion.capture import default_interface, list_interfaces

    default = default_interface()
    print(f"{'NAME':<24} {'IPv4':<16} {'MAC':<18} DESCRIPTION")
    for info in list_interfaces():
        marker = " (default)" if info.name == default else ""
        print(f"{info.name:<24} {info.ipv4 or '-':<16} {info.mac or '-':<18} {info.description}{marker}")
    return 0


def cmd_doctor(args: argparse.Namespace, settings: Settings) -> int:
    from app.services.doctor import exit_code, render, run_checks

    logging.disable(logging.INFO)  # the report is the output; only warnings/errors from the checks
    try:
        checks = run_checks(settings, interface=args.interface)
    finally:
        logging.disable(logging.NOTSET)
    print(render(checks))
    return exit_code(checks)


def cmd_reload(args: argparse.Namespace, settings: Settings) -> int:
    """Ask the running server to re-read its detection settings (token-authenticated)."""
    import json
    import urllib.error
    import urllib.request

    from app.core.security import TOKEN_HEADER, read_ingest_token
    from app.ingestion.forwarder import DIRECT_OPENER

    token = read_ingest_token(settings)
    if not token:
        print(
            f"No token found ({settings.resolve_path(settings.ingest_token_path)}). Start the server first, "
            "or set HOUND_INGEST_TOKEN to the server's value.",
            file=sys.stderr,
        )
        return 2
    url = (args.api_url or settings.api_base_url).rstrip("/") + "/api/admin/reload"
    request = urllib.request.Request(url, data=b"", method="POST", headers={TOKEN_HEADER: token})
    try:
        with DIRECT_OPENER.open(request, timeout=15) as response:
            result = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read()).get("detail", "")
        except (ValueError, AttributeError):
            detail = ""
        print(f"Reload refused (HTTP {exc.code}): {detail}", file=sys.stderr)
        return 1 if exc.code == 400 else 2
    except (urllib.error.URLError, OSError) as exc:
        print(f"Cannot reach Hound at {url}: {exc}. Is the server running?", file=sys.stderr)
        return 2
    overridden = result.get("risk_overridden_by_environment") or []
    print(
        "Reloaded: "
        f"{result['blocklist_entries']} blocklist entries, "
        f"allowlist {result['allowlist_domains']} domain(s) + {result['allowlist_devices']} device(s), "
        f"{result['risk_values_from_file']} risk setting(s) from the file"
        + (f"; overridden by environment: {', '.join(overridden)}" if overridden else "")
        + ("; behaviour windows restarted (window length changed)" if result.get("behaviour_windows_reset") else "")
        + (f"; geolocation: {result['geolocation']}" if result.get("geolocation") else "")
        + "."
    )
    return 0


def _database_file(settings: Settings) -> Path | None:
    from app.database.inspect import sqlite_path

    path = sqlite_path(settings)
    if path is None:
        print("Backup and restore work with a local SQLite database only.", file=sys.stderr)
    return path


def cmd_backup(args: argparse.Namespace, settings: Settings) -> int:
    from app.database.backup import BackupError, create_backup, default_backup_path

    database = _database_file(settings)
    if database is None:
        return 2
    target = Path(args.path).expanduser() if args.path else default_backup_path(database, datetime.now(UTC))
    try:
        result = create_backup(database, target.resolve())
    except BackupError as exc:
        print(f"Backup failed: {exc}", file=sys.stderr)
        return 2
    print(
        f"Backup written: {result.path} ({result.size_bytes / 2**20:.1f} MiB, "
        f"{result.info.events or 0:,} events, schema v{result.info.version}, integrity ok, {result.seconds} s)"
    )
    return 0


def cmd_geo(args: argparse.Namespace, settings: Settings) -> int:
    from app.enrichment.geoip import ATTRIBUTION, GeoIpError, MmdbGeoLocator, download_dbip, installed_databases

    directory = settings.resolve_path(settings.geoip_dir)
    if args.action == "update":
        print("Downloading the DB-IP Lite country database from download.db-ip.com ...")
        try:
            info = download_dbip(directory, datetime.now(UTC).date())
        except GeoIpError as exc:
            print(f"Update failed: {exc}", file=sys.stderr)
            return 2
        print(f"Installed {info.path} (DB-IP Lite {info.month}, built {info.built:%Y-%m-%d}).")
        print("A running server switches to it within an hour, or at once with: python run.py reload")
        print(f"Data licence: CC BY 4.0 - {ATTRIBUTION} (https://db-ip.com)")
        return 0
    installed = installed_databases(directory)
    if not installed:
        mode = "Hound downloads it at start" if settings.geoip_auto_update else "automatic download is off"
        print(f"No geolocation database in {directory} ({mode}). Get it now: python run.py geo update")
        return 1
    try:
        locator = MmdbGeoLocator.open(installed[0])
    except GeoIpError as exc:
        print(f"{installed[0]} is not usable: {exc}. Run: python run.py geo update", file=sys.stderr)
        return 2
    locator.close()
    info = locator.info
    print(f"{info.path} - DB-IP Lite {info.month}, built {info.built:%Y-%m-%d} ({info.database_type})")
    print(f"Automatic monthly update: {'on' if settings.geoip_auto_update else 'off'}; mode: {settings.geo_mode}")
    return 0


def cmd_restore(args: argparse.Namespace, settings: Settings) -> int:
    from app.database.backup import BackupError, restore_backup
    from app.services.doctor import probe_hound

    database = _database_file(settings)
    if database is None:
        return 2
    if probe_hound(settings.api_base_url):
        print(
            f"Hound is running at {settings.api_base_url}. Stop the server (and the capture daemon) first, "
            "then run restore again.",
            file=sys.stderr,
        )
        return 2
    try:
        result = restore_backup(Path(args.backup).expanduser().resolve(), database, datetime.now(UTC))
    except BackupError as exc:
        print(f"Restore refused: {exc}", file=sys.stderr)
        return 2
    kept = f" The previous database was kept as {result.previous_saved_as}." if result.previous_saved_as else ""
    print(
        f"Restored {result.database} from {result.restored_from} "
        f"({result.info.events or 0:,} events, schema v{result.info.version}).{kept} Start Hound as usual."
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(normalize_argv(sys.argv[1:] if argv is None else argv))
    overrides: dict[str, object] = {"log_level": getattr(args, "log_level", None)}
    if args.command == "serve":
        overrides.update(host=args.host, port=args.port, demo_events_per_second=args.demo_rate)
    elif args.command == "capture":
        overrides.update(bpf_filter=args.bpf_filter)
    try:
        settings = load_settings(**overrides)
    except ValidationError as exc:
        print(f"Invalid configuration:\n{exc}", file=sys.stderr)
        return 2
    configure_logging(settings.log_level, settings.log_format)

    try:
        if args.command == "capture":
            return cmd_capture(args, settings)
        if args.command == "interfaces":
            return cmd_interfaces()
        if args.command == "doctor":
            return cmd_doctor(args, settings)
        if args.command == "reload":
            return cmd_reload(args, settings)
        if args.command == "backup":
            return cmd_backup(args, settings)
        if args.command == "restore":
            return cmd_restore(args, settings)
        if args.command == "geo":
            return cmd_geo(args, settings)
        return cmd_serve(args, settings)
    except KeyboardInterrupt:
        return 130
