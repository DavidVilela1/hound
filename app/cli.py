"""Command-line interface.

Commands (``serve`` is the default and may be omitted)::

    python run.py [serve] [--demo | --interface IFACE] [--host H] [--port P] [--no-dashboard]
    python run.py capture --interface IFACE [--api-url URL]
    python run.py interfaces
    python run.py doctor [--interface IFACE]
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from pydantic import ValidationError

from app import __version__
from app.core.config import Settings, load_settings
from app.core.logging_config import configure_logging
from app.core.privileges import is_privileged as _is_privileged

logger = logging.getLogger("hound")

COMMANDS = ("serve", "capture", "interfaces", "doctor")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hound",
        description="Hound — local home-network monitoring and lightweight security analysis.",
        epilog="Only monitor networks you own or are authorised to monitor.",
    )
    parser.add_argument("--version", action="version", version=f"hound {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="{serve,capture,interfaces,doctor}")

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
        return cmd_serve(args, settings)
    except KeyboardInterrupt:
        return 130
