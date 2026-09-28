"""Real-time packet capture with Scapy.

Threading model::

    Scapy AsyncSniffer thread ──prn──▶ PacketParser ──▶ sink (EventQueue.offer, non-blocking)

The Scapy callback does only parsing and a non-blocking enqueue; database work
happens elsewhere, so a slow consumer cannot stall capture. A lightweight
supervisor thread watches the sniffer and records failures (e.g. an interface
going away) so they are visible in ``/health`` instead of dying silently.
"""

from __future__ import annotations

import errno
import hashlib
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass

from scapy.config import conf
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer

from app.core.config import DEFAULT_BPF_FILTER
from app.ingestion.parser import PacketParser
from app.ingestion.sources import EventSink, SourceStateName, SourceStatus

logger = logging.getLogger(__name__)

TCP_FLAG_SYN = 0x02


class CaptureError(RuntimeError):
    """Packet capture could not be started or failed irrecoverably."""


@dataclass(frozen=True, slots=True)
class InterfaceInfo:
    """One capture interface.

    ``name`` is what ``--interface`` expects: the kernel name on Linux/macOS
    (``eth0``, ``en0``) and the friendly name on Windows (``Wi-Fi``).
    ``network_name`` is the OS-level device name, which differs only on Windows
    (``\\Device\\NPF_{GUID}``).
    """

    name: str
    description: str
    ipv4: str | None
    mac: str | None
    network_name: str | None = None


def list_interfaces() -> list[InterfaceInfo]:
    """Interfaces Scapy can see (names are what ``--interface`` expects)."""
    result: list[InterfaceInfo] = []
    for iface in conf.ifaces.values():
        result.append(
            InterfaceInfo(
                name=str(iface.name),
                description=str(getattr(iface, "description", "") or ""),
                ipv4=str(iface.ip) if getattr(iface, "ip", None) else None,
                mac=str(iface.mac) if getattr(iface, "mac", None) else None,
                network_name=str(iface.network_name) if getattr(iface, "network_name", None) else None,
            )
        )
    return sorted(result, key=lambda i: i.name)


def default_interface() -> str | None:
    iface = conf.iface
    return str(getattr(iface, "name", iface)) if iface else None


def resolve_interface(name: str | None) -> str:
    """Validate an interface (or pick Scapy's default) and return its canonical name.

    Accepts the interface name, its description or its OS network name.
    Raises :class:`CaptureError` if nothing matches.
    """
    if not name:
        default = default_interface()
        if not default:
            raise CaptureError("No network interface specified and no default interface found.")
        return default
    for info in list_interfaces():
        if name in (info.name, info.description, info.network_name):
            return info.name
    raise CaptureError(
        f"Network interface {name!r} not found. Run 'python run.py interfaces' to list available interfaces."
    )


def describe_capture_error(exc: BaseException, interface: str) -> str:
    """Translate low-level errors into actionable messages."""
    message = str(exc)
    lowered = message.lower()
    if (
        isinstance(exc, PermissionError)
        or (isinstance(exc, OSError) and exc.errno in (errno.EPERM, errno.EACCES))
        or "operation not permitted" in lowered
        or "permission denied" in lowered
    ):
        return (
            f"Permission denied opening interface {interface!r}. Packet capture needs elevated "
            "privileges: run the capture daemon with sudo/Administrator or grant CAP_NET_RAW "
            "(see README, 'Privileges')."
        )
    if (isinstance(exc, OSError) and exc.errno in (errno.ENODEV, errno.ENXIO)) or "no such device" in lowered:
        return f"Network interface {interface!r} is not available."
    if any(word in lowered for word in ("winpcap", "npcap", "libpcap", "tcpdump")):
        return f"Packet capture driver unavailable ({message}). Install libpcap (Linux/macOS) or Npcap (Windows)."
    if "filter" in lowered:
        return f"Invalid BPF filter: {message}"
    return f"Packet capture failed: {type(exc).__name__}: {message}"


def _userspace_default_filter(packet: Packet) -> bool:
    """Python equivalent of :data:`DEFAULT_BPF_FILTER`, used only if BPF compilation is unavailable."""
    transport = packet.getlayer("TCP") or packet.getlayer("UDP")
    if transport is None:
        return False
    if 53 in (transport.sport, transport.dport):
        return True
    return bool(packet.haslayer("TCP")) and bool(int(packet["TCP"].flags) & TCP_FLAG_SYN)


class LoopbackDeduplicator:
    """Drop the second copy of packets seen on loopback.

    On Linux, a raw socket on ``lo`` sees every packet twice (once outgoing,
    once incoming); libpcap-based tools hide this, Scapy's native socket does
    not. Identical frames within ``window`` seconds are treated as one.
    """

    def __init__(self, window: float = 0.2, size: int = 256) -> None:
        self._window = window
        self._recent: deque[tuple[bytes, float]] = deque(maxlen=size)

    def is_duplicate(self, raw: bytes, ts: float) -> bool:
        digest = hashlib.blake2b(raw, digest_size=12).digest()
        for seen, seen_ts in self._recent:
            if seen == digest and abs(ts - seen_ts) <= self._window:
                return True
        self._recent.append((digest, ts))
        return False


def is_loopback_interface(name: str | None) -> bool:
    if not name:
        return False
    lowered = name.lower()
    return lowered in {"lo", "lo0"} or "loopback" in lowered


class PacketCaptureService:
    """Runs a Scapy sniffer on one interface and pushes parsed events into a sink."""

    name = "capture"

    def __init__(
        self,
        interface: str | None,
        bpf_filter: str,
        sink: EventSink,
        *,
        parser: PacketParser | None = None,
        startup_timeout: float = 5.0,
        supervise_interval: float = 2.0,
    ) -> None:
        self._requested_interface = interface
        self._interface: str | None = interface
        self._bpf_filter = bpf_filter
        self._sink = sink
        self._parser = parser
        self._startup_timeout = startup_timeout
        self._supervise_interval = supervise_interval
        self._sniffer: AsyncSniffer | None = None
        self._active_filter: str | None = None
        self._dedupe: LoopbackDeduplicator | None = None
        self._stop = threading.Event()
        self._supervisor: threading.Thread | None = None
        self._state: SourceStateName = "idle"
        self._error: str | None = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self._set_state("starting")
        try:
            self._interface = resolve_interface(self._requested_interface)
        except CaptureError as exc:
            self._fail(str(exc))
            raise
        if self._parser is None:
            self._parser = PacketParser(self._interface)
        self._dedupe = LoopbackDeduplicator() if is_loopback_interface(self._interface) else None
        self._stop.clear()
        try:
            self._launch(self._bpf_filter, lfilter=None)
        except CaptureError as exc:
            if self._bpf_filter.strip() != DEFAULT_BPF_FILTER or "driver unavailable" not in str(exc):
                self._fail(str(exc))
                raise
            logger.warning(
                "BPF compilation unavailable; falling back to user-space filtering (higher CPU use)",
                extra={"interface": self._interface},
            )
            try:
                self._launch(None, lfilter=_userspace_default_filter)
            except CaptureError as retry_exc:
                self._fail(str(retry_exc))
                raise
        self._set_state("running")
        self._supervisor = threading.Thread(target=self._supervise, name="hound-capture-supervisor", daemon=True)
        self._supervisor.start()
        logger.info(
            "Packet capture started",
            extra={"interface": self._interface, "filter": self._active_filter or "user-space"},
        )

    def _launch(self, bpf_filter: str | None, lfilter: object) -> None:
        started = threading.Event()
        kwargs: dict[str, object] = {
            "iface": self._interface,
            "prn": self._on_packet,
            "store": False,
            "started_callback": started.set,
        }
        if bpf_filter:
            kwargs["filter"] = bpf_filter
        if lfilter is not None:
            kwargs["lfilter"] = lfilter
        sniffer = AsyncSniffer(**kwargs)
        sniffer.start()
        deadline = time.monotonic() + self._startup_timeout
        while not started.wait(0.1):
            if sniffer.thread is None or not sniffer.thread.is_alive() or time.monotonic() > deadline:
                break
        if sniffer.exception is not None or (sniffer.thread is not None and not sniffer.thread.is_alive()):
            exc = sniffer.exception or RuntimeError("capture thread exited during start-up")
            raise CaptureError(describe_capture_error(exc, self._interface or "?")) from exc
        if not started.is_set():
            logger.warning("Capture start-up confirmation timed out; continuing", extra={"interface": self._interface})
        self._sniffer = sniffer
        self._active_filter = bpf_filter

    def stop(self) -> None:
        self._stop.set()
        sniffer, self._sniffer = self._sniffer, None
        if sniffer is not None and sniffer.running:
            try:
                sniffer.stop(join=True)
            except Exception as exc:  # stopping must never raise
                logger.warning("Error while stopping sniffer", extra={"error": str(exc)})
        if self._supervisor is not None:
            self._supervisor.join(timeout=5)
            self._supervisor = None
        with self._lock:
            if self._state != "error":
                self._state = "stopped"
        logger.info("Packet capture stopped", extra={"interface": self._interface})

    # ------------------------------------------------------------------ internals
    def _on_packet(self, packet: Packet) -> None:
        try:
            assert self._parser is not None
            if self._dedupe is not None:
                raw = getattr(packet, "original", None) or bytes(packet)
                if self._dedupe.is_duplicate(raw, float(getattr(packet, "time", 0) or 0)):
                    return
            event = self._parser.parse(packet)
            if event is not None:
                self._sink(event)
        except Exception:  # pragma: no cover - parser/sink are designed not to raise
            logger.exception("Unexpected error in packet callback")

    def _supervise(self) -> None:
        while not self._stop.wait(self._supervise_interval):
            sniffer = self._sniffer
            if sniffer is None or sniffer.thread is None:
                continue
            if not sniffer.thread.is_alive():
                exc = sniffer.exception or RuntimeError("capture thread exited unexpectedly")
                message = describe_capture_error(exc, self._interface or "?")
                self._fail(message)
                logger.error("Packet capture stopped unexpectedly", extra={"reason": message})
                return

    def _set_state(self, state: SourceStateName) -> None:
        with self._lock:
            self._state = state
            if state in ("starting", "running"):
                self._error = None

    def _fail(self, message: str) -> None:
        with self._lock:
            self._state = "error"
            self._error = message

    def status(self) -> SourceStatus:
        stats = self._parser.stats if self._parser else None
        with self._lock:
            return SourceStatus(
                name=self.name,
                state=self._state,
                error=self._error,
                interface=self._interface,
                packets_parsed=stats.parsed if stats else 0,
                packets_ignored=stats.ignored if stats else 0,
                packets_malformed=stats.malformed if stats else 0,
            )
