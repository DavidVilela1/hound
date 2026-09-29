"""What the chosen deployment position can and cannot see (ADR-026).

The owner states where Hound captures (``HOUND_DEPLOYMENT_POSITION``); this module holds
the plain-language description of each position and checks it against the stored
traffic, so an empty dashboard is not misread as "nothing happened".

The traffic check counts **devices that start something**: addresses that sent a DNS
lookup or a TCP connection attempt in the last 24 hours. (DNS answers are not stored, so
the resolver answering a laptop's lookups — usually the router — is not a device here.)
Only local IPv4 addresses are counted as devices: one computer commonly uses several
IPv6 addresses at once, so IPv6 is reported separately and never decides.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.core.config import DEFAULT_BPF_FILTER, DeploymentPosition, Settings
from app.core.netutils import is_local_address
from app.database.engine import Database
from app.database.repositories import EventRepository
from app.models.schemas import CoverageEvidence, CoverageObserved, CoverageOut

WINDOW = timedelta(hours=24)
MIN_EVENTS = 50
"""Lookups + connection attempts needed before the traffic is used as evidence."""
MIN_SPAN = timedelta(minutes=15)
"""…spread over at least this long, so a quiet first minute on a router is not a verdict."""
CACHE_SECONDS = 30.0
MAX_EXAMPLES = 5

SETTING = "HOUND_DEPLOYMENT_POSITION"
CHOICES = "this_computer, gateway, mirror or dns_server"


@dataclass(frozen=True, slots=True)
class PositionProfile:
    label: str
    summary: str
    sees: tuple[str, ...]
    misses: tuple[str, ...]
    main_blind_spot: str = ""
    """A few words for one-line reports (``doctor``)."""


PROFILES: dict[DeploymentPosition, PositionProfile] = {
    DeploymentPosition.AUTO: PositionProfile(
        label="Position not set",
        summary=f"Hound describes what it sees from the traffic. Set {SETTING} ({CHOICES}) to state where it runs.",
        sees=(),
        misses=(),
    ),
    DeploymentPosition.THIS_COMPUTER: PositionProfile(
        label="This computer only",
        main_blind_spot="other devices on your network",
        summary="Hound sees the lookups and connections of the computer it runs on, not the rest of your network.",
        sees=(
            "DNS lookups and new TCP connections made by this computer (every program on it).",
            "Connection attempts that other devices make to this computer.",
        ),
        misses=(
            "Other devices on your network: switches send each device only its own traffic, and Wi-Fi adapters "
            "(outside monitor mode) pass on only this computer's, so theirs never reaches Hound.",
            "Traffic sent through a VPN: on the Wi-Fi or Ethernet adapter it is encrypted; capture on the VPN "
            "adapter to see it.",
        ),
    ),
    DeploymentPosition.GATEWAY: PositionProfile(
        label="Router / gateway",
        main_blind_spot="traffic between devices inside your network",
        summary="Hound runs on the device that connects your network to the internet and sees every device "
        "whose traffic passes through it.",
        sees=("DNS lookups and internet connections of every device that uses this gateway.",),
        misses=(
            "Traffic between devices inside your network (a phone casting to a TV, for example): it is often "
            "switched in hardware and never reaches the router's processor.",
            "Individual devices if the capture runs on the internet (WAN) side: address translation makes every "
            "device look like the router. Capture on the LAN side.",
        ),
    ),
    DeploymentPosition.MIRROR: PositionProfile(
        label="Mirror (SPAN) port",
        main_blind_spot="ports that are not mirrored",
        summary="Hound listens on a switch port that receives a copy of other ports' traffic; it sees what the "
        "switch copies.",
        sees=(
            "Lookups and connections on the mirrored ports: usually the router's port, which carries every "
            "device's internet traffic.",
        ),
        misses=(
            "Ports that are not mirrored, and devices whose traffic bypasses them (for example Wi-Fi clients of an "
            "access point that is not behind this switch).",
            "Copies the switch drops when the mirrored ports carry more than the mirror port can: that loss "
            "happens in the switch and does not appear in Hound's metrics.",
        ),
    ),
    DeploymentPosition.DNS_SERVER: PositionProfile(
        label="DNS server",
        main_blind_spot="other devices' connections (only their DNS lookups)",
        summary="Hound runs on the machine that answers your network's DNS lookups (e.g. next to Pi-hole): it "
        "sees which names every device looks up, but not their connections.",
        sees=(
            "DNS lookups of every device that uses this server (usually handed out by the router's DHCP).",
            "This machine's own connections.",
        ),
        misses=(
            "Other devices' connections: they go straight to the router, so connection signals (port scans, "
            "host sweeps, suspicious ports) apply only to this machine.",
            "Devices that use another DNS server (one set by hand, or built into an app).",
            "Which device asked, if the router forwards lookups on the devices' behalf: then every lookup "
            "appears to come from the router.",
        ),
    ),
}

ALWAYS_MISSED: tuple[str, ...] = (
    "Encrypted DNS (DNS over HTTPS or TLS, such as a browser's secure DNS or Android's Private DNS): the names "
    "are hidden; the connections are still seen, without a name.",
    "Connections over UDP, including QUIC (HTTP/3), which many large sites use: only TCP connection attempts are "
    "captured.",
    "What is inside any connection: Hound records names and connection starts, never content.",
)
IPV6_SYN_MISSED = (
    "IPv6 connection attempts: the default capture filter matches IPv4 TCP only (IPv6 DNS lookups are captured)."
)
CUSTOM_FILTER = "A custom capture filter is set (HOUND_BPF_FILTER): what is captured depends on it."


def misses_for(position: DeploymentPosition, bpf_filter: str) -> list[str]:
    filter_note = IPV6_SYN_MISSED if bpf_filter.strip() == DEFAULT_BPF_FILTER else CUSTOM_FILTER
    return [*PROFILES[position].misses, *ALWAYS_MISSED, filter_note]


# ------------------------------------------------------------------------------ evidence
@dataclass(frozen=True, slots=True)
class Initiator:
    address: str
    count: int
    first: datetime
    last: datetime


def observe(initiators: list[Initiator], window: timedelta = WINDOW) -> CoverageObserved:
    local_v4: list[Initiator] = []
    ipv6 = public_v4 = 0
    for item in initiators:
        try:
            version = ipaddress.ip_address(item.address).version
        except ValueError:
            continue
        if version == 6:
            ipv6 += 1
        elif is_local_address(item.address):
            local_v4.append(item)
        else:
            public_v4 += 1
    total = sum(item.count for item in initiators)
    span = max(i.last for i in initiators) - min(i.first for i in initiators) if initiators else timedelta(0)
    busiest = sorted(local_v4, key=lambda i: (-i.count, ipaddress.ip_address(i.address)))
    return CoverageObserved(
        window_hours=int(window.total_seconds() // 3600),
        lookups_and_connections=total,
        observed_minutes=int(span.total_seconds() // 60),
        ipv4_devices=len(local_v4),
        ipv6_addresses=ipv6,
        public_ipv4_sources=public_v4,
        busiest_ipv4_devices=[i.address for i in busiest[:MAX_EXAMPLES]],
    )


def evidence_of(observed: CoverageObserved, *, demo: bool) -> CoverageEvidence:
    if demo:
        return "demo"
    if observed.lookups_and_connections < MIN_EVENTS or observed.observed_minutes < MIN_SPAN.total_seconds() // 60:
        return "not_enough_traffic"
    if observed.ipv4_devices == 0:
        return "no_local_ipv4"
    return "one_device" if observed.ipv4_devices == 1 else "several_devices"


def assess(position: DeploymentPosition, evidence: CoverageEvidence, observed: CoverageObserved) -> tuple[str, str]:
    """Plain-language verdict and its level (``info``, ``ok`` or ``warning``)."""
    n = observed.ipv4_devices
    only = observed.busiest_ipv4_devices[0] if observed.busiest_ipv4_devices else "?"
    hours = observed.window_hours
    if evidence == "demo":
        return (
            "Demo mode: the events are synthetic, so they say nothing about what this position can see.",
            "info",
        )
    if evidence == "not_enough_traffic":
        return (
            f"Not enough traffic yet to check what this position sees ({observed.lookups_and_connections} lookups "
            f"and connections over {observed.observed_minutes} min in the last {hours} h; the check needs "
            f"{MIN_EVENTS} over {int(MIN_SPAN.total_seconds() // 60)} min).",
            "info",
        )
    if evidence == "no_local_ipv4":
        if observed.public_ipv4_sources:
            return (
                "Every lookup and connection comes from a public address. If Hound runs on a router it is "
                "probably capturing the internet (WAN) side, where all devices look like one; capture on the "
                "LAN side instead.",
                "warning" if position in (DeploymentPosition.GATEWAY, DeploymentPosition.MIRROR) else "info",
            )
        return ("No local IPv4 devices seen, so Hound cannot count devices here (IPv6 only?).", "info")

    if position is DeploymentPosition.AUTO:
        if evidence == "one_device":
            return (
                f"Only one device ({only}) looked up names or started connections in the last {hours} h. Hound "
                "most likely sees just the computer it runs on: other devices' traffic never reaches this "
                f"network card. If that is intended, set {SETTING}=this_computer.",
                "info",
            )
        return (
            f"{n} devices seen in the last {hours} h: Hound sees more than the computer it runs on (router, mirror "
            f"port or DNS server). Set {SETTING} to say which, so the blind spots shown are the right ones.",
            "info",
        )
    if position is DeploymentPosition.THIS_COMPUTER:
        if evidence == "one_device":
            return (f"As expected for this position: one device ({only}).", "ok")
        return (
            f"{n} devices seen, but the position is 'this computer'. Extra addresses usually come from virtual "
            "machines or containers on this computer, or from devices connecting to it; if Hound actually runs on "
            f"a router, mirror port or DNS server, change {SETTING}.",
            "warning",
        )
    if position is DeploymentPosition.DNS_SERVER:
        if evidence == "one_device":
            return (
                f"All lookups come from one address ({only}). If that is your router, it forwards lookups on the "
                "devices' behalf and Hound cannot tell devices apart: let the router's DHCP hand out this "
                "server's address instead.",
                "warning",
            )
        return (f"As expected for this position: lookups from {n} devices.", "ok")
    # gateway or mirror
    if evidence == "one_device":
        return (
            f"Only one device ({only}) in the last {hours} h, but this position should see the whole network. "
            + (
                "Check that the capture runs on the LAN side, not the internet (WAN) side."
                if position is DeploymentPosition.GATEWAY
                else "Check that the mirror session is active and copies the router's port."
            ),
            "warning",
        )
    return (f"As expected for this position: {n} devices seen in the last {hours} h.", "ok")


# ------------------------------------------------------------------------------ service
class CoverageService:
    """Builds :class:`CoverageOut`; the traffic query is cached briefly (the dashboard polls)."""

    def __init__(
        self,
        database: Database,
        settings: Settings,
        *,
        demo: Callable[[], bool],
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        cache_seconds: float = CACHE_SECONDS,
    ) -> None:
        self._db = database
        self._position = settings.deployment_position
        self._bpf_filter = settings.bpf_filter
        self._demo = demo
        self._clock = clock
        self._cache_seconds = cache_seconds
        self._lock = threading.Lock()
        self._cached: tuple[float, CoverageOut] | None = None

    def coverage(self) -> CoverageOut:
        with self._lock:
            if self._cached and time.monotonic() - self._cached[0] < self._cache_seconds:
                return self._cached[1]
            result = self._build()
            self._cached = (time.monotonic(), result)
            return result

    def _build(self) -> CoverageOut:
        now = self._clock()
        with self._db.session() as session:
            rows = EventRepository(session).initiators_since(now - WINDOW)
        observed = observe([Initiator(*row) for row in rows])
        evidence = evidence_of(observed, demo=self._demo())
        assessment, level = assess(self._position, evidence, observed)
        profile = PROFILES[self._position]
        return CoverageOut(
            position=self._position.value,  # type: ignore[arg-type]
            position_set=self._position is not DeploymentPosition.AUTO,
            label=profile.label,
            summary=profile.summary,
            sees=list(profile.sees),
            misses=misses_for(self._position, self._bpf_filter),
            observed=observed,
            evidence=evidence,
            assessment=assessment,
            assessment_level=level,  # type: ignore[arg-type]
            generated_at=now,
        )
