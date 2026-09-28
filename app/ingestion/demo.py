"""Demo mode: synthetic but realistic home-network traffic.

The generator builds **real Scapy packets** (Ethernet/IP/UDP/DNS and
Ethernet/IP/TCP SYN), serialises them to bytes and re-dissects them, then runs
them through the same :class:`PacketParser` used for live capture. From there
the events follow the normal pipeline (queue → enrichment → risk → SQLite →
API/WebSocket → dashboard). Nothing is sent on the network and no privileges
are required.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import random
import string
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from app.ingestion.parser import PacketParser
from app.ingestion.sources import EventSink, SourceStateName, SourceStatus

logger = logging.getLogger(__name__)

DEMO_INTERFACE = "demo0"
ROUTER_IP = "192.168.1.1"
PUBLIC_RESOLVERS = ("8.8.8.8", "1.1.1.1")
NXDOMAIN = 3

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True, slots=True)
class DemoDevice:
    ip: str
    name: str
    mac: str
    weight: int


@dataclass(frozen=True, slots=True)
class DemoSite:
    domain: str
    country: str
    port: int = 443


DEVICES: tuple[DemoDevice, ...] = (
    DemoDevice("192.168.1.10", "laptop", "02:00:00:00:00:10", 30),
    DemoDevice("192.168.1.12", "desktop", "02:00:00:00:00:12", 20),
    DemoDevice("192.168.1.23", "phone", "02:00:00:00:00:23", 25),
    DemoDevice("192.168.1.31", "tablet", "02:00:00:00:00:31", 10),
    DemoDevice("192.168.1.40", "smart-tv", "02:00:00:00:00:40", 10),
    DemoDevice("192.168.1.57", "ip-camera", "02:00:00:00:00:57", 5),
)
CAMERA = DEVICES[5]
TV = DEVICES[4]

SITES: tuple[DemoSite, ...] = (
    DemoSite("www.google.com", "US"),
    DemoSite("www.youtube.com", "US"),
    DemoSite("github.com", "US"),
    DemoSite("api.github.com", "US"),
    DemoSite("www.netflix.com", "US"),
    DemoSite("open.spotify.com", "SE"),
    DemoSite("en.wikipedia.org", "NL"),
    DemoSite("www.bbc.co.uk", "GB"),
    DemoSite("www.amazon.de", "DE"),
    DemoSite("www.apple.com", "US"),
    DemoSite("p57-caldav.icloud.com", "US"),
    DemoSite("login.microsoftonline.com", "IE"),
    DemoSite("zoom.us", "US"),
    DemoSite("cdn.jsdelivr.net", "NL"),
    DemoSite("www.reddit.com", "US"),
    DemoSite("www.dropbox.com", "US"),
    DemoSite("www.sapo.pt", "PT"),
    DemoSite("www.publico.pt", "PT"),
    DemoSite("www.lemonde.fr", "FR"),
    DemoSite("www.rakuten.co.jp", "JP"),
    DemoSite("www.naver.com", "KR"),
    DemoSite("www.baidu.com", "CN"),
    DemoSite("yandex.ru", "RU"),
    DemoSite("www.mercadolivre.com.br", "BR"),
    DemoSite("time.cloudflare.com", "US"),
    DemoSite("mqtt.iot-vendor.example", "DE", 8883),
)
TXT_DOMAINS = ("_dmarc.example.org", "status.example.net", "update-check.example.com")
SCAN_PORTS = (21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 4444, 5432, 5900, 6667, 8080, 8443)
FALLBACK_BLOCKLISTED = ("malware-c2.example",)


def _stable_int(text: str) -> int:
    return int.from_bytes(hashlib.blake2b(text.encode(), digest_size=8).digest(), "big")


def ip_in_network(network: Network, key: str) -> str:
    """Deterministically pick a host address inside ``network`` for ``key``."""
    hosts = max(network.num_addresses - 2, 1)
    return str(network.network_address + 1 + (_stable_int(key) % hosts))


class DemoTrafficGenerator:
    """Produces batches of Scapy packets for weighted, repeatable scenarios."""

    def __init__(
        self,
        *,
        seed: int | None = None,
        blocklisted_domains: Sequence[str] = (),
        country_networks: Mapping[str, Sequence[Network]] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._rng = random.Random(seed)
        self._blocklisted = tuple(blocklisted_domains) or FALLBACK_BLOCKLISTED
        # Broad IPv4 ranges only, so demo sites don't land inside e.g. a well-known resolver /24.
        self._networks = {
            k: [n for n in v if n.version == 4 and n.prefixlen <= 20] for k, v in (country_networks or {}).items()
        }
        self._clock = clock
        self._scenarios: list[tuple[Callable[[], list[Packet]], int]] = [
            (self._browse, 62),
            (self._browse_public_resolver, 5),
            (self._blocklisted_lookup, 4),
            (self._direct_ip, 5),
            (self._iot_uncommon_port, 4),
            (self._txt_query, 3),
            (self._suspicious_port, 3),
            (self._dga_burst, 2),
            (self._retry_storm, 2),
            (self._port_scan, 1),
            (self._host_sweep, 1),
        ]

    # ------------------------------------------------------------------ public
    def next_batch(self) -> list[Packet]:
        funcs, weights = zip(*self._scenarios, strict=True)
        scenario = self._rng.choices(funcs, weights=weights, k=1)[0]
        packets = scenario()
        base = self._clock()
        for index, packet in enumerate(packets):
            packet.time = base + index * 0.002
        return packets

    # ------------------------------------------------------------------ helpers
    def _device(self, exclude_camera: bool = False) -> DemoDevice:
        pool = [d for d in DEVICES if not (exclude_camera and d is CAMERA)]
        return self._rng.choices(pool, weights=[d.weight for d in pool], k=1)[0]

    def _public_ip(self, key: str, country: str | None = None) -> str:
        networks = self._networks.get(country or "", [])
        if networks:
            return ip_in_network(networks[_stable_int(key) % len(networks)], key)
        # Deterministic fallback: first globally routable address derived from the key.
        for salt in range(64):
            candidate = ipaddress.IPv4Address(_stable_int(f"{key}/{salt}") & 0xFFFFFFFF)
            if candidate.is_global and not candidate.is_multicast:
                return str(candidate)
        return "93.184.216.34"  # pragma: no cover - statistically unreachable

    def _sport(self) -> int:
        return self._rng.randint(32768, 60999)

    def _query(self, dev: DemoDevice, resolver: str, domain: str, qtype: str = "A") -> tuple[Packet, int, int]:
        qid, sport = self._rng.randint(1, 65535), self._sport()
        pkt = (
            Ether(src=dev.mac, dst="02:00:00:00:00:01")
            / IP(src=dev.ip, dst=resolver)
            / UDP(sport=sport, dport=53)
            / DNS(id=qid, rd=1, qd=DNSQR(qname=domain, qtype=qtype))
        )
        return pkt, qid, sport

    def _response(
        self,
        dev: DemoDevice,
        resolver: str,
        domain: str,
        qid: int,
        dport: int,
        answers: Sequence[str] = (),
        rcode: int = 0,
        qtype: str = "A",
    ) -> Packet:
        records = [DNSRR(rrname=domain, type="A", ttl=300, rdata=ip) for ip in answers]
        dns = DNS(id=qid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=domain, qtype=qtype), an=records)
        return (
            Ether(src="02:00:00:00:00:01", dst=dev.mac)
            / IP(src=resolver, dst=dev.ip)
            / UDP(sport=53, dport=dport)
            / dns
        )

    def _syn(self, dev: DemoDevice, dst: str, dport: int) -> Packet:
        return (
            Ether(src=dev.mac, dst="02:00:00:00:00:01")
            / IP(src=dev.ip, dst=dst)
            / TCP(sport=self._sport(), dport=dport, flags="S", seq=self._rng.randint(0, 2**32 - 1))
        )

    def _lookup_and_connect(
        self, dev: DemoDevice, resolver: str, domain: str, country: str | None, port: int
    ) -> list[Packet]:
        ip = self._public_ip(domain, country)
        query, qid, sport = self._query(dev, resolver, domain)
        answers = [ip] + ([self._public_ip(domain + "#2", country)] if self._rng.random() < 0.3 else [])
        packets = [query, self._response(dev, resolver, domain, qid, sport, answers)]
        packets.extend(self._syn(dev, ip, port) for _ in range(self._rng.randint(1, 2)))
        return packets

    # ------------------------------------------------------------------ scenarios
    def _browse(self) -> list[Packet]:
        site = self._rng.choice(SITES[:-1])
        return self._lookup_and_connect(self._device(), ROUTER_IP, site.domain, site.country, site.port)

    def _browse_public_resolver(self) -> list[Packet]:
        site = self._rng.choice(SITES[:-1])
        return self._lookup_and_connect(
            self._device(), self._rng.choice(PUBLIC_RESOLVERS), site.domain, site.country, 443
        )

    def _blocklisted_lookup(self) -> list[Packet]:
        entry = self._rng.choice(self._blocklisted)
        domain = entry if self._rng.random() < 0.6 else f"cdn.{entry}"
        return self._lookup_and_connect(
            self._device(), ROUTER_IP, domain, self._rng.choice(["RU", "CN", "US", "NL"]), 443
        )

    def _direct_ip(self) -> list[Packet]:
        ip = self._public_ip(f"direct-{self._rng.randint(0, 40)}")
        return [self._syn(self._device(), ip, self._rng.choice([443, 443, 80]))]

    def _iot_uncommon_port(self) -> list[Packet]:
        site = SITES[-1]
        return self._lookup_and_connect(TV, ROUTER_IP, site.domain, site.country, site.port)

    def _txt_query(self) -> list[Packet]:
        dev = self._device()
        domain = self._rng.choice(TXT_DOMAINS)
        query, qid, sport = self._query(dev, ROUTER_IP, domain, qtype="TXT")
        return [query, self._response(dev, ROUTER_IP, domain, qid, sport, qtype="TXT")]

    def _suspicious_port(self) -> list[Packet]:
        ip = self._public_ip(f"rdp-{self._rng.randint(0, 5)}", "NL")
        return [self._syn(self._device(exclude_camera=True), ip, self._rng.choice([3389, 445, 5900]))]

    def _dga_burst(self) -> list[Packet]:
        dev = self._rng.choice([CAMERA, TV])
        packets: list[Packet] = []
        for _ in range(12):
            label = "".join(self._rng.choices(string.ascii_lowercase + string.digits, k=self._rng.randint(13, 18)))
            domain = f"{label}.{self._rng.choice(['com', 'net', 'top', 'info'])}"
            query, qid, sport = self._query(dev, ROUTER_IP, domain)
            packets += [query, self._response(dev, ROUTER_IP, domain, qid, sport, rcode=NXDOMAIN)]
        return packets

    def _retry_storm(self) -> list[Packet]:
        dev = self._device(exclude_camera=True)
        ip = self._public_ip(f"retry-{self._rng.randint(0, 3)}", "US")
        return [self._syn(dev, ip, 443) for _ in range(18)]

    def _port_scan(self) -> list[Packet]:
        ip = self._public_ip(f"scan-target-{self._rng.randint(0, 3)}", "CN")
        return [self._syn(CAMERA, ip, port) for port in SCAN_PORTS]

    def _host_sweep(self) -> list[Packet]:
        return [self._syn(CAMERA, f"192.168.1.{host}", 23) for host in range(100, 124)]


class DemoEventSource:
    """Runs :class:`DemoTrafficGenerator` on a thread and feeds parsed events into a sink."""

    name = "demo"

    def __init__(
        self,
        sink: EventSink,
        *,
        events_per_second: float = 4.0,
        generator: DemoTrafficGenerator | None = None,
        interface: str = DEMO_INTERFACE,
    ) -> None:
        if events_per_second <= 0:
            raise ValueError("events_per_second must be positive")
        self._sink = sink
        self._rate = events_per_second
        self._generator = generator or DemoTrafficGenerator()
        self._interface = interface
        self._parser = PacketParser(interface)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._state: SourceStateName = "idle"
        self._error: str | None = None

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="hound-demo", daemon=True)
        self._state = "running"
        self._thread.start()
        logger.info("Demo traffic generator started", extra={"rate": self._rate})

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        if self._state != "error":
            self._state = "stopped"

    def emit_once(self) -> int:
        """Generate one scenario synchronously; returns the number of events emitted."""
        emitted = 0
        for packet in self._generator.next_batch():
            wire = Ether(bytes(packet))  # dissect from raw bytes, exactly like a capture
            wire.time = packet.time
            wire.sniffed_on = self._interface
            event = self._parser.parse(wire)
            if event is not None and self._sink(event):
                emitted += 1
        return emitted

    def _run(self) -> None:
        interval = 1.0 / self._rate
        try:
            while not self._stop.is_set():
                emitted = self.emit_once()
                # Pace roughly to the configured rate; bursts wait a little longer, capped.
                wait = min(max(emitted, 1) * interval, 3 * interval + 0.5)
                if self._stop.wait(wait):
                    break
        except Exception as exc:
            self._state = "error"
            self._error = f"Demo generator failed: {exc}"
            logger.exception("Demo generator crashed")

    def status(self) -> SourceStatus:
        stats = self._parser.stats
        return SourceStatus(
            name=self.name,
            state=self._state,
            error=self._error,
            interface=self._interface,
            packets_parsed=stats.parsed,
            packets_ignored=stats.ignored,
            packets_malformed=stats.malformed,
        )
