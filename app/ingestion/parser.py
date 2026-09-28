"""Convert raw Scapy packets into normalised :class:`NetworkEvent` objects.

This is the only module that understands Scapy packet structure. It never
raises: malformed or irrelevant packets yield ``None`` and are counted.

Classification rules
--------------------
* TCP with SYN set and ACK clear → ``tcp_syn`` (a connection *attempt*; the
  handshake may never complete, so it is not treated as a connection).
* TCP SYN+ACK → ignored (server side of the handshake).
* UDP/TCP carrying a DNS message → ``dns_query`` or ``dns_response``.
* Everything else → ignored.
"""

from __future__ import annotations

import logging
import struct
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from app.core.netutils import is_valid_ip, normalize_domain
from app.models.events import NetworkEvent, PacketType, TransportProtocol

logger = logging.getLogger(__name__)

TCP_FLAG_SYN = 0x02
TCP_FLAG_ACK = 0x10
DNS_TYPE_A = 1
DNS_TYPE_AAAA = 28
MAX_DNS_ANSWERS = 32

QTYPE_NAMES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    10: "NULL",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    64: "SVCB",
    65: "HTTPS",
    255: "ANY",
}


@dataclass(slots=True)
class ParserStats:
    parsed: int = 0
    ignored: int = 0
    malformed: int = 0


def _as_list(value: Any) -> list[Any]:
    """Scapy ≥ 2.6 exposes DNS sections as lists; older versions as chained packets."""
    if value is None:
        return []
    if isinstance(value, list | tuple):
        return list(value)
    return [value]


def _decode_name(raw: Any) -> str | None:
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("ascii")
        except UnicodeDecodeError:
            return None
    return raw if isinstance(raw, str) else None


def _timestamp(packet: Packet) -> datetime:
    raw = getattr(packet, "time", None)
    try:
        return datetime.fromtimestamp(float(raw), tz=UTC) if raw is not None else datetime.now(UTC)
    except (TypeError, ValueError, OverflowError, OSError):
        return datetime.now(UTC)


class PacketParser:
    """Stateless apart from counters; safe to call from the capture thread."""

    def __init__(self, interface: str | None = None) -> None:
        self._interface = interface[:64] if interface else None
        self._lock = threading.Lock()
        self.stats = ParserStats()

    def parse(self, packet: Packet) -> NetworkEvent | None:
        try:
            event = self._parse(packet)
        except (ValidationError, AttributeError, IndexError, TypeError, ValueError, struct.error) as exc:
            self._count("malformed")
            logger.debug("Malformed packet skipped", extra={"error": type(exc).__name__})
            return None
        except Exception:  # never let one packet kill the capture thread
            self._count("malformed")
            logger.exception("Unexpected error while parsing packet")
            return None
        self._count("parsed" if event is not None else "ignored")
        return event

    def _count(self, field: str) -> None:
        with self._lock:
            setattr(self.stats, field, getattr(self.stats, field) + 1)

    # ------------------------------------------------------------------ internals
    def _parse(self, packet: Packet) -> NetworkEvent | None:
        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if ip_layer is None:
            return None
        src, dst = str(ip_layer.src), str(ip_layer.dst)
        if not (is_valid_ip(src) and is_valid_ip(dst)):
            raise ValueError("invalid IP address")
        interface = self._interface_of(packet)
        timestamp = _timestamp(packet)

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = int(tcp.flags)
            if flags & TCP_FLAG_SYN:
                if flags & TCP_FLAG_ACK:
                    return None  # SYN-ACK: responder side of a handshake
                return NetworkEvent(
                    timestamp=timestamp,
                    source_ip=src,
                    source_port=int(tcp.sport),
                    destination_ip=dst,
                    destination_port=int(tcp.dport),
                    protocol=TransportProtocol.TCP,
                    packet_type=PacketType.TCP_SYN,
                    interface=interface,
                )
            transport, protocol = tcp, TransportProtocol.TCP
        elif packet.haslayer(UDP):
            transport, protocol = packet[UDP], TransportProtocol.UDP
        else:
            return None

        if not packet.haslayer(DNS):
            if 53 in (int(transport.sport), int(transport.dport)) and protocol is TransportProtocol.UDP:
                raise ValueError("port-53 payload is not a DNS message")
            return None
        return self._dns_event(packet[DNS], src, dst, transport, protocol, timestamp, interface)

    def _dns_event(
        self,
        dns: Packet,
        src: str,
        dst: str,
        transport: Packet,
        protocol: TransportProtocol,
        timestamp: datetime,
        interface: str | None,
    ) -> NetworkEvent:
        questions = _as_list(dns.qd)
        question = questions[0] if questions else None
        domain: str | None = None
        qtype: str | None = None
        if question is not None:
            name = _decode_name(question.qname)
            domain = normalize_domain(name)
            if name and domain is None:
                logger.debug("Unparseable DNS name ignored")
            qtype_num = int(question.qtype)
            qtype = QTYPE_NAMES.get(qtype_num, str(qtype_num))

        is_response = bool(int(dns.qr))
        answers: list[str] = []
        rcode: int | None = None
        if is_response:
            rcode = int(dns.rcode)
            for record in _as_list(dns.an)[: MAX_DNS_ANSWERS * 2]:
                if getattr(record, "type", None) in (DNS_TYPE_A, DNS_TYPE_AAAA):
                    rdata = str(record.rdata)
                    if is_valid_ip(rdata):
                        answers.append(rdata)
                if len(answers) >= MAX_DNS_ANSWERS:
                    break

        return NetworkEvent(
            timestamp=timestamp,
            source_ip=src,
            source_port=int(transport.sport),
            destination_ip=dst,
            destination_port=int(transport.dport),
            protocol=protocol,
            packet_type=PacketType.DNS_RESPONSE if is_response else PacketType.DNS_QUERY,
            domain=domain,
            interface=interface,
            dns_query_type=qtype,
            dns_rcode=rcode,
            dns_answers=tuple(answers),
        )

    def _interface_of(self, packet: Packet) -> str | None:
        sniffed_on = getattr(packet, "sniffed_on", None)
        if sniffed_on:
            return str(sniffed_on)[:64]
        return self._interface
