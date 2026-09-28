"""Packet parsing/classification using synthetic Scapy packets (no capture needed)."""

from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw

from app.ingestion.parser import PacketParser
from app.models.events import PacketType, TransportProtocol
from tests.conftest import eth


def wire(packet: Packet, ts: float = 1_760_000_000.0) -> Packet:
    """Serialise and re-dissect, exactly as a real capture would deliver it."""
    parsed = Ether(bytes(packet))
    parsed.time = ts
    return parsed


def dns_query(domain: str = "Example.COM", qtype: str = "A") -> Packet:
    return wire(
        eth()
        / IP(src="192.168.1.10", dst="192.168.1.1")
        / UDP(sport=50000, dport=53)
        / DNS(id=7, rd=1, qd=DNSQR(qname=domain, qtype=qtype))
    )


def test_dns_query_extracts_domain_and_metadata() -> None:
    parser = PacketParser("eth0")
    event = parser.parse(dns_query())
    assert event is not None
    assert event.packet_type is PacketType.DNS_QUERY
    assert event.protocol is TransportProtocol.UDP
    assert event.domain == "example.com"  # normalised
    assert (event.source_ip, event.source_port) == ("192.168.1.10", 50000)
    assert (event.destination_ip, event.destination_port) == ("192.168.1.1", 53)
    assert event.dns_query_type == "A"
    assert event.interface == "eth0"
    assert event.timestamp.timestamp() == 1_760_000_000.0
    assert parser.stats.parsed == 1


def test_dns_query_type_names() -> None:
    event = PacketParser().parse(dns_query("example.org", qtype="TXT"))
    assert event is not None and event.dns_query_type == "TXT"


def test_dns_response_with_answers_and_rcode() -> None:
    pkt = wire(
        eth()
        / IP(src="192.168.1.1", dst="192.168.1.10")
        / UDP(sport=53, dport=50000)
        / DNS(
            id=7,
            qr=1,
            rcode=0,
            qd=DNSQR(qname="example.com"),
            an=[
                DNSRR(rrname="example.com", type="CNAME", rdata="edge.example.net"),
                DNSRR(rrname="example.com", type="A", rdata="93.184.216.34"),
                DNSRR(rrname="example.com", type="AAAA", rdata="2606:2800:220:1::1"),
            ],
        )
    )
    event = PacketParser().parse(pkt)
    assert event is not None
    assert event.packet_type is PacketType.DNS_RESPONSE
    assert event.dns_rcode == 0
    assert event.dns_answers == ("93.184.216.34", "2606:2800:220:1::1")


def test_nxdomain_response() -> None:
    pkt = wire(
        eth()
        / IP(src="192.168.1.1", dst="192.168.1.10")
        / UDP(sport=53, dport=50000)
        / DNS(id=7, qr=1, rcode=3, qd=DNSQR(qname="nope.example"))
    )
    event = PacketParser().parse(pkt)
    assert event is not None and event.dns_rcode == 3 and event.dns_answers == ()


def test_tcp_syn_is_connection_attempt() -> None:
    pkt = wire(eth() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=40000, dport=443, flags="S"))
    event = PacketParser().parse(pkt)
    assert event is not None
    assert event.packet_type is PacketType.TCP_SYN
    assert event.protocol is TransportProtocol.TCP
    assert event.domain is None
    assert event.destination_port == 443


def test_syn_ack_and_established_segments_are_ignored() -> None:
    parser = PacketParser()
    syn_ack = wire(eth() / IP(src="93.184.216.34", dst="192.168.1.10") / TCP(sport=443, dport=40000, flags="SA"))
    ack = wire(eth() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=40000, dport=443, flags="A"))
    assert parser.parse(syn_ack) is None
    assert parser.parse(ack) is None
    assert parser.stats.ignored == 2


def test_dns_over_tcp() -> None:
    pkt = wire(
        eth()
        / IP(src="192.168.1.10", dst="192.168.1.1")
        / TCP(sport=40001, dport=53, flags="PA")
        / DNS(id=1, qd=DNSQR(qname="tcp.example.com"))
    )
    event = PacketParser().parse(pkt)
    assert event is not None
    assert event.protocol is TransportProtocol.TCP and event.domain == "tcp.example.com"


def test_ipv6_dns_query() -> None:
    pkt = wire(
        eth()
        / IPv6(src="fe80::1", dst="2001:4860:4860::8888")
        / UDP(sport=5000, dport=53)
        / DNS(qd=DNSQR(qname="ipv6.example.com", qtype="AAAA"))
    )
    event = PacketParser().parse(pkt)
    assert event is not None
    assert event.destination_ip == "2001:4860:4860::8888" and event.dns_query_type == "AAAA"


def test_non_ip_and_irrelevant_packets_ignored() -> None:
    parser = PacketParser()
    assert parser.parse(wire(eth() / ARP(hwsrc="02:00:00:00:00:10", psrc="192.168.1.10", pdst="192.168.1.1"))) is None
    assert parser.parse(wire(eth() / IP(src="1.1.1.1", dst="2.2.2.2") / ICMP())) is None
    assert parser.parse(wire(eth() / IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=1, dport=123))) is None


def test_malformed_dns_payload_is_counted_not_raised() -> None:
    parser = PacketParser()
    garbage = wire(eth() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=5555, dport=53) / Raw(b"\x00\x01\xff"))
    assert parser.parse(garbage) is None
    assert parser.stats.malformed == 1


def test_truncated_dns_does_not_raise() -> None:
    full = bytes(dns_query())
    parser = PacketParser()
    for cut in range(14, len(full)):
        parser.parse(Ether(full[:cut]))  # must never raise
    assert parser.stats.parsed + parser.stats.ignored + parser.stats.malformed == len(full) - 14


def test_missing_or_invalid_dns_name() -> None:
    no_question = wire(eth() / IP(src="192.168.1.10", dst="192.168.1.1") / UDP(sport=5, dport=53) / DNS(id=1, qd=[]))
    event = PacketParser().parse(no_question)
    assert event is not None and event.domain is None
    bad_name = wire(
        eth()
        / IP(src="192.168.1.10", dst="192.168.1.1")
        / UDP(sport=5, dport=53)
        / DNS(id=1, qd=DNSQR(qname=b"bad name\xff.example"))
    )
    event = PacketParser().parse(bad_name)
    assert event is not None and event.domain is None


def test_parser_accepts_non_packet_garbage() -> None:
    parser = PacketParser()
    assert parser.parse(object()) is None  # type: ignore[arg-type]
    assert parser.stats.malformed == 1


def test_fuzz_random_and_mutated_frames_never_raise() -> None:
    """S-3: the parser runs inside the privileged capture process and must survive any input.

    Deterministic (fixed seed): random frames, plus valid DNS/SYN frames with random byte
    flips and truncations. Every frame must be counted exactly once as parsed, ignored or
    malformed, and anything parsed must still be a valid NetworkEvent.
    """
    import random

    from app.models.events import NetworkEvent

    rng = random.Random(1337)
    seeds = [
        bytes(dns_query()),
        bytes(wire(eth() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=40000, dport=443, flags="S"))),
        bytes(
            wire(
                eth()
                / IP(src="192.168.1.1", dst="192.168.1.10")
                / UDP(sport=53, dport=5000)
                / DNS(
                    id=7,
                    qr=1,
                    qd=DNSQR(qname="example.com"),
                    an=[DNSRR(rrname="example.com", type="A", rdata="93.184.216.34")],
                )
            )
        ),
    ]
    frames: list[bytes] = [bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 200))) for _ in range(800)]
    for _ in range(1600):
        frame = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 6)):
            frame[rng.randrange(len(frame))] = rng.getrandbits(8)
        if rng.random() < 0.3:
            del frame[rng.randrange(1, len(frame)) :]
        frames.append(bytes(frame))

    def as_sniffed(raw: bytes) -> Packet:
        # Scapy's capture socket (SuperSocket.recv) falls back to a Raw packet when
        # dissection fails, so that is what the parser receives for undissectable frames.
        try:
            return Ether(raw)
        except Exception:
            return Raw(raw)

    parser = PacketParser("fuzz0")
    for raw in frames:
        event = parser.parse(as_sniffed(raw))  # must never raise
        if event is not None:
            assert isinstance(event, NetworkEvent)
    stats = parser.stats
    assert stats.parsed + stats.ignored + stats.malformed == len(frames)
    assert stats.parsed > 0 and stats.malformed > 0  # the corpus really exercised both paths
