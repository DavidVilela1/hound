"""Demo mode drives the real parser and pipeline without privileges or a network."""

from __future__ import annotations

import time

from app.core.config import Settings
from app.database.repositories import EventFilter
from app.ingestion.demo import DemoEventSource, DemoTrafficGenerator, ip_in_network
from app.ingestion.parser import PacketParser
from app.models.events import NetworkEvent, PacketType
from app.services.runtime import HoundRuntime, RunMode


def test_generator_is_deterministic_with_seed() -> None:
    def summary(seed: int) -> list[str]:
        gen = DemoTrafficGenerator(seed=seed, clock=lambda: 1_000.0)
        return [p.summary() for _ in range(30) for p in gen.next_batch()]

    assert summary(3) == summary(3)
    assert summary(3) != summary(4)


def test_generated_packets_parse_into_valid_events() -> None:
    parser = PacketParser("demo0")
    gen = DemoTrafficGenerator(seed=1, blocklisted_domains=["bad.example"])
    types: set[PacketType] = set()
    for _ in range(200):
        for packet in gen.next_batch():
            event = parser.parse(packet)
            if event is not None:
                types.add(event.packet_type)
    assert types == {PacketType.DNS_QUERY, PacketType.DNS_RESPONSE, PacketType.TCP_SYN}
    assert parser.stats.malformed == 0


def test_demo_source_emits_into_sink() -> None:
    received: list[NetworkEvent] = []
    source = DemoEventSource(lambda e: received.append(e) or True, generator=DemoTrafficGenerator(seed=5))
    assert source.emit_once() == len(received) > 0
    assert all(e.interface == "demo0" for e in received)


def test_ip_in_network_is_stable() -> None:
    import ipaddress

    net = ipaddress.ip_network("34.0.0.0/10")
    ip = ip_in_network(net, "github.com")
    assert ip == ip_in_network(net, "github.com") and ipaddress.ip_address(ip) in net


def test_demo_mode_runs_full_pipeline(settings: Settings) -> None:
    demo_settings = settings.model_copy(update={"demo_events_per_second": 200.0})
    runtime = HoundRuntime(demo_settings, RunMode.DEMO)
    runtime.start()
    try:
        deadline = time.monotonic() + 10
        while runtime.processor.stats().processed < 50 and time.monotonic() < deadline:
            time.sleep(0.05)
        status = runtime.pipeline_status()
        assert status.mode == "demo" and status.source == "demo" and status.source_state == "running"
        page = runtime.events.list_events(EventFilter(), limit=10, offset=0)
        assert page.total >= 50
        assert runtime.stats.stats().devices >= 1
    finally:
        runtime.stop()
    assert runtime.pipeline_status().source_state == "stopped"
