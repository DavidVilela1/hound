"""Deterministic risk scoring, signals and behaviour tracking."""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.models.events import PacketType
from app.models.processed import Enrichment
from app.models.risk import RiskLevel
from app.risk.behavior import DeviceBehaviorTracker
from app.risk.config import RiskConfig
from app.risk.engine import RiskEngine
from tests.conftest import BASE_TIME, EventFactory


def enrichment(domain: str | None = None, *, public: bool = True, blocked: str | None = None) -> Enrichment:
    return Enrichment(
        country="US" if public else "LAN",
        domain=domain,
        domain_source=None,
        blocklist_match=blocked,
        destination_is_public=public,
    )


def codes(assessment) -> set[str]:  # type: ignore[no-untyped-def]
    return {r.code for r in assessment.reasons}


def test_benign_dns_query_is_safe(make_event: EventFactory) -> None:
    result = RiskEngine().assess(make_event(domain="www.wikipedia.org"), enrichment("www.wikipedia.org", public=False))
    assert result.score == 0 and result.level is RiskLevel.SAFE and result.reasons == ()


def test_blocklisted_domain_is_dangerous(make_event: EventFactory) -> None:
    result = RiskEngine().assess(
        make_event(domain="c2.bad.example"), enrichment("c2.bad.example", public=False, blocked="bad.example")
    )
    assert result.level is RiskLevel.DANGEROUS
    assert result.score == 70
    assert codes(result) == {"BLOCKLISTED_DOMAIN"}
    assert "bad.example" in result.reasons[0].description


@pytest.mark.parametrize(
    "score,level",
    [
        (0, RiskLevel.SAFE),
        (24, RiskLevel.SAFE),
        (25, RiskLevel.SUSPICIOUS),
        (69, RiskLevel.SUSPICIOUS),
        (70, RiskLevel.DANGEROUS),
        (100, RiskLevel.DANGEROUS),
    ],
)
def test_level_thresholds(score: int, level: RiskLevel) -> None:
    assert RiskConfig().level_for(score) is level


def test_invalid_thresholds_rejected() -> None:
    with pytest.raises(ValueError):
        RiskConfig(suspicious_threshold=80, dangerous_threshold=70)


def test_suspicious_port_plus_direct_ip(make_event: EventFactory) -> None:
    syn = make_event(packet_type=PacketType.TCP_SYN, destination_port=3389)
    result = RiskEngine().assess(syn, enrichment(None))
    assert codes(result) == {"SUSPICIOUS_PORT", "NO_PRIOR_DNS_LOOKUP"}
    assert result.score == 30 and result.level is RiskLevel.SUSPICIOUS
    assert result.reasons[0].code == "SUSPICIOUS_PORT"  # sorted by weight


def test_suspicious_port_on_lan_is_not_flagged(make_event: EventFactory) -> None:
    syn = make_event(packet_type=PacketType.TCP_SYN, destination_ip="192.168.1.20", destination_port=445)
    assert RiskEngine().assess(syn, enrichment(None, public=False)).score == 0


def test_uncommon_port_is_low_weight(make_event: EventFactory) -> None:
    syn = make_event(packet_type=PacketType.TCP_SYN, destination_port=8883)
    result = RiskEngine().assess(syn, enrichment("mqtt.example"))
    assert codes(result) == {"UNCOMMON_PORT"} and result.level is RiskLevel.SAFE


def test_port_scan_detection(make_event: EventFactory) -> None:
    engine = RiskEngine()
    results = [
        engine.assess(
            make_event(packet_type=PacketType.TCP_SYN, destination_port=1000 + i, seconds=i * 0.1),
            enrichment("x.example"),
        )
        for i in range(15)
    ]
    assert "PORT_SCAN_PATTERN" not in codes(results[13])
    assert "PORT_SCAN_PATTERN" in codes(results[14])  # 15th distinct port
    assert results[14].level is RiskLevel.SUSPICIOUS


def test_host_sweep_detection(make_event: EventFactory) -> None:
    engine = RiskEngine()
    last = None
    for i in range(20):
        syn = make_event(
            packet_type=PacketType.TCP_SYN, destination_ip=f"192.168.1.{100 + i}", destination_port=23, seconds=i
        )
        last = engine.assess(syn, enrichment(None, public=False))
    assert last is not None and "HOST_SWEEP_PATTERN" in codes(last)


def test_repeated_attempts_and_window_expiry(make_event: EventFactory) -> None:
    engine = RiskEngine(RiskConfig(window=timedelta(seconds=60), repeated_attempts_threshold=5))
    for i in range(5):
        result = engine.assess(make_event(packet_type=PacketType.TCP_SYN, seconds=i), enrichment("a.example"))
    assert "REPEATED_CONNECTION_ATTEMPTS" in codes(result)
    later = engine.assess(make_event(packet_type=PacketType.TCP_SYN, seconds=200), enrichment("a.example"))
    assert "REPEATED_CONNECTION_ATTEMPTS" not in codes(later)  # old attempts left the window


def test_nxdomain_burst_flags_following_queries(make_event: EventFactory) -> None:
    engine = RiskEngine()
    for i in range(10):
        engine.observe(
            make_event(
                packet_type=PacketType.DNS_RESPONSE,
                source_ip="192.168.1.1",
                destination_ip="192.168.1.10",
                dns_rcode=3,
                domain=f"n{i}.example",
                seconds=i,
            )
        )
    result = engine.assess(make_event(domain="next.example", seconds=11), enrichment("next.example", public=False))
    assert "NXDOMAIN_BURST" in codes(result) and result.level is RiskLevel.SUSPICIOUS
    other_device = engine.assess(
        make_event(source_ip="192.168.1.99", seconds=11), enrichment("next.example", public=False)
    )
    assert other_device.score == 0


def test_dga_like_domain(make_event: EventFactory) -> None:
    domain = "x7k2qp9zv4m1bw.top"
    result = RiskEngine().assess(make_event(domain=domain), enrichment(domain, public=False))
    assert codes(result) == {"HIGH_ENTROPY_DOMAIN", "RISKY_TLD"}
    assert result.score == 30


def test_long_domain_and_txt_query(make_event: EventFactory) -> None:
    domain = ".".join(["abc"] * 8) + ".example"
    result = RiskEngine().assess(make_event(domain=domain, dns_query_type="TXT"), enrichment(domain, public=False))
    assert {"LONG_DOMAIN", "UNUSUAL_DNS_QUERY_TYPE"} <= codes(result)


def test_untrusted_resolver_only_when_configured(make_event: EventFactory) -> None:
    event = make_event(destination_ip="8.8.8.8")
    assert RiskEngine().assess(event, enrichment("example.com")).score == 0
    engine = RiskEngine(RiskConfig(trusted_dns_servers=frozenset({"192.168.1.1"})))
    assert codes(engine.assess(event, enrichment("example.com"))) == {"UNTRUSTED_DNS_RESOLVER"}


def test_score_is_capped_at_100(make_event: EventFactory) -> None:
    engine = RiskEngine(RiskConfig(port_scan_threshold=2, repeated_attempts_threshold=2))
    engine.assess(
        make_event(packet_type=PacketType.TCP_SYN, destination_port=4444),
        enrichment("bad.example", blocked="bad.example"),
    )
    result = engine.assess(
        make_event(packet_type=PacketType.TCP_SYN, destination_port=4444, seconds=1),
        enrichment("bad.example", blocked="bad.example"),
    )
    assert result.score == 100
    assert sum(r.points for r in result.reasons) > 100


def test_scoring_is_deterministic(make_event: EventFactory) -> None:
    def run() -> list[tuple[int, str]]:
        engine = RiskEngine()
        out = []
        for i in range(30):
            ev = make_event(packet_type=PacketType.TCP_SYN, destination_port=20 + i % 7, seconds=i)
            r = engine.assess(ev, enrichment(None))
            out.append((r.score, r.level.value))
        return out

    assert run() == run()


def test_tracker_memory_is_bounded() -> None:
    tracker = DeviceBehaviorTracker(timedelta(hours=1), max_devices=3, max_entries_per_device=5)
    for d in range(10):
        for i in range(20):
            tracker.record_attempt(f"10.0.0.{d}", "1.1.1.1", i, BASE_TIME + timedelta(seconds=i), local=False)
    assert tracker.tracked_devices == 3
    snap = tracker.record_attempt("10.0.0.9", "1.1.1.1", 999, BASE_TIME + timedelta(seconds=30), local=False)
    assert snap.ports_on_target_host == 5
