"""Allowlist: parsing, matching, the scoring policy, and the path from file to API."""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.app import create_app
from app.core.config import PROJECT_ROOT, Settings
from app.enrichment.allowlist import Allowlist, parse_allowlist_line
from app.enrichment.blocklist import Blocklist
from app.enrichment.dns_cache import ResolutionCache
from app.enrichment.geo import StaticRangeGeoLocator
from app.enrichment.service import EnrichmentService
from app.models.events import PacketType
from app.models.processed import Enrichment
from app.models.risk import RiskLevel, RiskReason
from app.risk.engine import ALLOWLISTED, RiskEngine, apply_allowlist
from app.services.runtime import HoundRuntime
from tests.conftest import EventFactory

TRUSTED_NAS = "192.168.1.5"
DGA_LIKE = "x7k2qp9zv4m1bw.top"  # HIGH_ENTROPY_DOMAIN + RISKY_TLD = 30 points (SUSPICIOUS)


def codes(reasons: object) -> list[str]:
    return [reason.code for reason in reasons]  # type: ignore[attr-defined]


# ------------------------------------------------------------------------------ parsing & matching
@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("cdn.example.com", "cdn.example.com"),
        ("  *.CDN.Example.com.  # comment", "cdn.example.com"),
        ("192.168.1.20", ipaddress.ip_network("192.168.1.20/32")),
        ("192.168.1.64/28", ipaddress.ip_network("192.168.1.64/28")),
        ("192.168.1.70/28", ipaddress.ip_network("192.168.1.64/28")),  # host bits tolerated
        ("fd00::10", ipaddress.ip_network("fd00::10/128")),
        ("com", None),  # a bare label would silence a whole TLD
        ("not a domain!", None),
        ("# only a comment", None),
        ("", None),
    ],
)
def test_parse_line(line: str, expected: object) -> None:
    assert parse_allowlist_line(line) == expected


def test_domain_matching_uses_label_boundaries() -> None:
    allowlist = Allowlist(domains=["cdn.example.com"])
    assert allowlist.match_domain("cdn.example.com") == "cdn.example.com"
    assert allowlist.match_domain("a1b2.cdn.example.com") == "cdn.example.com"
    assert allowlist.match_domain("evilcdn.example.com") is None
    assert allowlist.match_domain("example.com") is None
    assert allowlist.match_domain(None) is None


def test_device_matching_addresses_and_ranges() -> None:
    allowlist = Allowlist(
        networks=[ipaddress.ip_network("192.168.1.5/32"), ipaddress.ip_network("192.168.1.64/28")]
        + [ipaddress.ip_network("fd00::/64")]
    )
    assert allowlist.match_device(TRUSTED_NAS) == TRUSTED_NAS  # single address shown without /32
    assert allowlist.match_device("192.168.1.70") == "192.168.1.64/28"
    assert allowlist.match_device("192.168.1.80") is None
    assert allowlist.match_device("fd00::1234%eth0") == "fd00::/64"  # zone id ignored
    assert allowlist.match_device("not-an-ip") is None and allowlist.match_device(None) is None
    assert not Allowlist() and Allowlist(domains=["a.example"])


def test_file_loading_warns_about_mistakes(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    path = tmp_path / "allowlist.txt"
    path.write_text("cdn.example.com\ncom\n192.168.0.0/16\n10.0.0.1\n!!!\n", encoding="utf-8")
    with caplog.at_level(logging.INFO):
        allowlist = Allowlist.from_file(path)
    assert allowlist.match_domain("x.cdn.example.com") and allowlist.match_device("192.168.200.1")
    assert allowlist.match_device("10.0.0.1") == "10.0.0.1"
    messages = [record.getMessage() for record in caplog.records]
    assert any("Broad allowlist range" in m for m in messages)
    invalid = next(r for r in caplog.records if "Ignored invalid allowlist lines" in r.getMessage())
    assert invalid.invalid == 2  # type: ignore[attr-defined]


def test_missing_file_means_nothing_allowlisted(tmp_path: Path) -> None:
    assert not Allowlist.from_file(tmp_path / "absent.txt")


def test_shipped_example_file_allowlists_nothing() -> None:
    assert not Allowlist.from_file(PROJECT_ROOT / "config" / "allowlist.txt")


# ------------------------------------------------------------------------------ policy
def reasons(*items: tuple[str, int]) -> list[RiskReason]:
    return [RiskReason(code, points, code.lower()) for code, points in items]


def enrichment(*, domain: str | None = None, device: str | None = None, blocked: str | None = None) -> Enrichment:
    return Enrichment(
        country=None,
        domain="x.example",
        domain_source=None,
        blocklist_match=blocked,
        destination_is_public=True,
        allowlisted_domain=domain,
        allowlisted_device=device,
    )


def test_domain_entry_covers_everything_including_the_blocklist() -> None:
    found = reasons(("BLOCKLISTED_DOMAIN", 70), ("HIGH_ENTROPY_DOMAIN", 20))
    result = apply_allowlist(found, enrichment(domain="cdn.example.com", blocked="example.com"))
    assert codes(result) == [ALLOWLISTED]
    assert result[0].points == 0
    assert "domain cdn.example.com" in result[0].description
    assert "BLOCKLISTED_DOMAIN, HIGH_ENTROPY_DOMAIN" in result[0].description


def test_device_entry_never_hides_a_blocklist_hit() -> None:
    found = reasons(("BLOCKLISTED_DOMAIN", 70), ("PORT_SCAN_PATTERN", 40))
    result = apply_allowlist(found, enrichment(device=TRUSTED_NAS))
    assert codes(result) == ["BLOCKLISTED_DOMAIN", ALLOWLISTED]
    assert "device 192.168.1.5: 1 indicator(s) not counted (PORT_SCAN_PATTERN)" in result[1].description


def test_nothing_to_suppress_adds_no_note() -> None:
    assert apply_allowlist([], enrichment(device=TRUSTED_NAS)) == []
    only_block = reasons(("BLOCKLISTED_DOMAIN", 70))
    assert apply_allowlist(only_block, enrichment(device=TRUSTED_NAS)) == only_block
    assert apply_allowlist(only_block, enrichment()) == only_block  # not allowlisted: unchanged


# ------------------------------------------------------------------------------ engine + enrichment
def pipeline(allowlist: Allowlist, blocked: tuple[str, ...] = ()) -> tuple[EnrichmentService, RiskEngine]:
    service = EnrichmentService(
        Blocklist(blocked), StaticRangeGeoLocator([]), ResolutionCache(100, timedelta(hours=1)), allowlist
    )
    return service, RiskEngine()


def test_allowlisted_cdn_domain_becomes_safe_but_stays_explained(make_event: EventFactory) -> None:
    event = make_event(domain=DGA_LIKE)
    service, engine = pipeline(Allowlist())
    assert engine.assess(event, service.enrich(event)).level is RiskLevel.SUSPICIOUS

    service, engine = pipeline(Allowlist(domains=[DGA_LIKE]))
    result = engine.assess(event, service.enrich(event))
    assert (result.level, result.score) == (RiskLevel.SAFE, 0)
    assert codes(result.reasons) == [ALLOWLISTED]
    assert "HIGH_ENTROPY_DOMAIN" in result.reasons[0].description


def test_allowlisted_device_scan_is_not_flagged(make_event: EventFactory) -> None:
    service, engine = pipeline(Allowlist(networks=[ipaddress.ip_network(TRUSTED_NAS)]))
    results = []
    for port in range(1000, 1016):  # 16 distinct ports: a port-scan pattern
        event = make_event(
            packet_type=PacketType.TCP_SYN, source_ip=TRUSTED_NAS, destination_port=port, seconds=port * 0.01
        )
        results.append(engine.assess(event, service.enrich(event)))
    assert all(result.level is RiskLevel.SAFE for result in results)
    assert "PORT_SCAN_PATTERN" in results[-1].reasons[0].description  # recorded, not counted


def test_allowlisted_device_contacting_a_blocklisted_domain_is_still_dangerous(make_event: EventFactory) -> None:
    service, engine = pipeline(Allowlist(networks=[ipaddress.ip_network(TRUSTED_NAS)]), blocked=("bad.example",))
    event = make_event(domain="c2.bad.example", source_ip=TRUSTED_NAS)
    result = engine.assess(event, service.enrich(event))
    assert result.level is RiskLevel.DANGEROUS and "BLOCKLISTED_DOMAIN" in codes(result.reasons)


# ------------------------------------------------------------------------------ file → API
@pytest.fixture
def allowlisted_client(settings: Settings, tmp_path: Path) -> Iterator[tuple[TestClient, HoundRuntime]]:
    path = tmp_path / "allowlist.txt"
    path.write_text(f"{DGA_LIKE}\n{TRUSTED_NAS}\n", encoding="utf-8")
    configured = settings.model_copy(update={"allowlist_path": path})
    runtime = HoundRuntime(configured)
    with TestClient(create_app(configured, runtime)) as client:
        yield client, runtime


def test_allowlist_file_applies_end_to_end(
    allowlisted_client: tuple[TestClient, HoundRuntime], make_event: EventFactory
) -> None:
    client, runtime = allowlisted_client
    runtime.processor.process_batch(
        [
            make_event(domain=DGA_LIKE, seconds=1),
            make_event(domain="c2.bad.example", source_ip=TRUSTED_NAS, seconds=2),  # blocklisted in the fixture
        ]
    )
    items = {item["domain"]: item for item in client.get("/api/events").json()["items"]}
    cdn = items[DGA_LIKE]
    assert cdn["risk_level"] == "safe" and cdn["risk_score"] == 0
    assert [r["code"] for r in cdn["risk_reasons"]] == [ALLOWLISTED]
    assert items["c2.bad.example"]["risk_level"] == "dangerous"  # a trusted device, but a known-bad domain
    device = client.get(f"/api/devices/{TRUSTED_NAS}").json()
    assert device["risk_level"] == "dangerous"
