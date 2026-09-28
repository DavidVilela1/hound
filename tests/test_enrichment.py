"""Blocklist matching, geolocation abstraction, DNS correlation and the enrichment service."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from app.enrichment.blocklist import Blocklist, parse_blocklist_line
from app.enrichment.dns_cache import ResolutionCache
from app.enrichment.geo import (
    LOCAL_NETWORK,
    GeoLocator,
    SimulatedGeoLocator,
    StaticRangeGeoLocator,
    build_geolocator,
    country_name,
    load_ranges,
)
from app.enrichment.service import EnrichmentService
from app.models.events import DomainSource, PacketType
from tests.conftest import BASE_TIME, EventFactory

# --------------------------------------------------------------------------- blocklist


@pytest.mark.parametrize(
    "domain,expected",
    [
        ("example.com", "example.com"),
        ("www.example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("example.com.", "example.com"),
        ("deep.sub.example.com", "example.com"),
        ("https://www.example.com/login", "example.com"),
        ("notexample.com", None),
        ("example.com.evil.net", None),
        ("example.org", None),
        (None, None),
        ("not a domain", None),
    ],
)
def test_blocklist_matching(domain: str | None, expected: str | None) -> None:
    assert Blocklist(["Example.COM"]).match(domain) == expected


def test_specific_subdomain_entry_does_not_block_parent() -> None:
    blocklist = Blocklist(["ads.example.com"])
    assert blocklist.match("x.ads.example.com") == "ads.example.com"
    assert blocklist.match("example.com") is None


@pytest.mark.parametrize(
    "line,expected",
    [
        ("bad.example", "bad.example"),
        ("  BAD.example  # comment", "bad.example"),
        ("*.wild.test", "wild.test"),
        ("0.0.0.0 hosts.example", "hosts.example"),
        ("127.0.0.1 hosts2.example", "hosts2.example"),
        ("# only a comment", None),
        ("", None),
        ("two words", None),
    ],
)
def test_parse_blocklist_line(line: str, expected: str | None) -> None:
    assert parse_blocklist_line(line) == expected


def test_blocklist_from_file(blocklist_file: Path) -> None:
    blocklist = Blocklist.from_file(blocklist_file)
    assert len(blocklist) == 3
    assert "cdn.tracker.test" in blocklist
    assert blocklist.match("hosts-style.example") == "hosts-style.example"
    assert blocklist.domains == ("bad.example", "hosts-style.example", "tracker.test")


def test_missing_and_empty_blocklist(tmp_path: Path) -> None:
    assert len(Blocklist.from_file(tmp_path / "missing.txt")) == 0
    empty = tmp_path / "empty.txt"
    empty.write_text("# nothing\n\n", encoding="utf-8")
    blocklist = Blocklist.from_file(empty)
    assert not blocklist
    assert blocklist.match("anything.example") is None


def test_invalid_blocklist_lines_are_skipped(tmp_path: Path) -> None:
    path = tmp_path / "mixed.txt"
    path.write_text("good.example\n-bad-.example\nthis has spaces\n", encoding="utf-8")
    assert Blocklist.from_file(path).domains == ("good.example",)


# --------------------------------------------------------------------------- geolocation


def test_static_locator(geo_file: Path) -> None:
    locator = StaticRangeGeoLocator(load_ranges(geo_file))
    assert locator.locate("93.184.216.34") == "US"
    assert locator.locate("185.15.57.1") == "NL"
    assert locator.locate("2a00:1450::1") == "DE"
    assert locator.locate("192.168.1.1") == LOCAL_NETWORK
    assert locator.locate("fe80::1") == LOCAL_NETWORK
    assert locator.locate("8.8.4.4") is None
    assert locator.locate("not-an-ip") is None


def test_longest_prefix_wins() -> None:
    import ipaddress

    locator = StaticRangeGeoLocator(
        [(ipaddress.ip_network("20.0.0.0/8"), "US"), (ipaddress.ip_network("20.1.0.0/16"), "IE")]
    )
    assert locator.locate("20.1.2.3") == "IE"
    assert locator.locate("20.2.2.3") == "US"


def test_simulated_locator_is_deterministic(geo_file: Path) -> None:
    locator = SimulatedGeoLocator(StaticRangeGeoLocator(load_ranges(geo_file)))
    first = locator.locate("45.33.32.156")
    assert first is not None and first == locator.locate("45.33.99.1")  # same /16 → same country
    assert locator.locate("93.184.216.34") == "US"  # static table wins
    assert locator.locate("10.0.0.1") == LOCAL_NETWORK


def test_build_geolocator_modes(geo_file: Path) -> None:
    assert build_geolocator("mapping_only", geo_file).locate("8.8.4.4") is None
    assert build_geolocator("simulated", geo_file).locate("8.8.4.4") is not None


def test_geo_protocol_allows_custom_implementations() -> None:
    class FixedLocator:
        def locate(self, ip: str) -> str | None:
            return "PT"

    locator: GeoLocator = FixedLocator()
    assert locator.locate("1.2.3.4") == "PT"
    assert country_name("PT") == "Portugal"
    assert country_name(None) == "Unknown"
    assert country_name("ZZ") == "ZZ"


def test_invalid_geo_rows_skipped(tmp_path: Path) -> None:
    path = tmp_path / "geo.csv"
    path.write_text("not-a-cidr,US\n1.0.0.0/8,??\n2.0.0.0/8,fr\nshort\n", encoding="utf-8")
    ranges = load_ranges(path)
    assert [(str(n), c) for n, c in ranges] == [("2.0.0.0/8", "FR")]
    assert load_ranges(tmp_path / "missing.csv") == []


# --------------------------------------------------------------------------- dns cache & service


def test_resolution_cache_ttl_and_bound() -> None:
    cache = ResolutionCache(max_entries=2, ttl=timedelta(seconds=10))
    cache.put("1.1.1.1", "a.example", BASE_TIME)
    cache.put("2.2.2.2", "b.example", BASE_TIME)
    cache.put("3.3.3.3", "c.example", BASE_TIME)
    assert len(cache) == 2
    assert cache.get("1.1.1.1", BASE_TIME) is None  # evicted (LRU)
    assert cache.get("3.3.3.3", BASE_TIME + timedelta(seconds=5)) == "c.example"
    assert cache.get("3.3.3.3", BASE_TIME + timedelta(seconds=11)) is None  # expired


def _service(geo_file: Path, blocked: list[str]) -> EnrichmentService:
    return EnrichmentService(Blocklist(blocked), build_geolocator("mapping_only", geo_file), ResolutionCache())


def test_enrich_dns_query(make_event: EventFactory, geo_file: Path) -> None:
    service = _service(geo_file, ["example.com"])
    result = service.enrich(make_event(domain="www.example.com"))
    assert result.domain == "www.example.com"
    assert result.domain_source is DomainSource.DNS_QUERY
    assert result.blocklist_match == "example.com"
    assert result.country == LOCAL_NETWORK  # resolver on the LAN
    assert not result.destination_is_public


def test_syn_gets_domain_from_prior_dns_answer(make_event: EventFactory, geo_file: Path) -> None:
    service = _service(geo_file, ["example.com"])
    response = make_event(
        packet_type=PacketType.DNS_RESPONSE,
        source_ip="192.168.1.1",
        destination_ip="192.168.1.10",
        domain="cdn.example.com",
        dns_answers=("93.184.216.34",),
        dns_rcode=0,
    )
    service.observe_dns_response(response)
    result = service.enrich(make_event(packet_type=PacketType.TCP_SYN, seconds=1))
    assert result.domain == "cdn.example.com"
    assert result.domain_source is DomainSource.DNS_CACHE
    assert result.blocklist_match == "example.com"
    assert result.country == "US"
    assert result.destination_is_public


def test_enrichment_survives_broken_geolocator(make_event: EventFactory) -> None:
    class Broken:
        def locate(self, ip: str) -> str | None:
            raise RuntimeError("boom")

    service = EnrichmentService(Blocklist(), Broken(), ResolutionCache())
    assert service.enrich(make_event()).country is None
