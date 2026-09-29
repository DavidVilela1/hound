"""Deployment positions (ADR-026): what each position can see, checked against the traffic."""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.api.app import create_app
from app.core.config import DeploymentPosition, Settings
from app.models.events import NetworkEvent, PacketType
from app.models.schemas import CoverageOut
from app.services import doctor
from app.services.coverage import (
    ALWAYS_MISSED,
    CUSTOM_FILTER,
    IPV6_SYN_MISSED,
    MIN_EVENTS,
    PROFILES,
    CoverageService,
    Initiator,
    observe,
)
from app.services.doctor import Status
from app.services.runtime import HoundRuntime
from tests.conftest import BASE_TIME, EventFactory

ROOT = Path(__file__).resolve().parent.parent
LAPTOP = "192.168.1.10"
ROUTER = "192.168.1.1"
NOW = BASE_TIME + timedelta(hours=1)


@pytest.fixture
def runtime(settings: Settings) -> Iterator[HoundRuntime]:
    runtime = HoundRuntime(settings)
    runtime.database.initialize()
    yield runtime
    runtime.database.dispose()


def coverage(
    runtime: HoundRuntime, settings: Settings, position: str = "auto", *, demo: bool = False, **extra: Any
) -> CoverageOut:
    configured = settings.model_copy(update={"deployment_position": DeploymentPosition(position), **extra})
    service = CoverageService(runtime.database, configured, demo=lambda: demo, clock=lambda: NOW, cache_seconds=0)
    return service.coverage()


def lookups(make_event: EventFactory, source: str, count: int = 60, minutes: int = 20) -> list[NetworkEvent]:
    """``count`` DNS lookups by ``source`` spread over ``minutes``."""
    step = minutes * 60 // max(1, count - 1)
    return [make_event(source_ip=source, domain=f"site{n}.example", seconds=n * step) for n in range(count)]


def answers(make_event: EventFactory, count: int = 60) -> list[NetworkEvent]:
    """DNS answers from the router's resolver to the laptop: the router answers, it starts nothing."""
    return [
        make_event(
            packet_type=PacketType.DNS_RESPONSE,
            source_ip=ROUTER,
            source_port=53,
            destination_ip=LAPTOP,
            destination_port=40000,
            domain=f"site{n}.example",
            dns_answers=("93.184.216.34",),
            dns_rcode=0,
            seconds=n * 20,
        )
        for n in range(count)
    ]


def several(make_event: EventFactory) -> list[NetworkEvent]:
    return [*lookups(make_event, LAPTOP), *lookups(make_event, "192.168.1.20", 10), *lookups(make_event, "10.0.0.7", 5)]


# ------------------------------------------------------------------------------ setting
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("This-Computer", DeploymentPosition.THIS_COMPUTER),
        (" dns server ", DeploymentPosition.DNS_SERVER),
        ("GATEWAY", DeploymentPosition.GATEWAY),
        ("", DeploymentPosition.AUTO),
    ],
)
def test_position_setting_is_forgiving_about_spelling(raw: str, expected: DeploymentPosition) -> None:
    assert Settings(_env_file=None, deployment_position=raw).deployment_position is expected  # type: ignore[arg-type]


def test_unknown_position_is_refused() -> None:
    with pytest.raises(ValidationError, match="deployment_position"):
        Settings(_env_file=None, deployment_position="wifi")  # type: ignore[arg-type]


# ------------------------------------------------------------------------------ inference
def test_laptop_is_one_device_although_the_router_answers_its_lookups(
    runtime: HoundRuntime, settings: Settings, make_event: EventFactory
) -> None:
    """The resolver answers but starts nothing; counting it would make every laptop 'see' two devices."""
    runtime.processor.process_batch([*lookups(make_event, LAPTOP), *answers(make_event)])
    result = coverage(runtime, settings)
    assert result.observed.ipv4_devices == 1
    assert result.observed.busiest_ipv4_devices == [LAPTOP]
    assert result.evidence == "one_device"
    assert result.assessment_level == "info"
    assert LAPTOP in result.assessment and "HOUND_DEPLOYMENT_POSITION=this_computer" in result.assessment
    assert not result.position_set and result.sees == []


def test_connection_attempts_count_as_starting_something(
    runtime: HoundRuntime, settings: Settings, make_event: EventFactory
) -> None:
    syns = [make_event(packet_type=PacketType.TCP_SYN, source_ip=LAPTOP, seconds=n * 20) for n in range(MIN_EVENTS)]
    runtime.processor.process_batch(syns)
    result = coverage(runtime, settings, "this_computer")
    assert result.observed.lookups_and_connections == MIN_EVENTS
    assert (result.evidence, result.assessment_level) == ("one_device", "ok")


def test_ipv6_addresses_are_reported_but_do_not_count_as_devices(
    runtime: HoundRuntime, settings: Settings, make_event: EventFactory
) -> None:
    temporary = ["2001:db8::10", "2001:db8::a1b2", "fe80::10"]  # one computer, several IPv6 addresses
    runtime.processor.process_batch(
        [*lookups(make_event, LAPTOP), *(e for ip in temporary for e in lookups(make_event, ip, 3))]
    )
    result = coverage(runtime, settings, "this_computer")
    assert (result.observed.ipv4_devices, result.observed.ipv6_addresses) == (1, 3)
    assert result.evidence == "one_device" and result.assessment_level == "ok"


@pytest.mark.parametrize(
    ("count", "minutes"),
    [(MIN_EVENTS - 1, 60), (500, 14)],
    ids=["too-few-events", "too-short"],
)
def test_no_verdict_without_enough_traffic(
    runtime: HoundRuntime, settings: Settings, make_event: EventFactory, count: int, minutes: int
) -> None:
    runtime.processor.process_batch(lookups(make_event, LAPTOP, count, minutes))
    result = coverage(runtime, settings, "gateway")  # one device on a router would otherwise be a warning
    assert result.evidence == "not_enough_traffic"
    assert result.assessment_level == "info"
    assert "Not enough traffic yet" in result.assessment


def test_only_the_last_24_hours_count(runtime: HoundRuntime, settings: Settings, make_event: EventFactory) -> None:
    old = [
        e.model_copy(update={"timestamp": e.timestamp - timedelta(days=2)}) for e in lookups(make_event, "192.168.1.99")
    ]
    runtime.processor.process_batch([*old, *lookups(make_event, LAPTOP)])
    result = coverage(runtime, settings)
    assert result.observed.busiest_ipv4_devices == [LAPTOP]
    assert result.observed.lookups_and_connections == 60


def test_busiest_devices_first_and_at_most_five(
    runtime: HoundRuntime, settings: Settings, make_event: EventFactory
) -> None:
    batch = lookups(make_event, LAPTOP, 60)
    for n in range(2, 9):
        batch += lookups(make_event, f"192.168.1.{n + 100}", n)
    runtime.processor.process_batch(batch)
    observed = coverage(runtime, settings).observed
    assert observed.ipv4_devices == 8
    assert observed.busiest_ipv4_devices == [LAPTOP, "192.168.1.108", "192.168.1.107", "192.168.1.106", "192.168.1.105"]


def test_unreadable_addresses_are_skipped() -> None:
    """Stored addresses are validated at ingest; a hand-edited database must still not break the page."""
    seen = Initiator("not-an-ip", 99, NOW, NOW)
    fine = Initiator(LAPTOP, 1, NOW, NOW)
    assert observe([seen, fine]).busiest_ipv4_devices == [LAPTOP]


# ------------------------------------------------------------------------------ verdict per position
@pytest.mark.parametrize(
    ("position", "scenario", "evidence", "level", "phrase"),
    [
        ("auto", "several", "several_devices", "info", "Set HOUND_DEPLOYMENT_POSITION"),
        ("this_computer", "one", "one_device", "ok", "As expected"),
        ("this_computer", "several", "several_devices", "warning", "virtual machines"),
        ("gateway", "several", "several_devices", "ok", "As expected"),
        ("gateway", "one", "one_device", "warning", "LAN side"),
        ("mirror", "several", "several_devices", "ok", "As expected"),
        ("mirror", "one", "one_device", "warning", "mirror session"),
        ("dns_server", "several", "several_devices", "ok", "As expected"),
        ("dns_server", "one", "one_device", "warning", "forwards lookups"),
        ("gateway", "wan", "no_local_ipv4", "warning", "internet (WAN) side"),
        ("this_computer", "wan", "no_local_ipv4", "info", "public address"),
        ("gateway", "v6", "no_local_ipv4", "info", "IPv6 only"),
    ],
)
def test_verdict_for_each_position(
    runtime: HoundRuntime,
    settings: Settings,
    make_event: EventFactory,
    position: str,
    scenario: str,
    evidence: str,
    level: str,
    phrase: str,
) -> None:
    batch = {
        "one": lookups(make_event, LAPTOP),
        "several": several(make_event),
        "wan": lookups(make_event, "85.240.10.20"),
        "v6": lookups(make_event, "2001:db8::10"),  # behind NAT every device is the router's public address
    }[scenario]
    runtime.processor.process_batch(batch)
    result = coverage(runtime, settings, position)
    assert (result.evidence, result.assessment_level) == (evidence, level)
    assert phrase in result.assessment


def test_demo_traffic_is_never_taken_as_evidence(
    runtime: HoundRuntime, settings: Settings, make_event: EventFactory
) -> None:
    runtime.processor.process_batch(several(make_event))
    result = coverage(runtime, settings, "this_computer", demo=True)
    assert result.evidence == "demo" and result.assessment_level == "info"
    assert result.observed.ipv4_devices == 3  # still counted, just not judged


# ------------------------------------------------------------------------------ blind spots
@pytest.mark.parametrize("position", list(DeploymentPosition))
def test_every_position_lists_the_universal_blind_spots(
    runtime: HoundRuntime, settings: Settings, position: DeploymentPosition
) -> None:
    result = coverage(runtime, settings, position.value)
    assert result.label == PROFILES[position].label and result.summary
    assert result.misses[: len(PROFILES[position].misses)] == list(PROFILES[position].misses)
    assert all(line in result.misses for line in ALWAYS_MISSED)
    assert result.misses[-1] == IPV6_SYN_MISSED


def test_custom_capture_filter_replaces_the_ipv6_statement(runtime: HoundRuntime, settings: Settings) -> None:
    result = coverage(runtime, settings, "gateway", bpf_filter="ip6 and tcp")
    assert result.misses[-1] == CUSTOM_FILTER and IPV6_SYN_MISSED not in result.misses


def test_profiles_are_complete_and_documented() -> None:
    """Drift guard: every position has its copy, and the README and .env.example name it."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert set(PROFILES) == set(DeploymentPosition)
    for position, profile in PROFILES.items():
        assert profile.label and profile.summary
        if position is not DeploymentPosition.AUTO:
            assert profile.sees and profile.misses and profile.main_blind_spot
            assert f"`{position.value}`" in readme
            assert position.value in env_example
    assert "HOUND_DEPLOYMENT_POSITION" in readme and "HOUND_DEPLOYMENT_POSITION" in env_example


# ------------------------------------------------------------------------------ API, cache, doctor
def test_api_reports_the_configured_position(settings: Settings, make_event: EventFactory) -> None:
    configured = settings.model_copy(update={"deployment_position": DeploymentPosition.DNS_SERVER})
    runtime = HoundRuntime(configured)
    with TestClient(create_app(configured, runtime), base_url="http://127.0.0.1") as client:
        first = client.get("/api/coverage")
        assert first.status_code == 200
        body = first.json()
        assert body["position"] == "dns_server" and body["position_set"] is True
        assert body["label"] == "DNS server" and body["observed"]["window_hours"] == 24
        runtime.processor.process_batch([make_event(source_ip=LAPTOP)])
        again = client.get("/api/coverage").json()
        assert again["generated_at"] == body["generated_at"]  # cached: the dashboard polls every minute
        assert "coverage" in {tag["name"] for tag in client.get("/openapi.json").json()["tags"]}


def test_cache_expires(runtime: HoundRuntime, settings: Settings, make_event: EventFactory) -> None:
    moments = iter([NOW, NOW + timedelta(seconds=1)])
    service = CoverageService(
        runtime.database, settings, demo=lambda: False, clock=lambda: next(moments), cache_seconds=0
    )
    assert service.coverage().generated_at != service.coverage().generated_at


def test_doctor_states_the_position(settings: Settings) -> None:
    unset = doctor.check_deployment_position(settings)
    assert unset.status is Status.INFO and "HOUND_DEPLOYMENT_POSITION" in unset.detail
    for position in DeploymentPosition:
        if position is DeploymentPosition.AUTO:
            continue
        check = doctor.check_deployment_position(settings.model_copy(update={"deployment_position": position}))
        assert check.status is Status.OK
        assert check.detail == f"{PROFILES[position].label}; does not see {PROFILES[position].main_blind_spot}"
        assert re.fullmatch(r"[ -~]+", check.detail)  # doctor output stays ASCII for any console
