"""Dashboard behaviour, exercised with NiceGUI's user simulation (no browser, no sockets).

The page talks to the *real* FastAPI app in-process (``httpx.ASGITransport``),
so these tests also guard the contract between dashboard and API. Live events
enter through ``LiveEventStream.dispatch`` - the same call the WebSocket reader
makes - and outages are simulated by a transport that can be switched off.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import textwrap
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from nicegui import ui
from nicegui.testing.user import User
from nicegui.testing.user_simulation import user_simulation

from app.api.app import create_app
from app.core.config import DeploymentPosition, Settings
from app.frontend import dashboard as dashboard_module
from app.frontend.client import HoundApiClient, LiveEventStream
from app.frontend.dashboard import FEED_LIMIT, DashboardPage
from app.models.events import PacketType
from app.services.coverage import IPV6_SYN_MISSED, PROFILES, CoverageService
from app.services.runtime import HoundRuntime
from tests.conftest import EventFactory
from tests.mmdb import dbip_file

ROOT = Path(__file__).resolve().parent.parent
LAN_DEVICE = "192.168.1.10"
RISKY_DEVICE = "192.168.1.20"


@pytest.fixture(autouse=True)
def _fast_feed_flush(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dashboard_module, "FLUSH_SECONDS", 0.05)  # keeps the batching, just faster


class SwitchableTransport(httpx.AsyncBaseTransport):
    """Forwards to the in-process app; ``down = True`` behaves like an unreachable server."""

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self._inner = inner
        self.down = False
        self.requests: list[httpx.URL] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request.url)
        if self.down:
            raise httpx.ConnectError("connection refused", request=request)
        return await self._inner.handle_async_request(request)

    def paths(self, path: str) -> list[httpx.URL]:
        return [url for url in self.requests if url.path == path]


@dataclass
class Harness:
    user: User
    page: DashboardPage
    stream: LiveEventStream
    transport: SwitchableTransport
    api: HoundApiClient
    runtime: HoundRuntime


async def wait_for(condition: Callable[[], Any], timeout: float = 3.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not condition():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.02)


@asynccontextmanager
async def open_dashboard(settings: Settings, make_event: EventFactory, *, down: bool = False) -> AsyncIterator[Harness]:
    runtime = HoundRuntime(settings)
    app = create_app(settings, runtime)
    runtime.start(asyncio.get_running_loop())
    runtime.processor.process_batch(
        [
            make_event(source_ip=LAN_DEVICE, domain="example.com", seconds=0),
            make_event(packet_type=PacketType.TCP_SYN, source_ip=LAN_DEVICE, seconds=1),
            make_event(source_ip=RISKY_DEVICE, domain="bad.example", seconds=2),
        ]
    )
    transport = SwitchableTransport(httpx.ASGITransport(app=app))
    transport.down = down
    http = httpx.AsyncClient(transport=transport, base_url="http://testserver")
    api = HoundApiClient("http://testserver", client=http)
    stream = LiveEventStream("ws://127.0.0.1:9/ws/events")  # never started: events arrive via dispatch()
    stream.connected = True  # as if the WebSocket were up; otherwise the page falls back to polling
    pages: list[DashboardPage] = []

    def root() -> None:
        page = DashboardPage(api, stream)
        pages.append(page)
        page.build()

    try:
        async with user_simulation(root) as user:
            await user.open("/")
            yield Harness(user, pages[0], stream, transport, api, runtime)
            # Let NiceGUI's outbox go idle first: on Python 3.11 its asyncio.wait_for() can swallow the
            # teardown cancellation, which stalls shutdown for 2 s (not a Hound issue; gone on 3.12+).
            await asyncio.sleep(0.2)
    finally:
        await http.aclose()
        runtime.stop()


def run(scenario: Callable[[], Any]) -> None:
    asyncio.run(scenario())


def rows(table: ui.table) -> list[dict[str, Any]]:
    return list(table.rows)


# --------------------------------------------------------------------------- rendering


def test_page_renders_api_snapshot(settings: Settings, make_event: EventFactory) -> None:
    async def scenario() -> None:
        async with open_dashboard(settings, make_event) as h:
            user, page = h.user, h.page
            await wait_for(lambda: rows(page.feed_table) and rows(page.devices_table) and rows(page.country_table))
            await user.should_see("Hound")
            await user.should_see("heuristics, not proof of compromise")  # disclaimer is always on the page
            await user.should_see("Live feed")

            assert page.kpi_total.text == "3"
            assert page.kpi_devices.text == "2"
            assert page.kpi_dangerous.text == "1"
            assert page.mode_badge.text == "mode: idle"

            feed = rows(page.feed_table)
            assert [r["device"] for r in feed] == [RISKY_DEVICE, LAN_DEVICE, LAN_DEVICE]  # newest first
            assert feed[0]["risk_level"] == "dangerous" and feed[0]["domain"] == "bad.example"
            assert not page.feed_loading.visible

            devices = rows(page.devices_table)
            assert devices[0]["ip"] == RISKY_DEVICE  # sorted by risk
            assert {d["ip"] for d in devices} == {LAN_DEVICE, RISKY_DEVICE}

            countries = rows(page.country_table)
            assert [c["code"] for c in countries] == ["US"]  # LAN destinations excluded by default
            assert countries[0]["percentage"] == "100.0%"
            assert "SIMULATED" in page.country_note.text
            assert page.country_chart.options["series"][0]["data"] == [100.0]
            assert not page.error_banner.visible

    run(scenario)


def test_include_local_switch_requeries_countries(settings: Settings, make_event: EventFactory) -> None:
    async def scenario() -> None:
        async with open_dashboard(settings, make_event) as h:
            await wait_for(lambda: rows(h.page.country_table))
            h.user.find("Include local network").click()
            await wait_for(lambda: len(rows(h.page.country_table)) > 1)
            queries = [url.params.get("include_local") for url in h.transport.paths("/api/stats/countries")]
            assert queries[-1] == "true" and "false" in queries

    run(scenario)


# --------------------------------------------------------------------------- live updates


def live_event(event_id: int, level: str, source_ip: str = LAN_DEVICE) -> dict[str, Any]:
    return {
        "id": event_id,
        "timestamp": "2026-01-15T12:00:00Z",
        "source_ip": source_ip,
        "destination_ip": "93.184.216.34",
        "destination_port": 443,
        "protocol": "TCP",
        "packet_type": "tcp_syn",
        "risk_level": level,
        "risk_score": {"safe": 0, "suspicious": 30, "dangerous": 80}[level],
        "risk_reasons": [],
    }


def test_live_events_are_batched_into_the_feed(settings: Settings, make_event: EventFactory) -> None:
    async def scenario() -> None:
        async with open_dashboard(settings, make_event) as h:
            page = h.page
            await wait_for(lambda: len(rows(page.feed_table)) == 3)
            for event_id in (901, 902, 903):
                h.stream.dispatch({"type": "event", "data": live_event(event_id, "safe")})
            h.stream.dispatch({"type": "stats", "data": {}})  # non-event messages are ignored
            assert len(rows(page.feed_table)) == 3  # buffered, not rendered per packet
            await wait_for(lambda: len(rows(page.feed_table)) == 6)
            assert [r["id"] for r in rows(page.feed_table)[:3]] == [903, 902, 901]

            for event_id in range(1000, 1000 + FEED_LIMIT + 50):  # a burst never grows the table unbounded
                h.stream.dispatch({"type": "event", "data": live_event(event_id, "safe")})
            await wait_for(lambda: rows(page.feed_table)[0]["id"] == 1000 + FEED_LIMIT + 49)
            assert len(rows(page.feed_table)) == FEED_LIMIT

    run(scenario)


def test_risk_filter_applies_to_snapshot_and_live_events(settings: Settings, make_event: EventFactory) -> None:
    async def scenario() -> None:
        async with open_dashboard(settings, make_event) as h:
            page = h.page
            await wait_for(lambda: len(rows(page.feed_table)) == 3)
            with h.user:
                h.user.find(ui.toggle).elements.pop().value = "dangerous"
            await wait_for(lambda: len(rows(page.feed_table)) == 1)
            assert h.transport.paths("/api/events")[-1].params["min_risk_level"] == "dangerous"

            h.stream.dispatch({"type": "event", "data": live_event(950, "safe")})
            h.stream.dispatch({"type": "event", "data": live_event(951, "dangerous")})
            await wait_for(lambda: len(rows(page.feed_table)) == 2)
            assert [r["risk_level"] for r in rows(page.feed_table)] == ["dangerous", "dangerous"]

    run(scenario)


def test_pause_holds_live_events_and_reloads_on_resume(settings: Settings, make_event: EventFactory) -> None:
    async def scenario() -> None:
        async with open_dashboard(settings, make_event) as h:
            page = h.page
            await wait_for(lambda: len(rows(page.feed_table)) == 3)
            h.user.find("Pause").click()
            await wait_for(lambda: page._paused)  # handlers run as tasks
            for event_id in (960, 961):
                h.stream.dispatch({"type": "event", "data": live_event(event_id, "safe")})
            await asyncio.sleep(0.25)  # several flush intervals
            assert len(rows(page.feed_table)) == 3
            await page._load_stats()
            assert "2 new events while paused" in page.feed_note.text

            h.runtime.processor.process_batch([make_event(domain="after-pause.example", seconds=10)])
            h.user.find("Pause").click()
            await wait_for(lambda: len(rows(page.feed_table)) == 4)  # resume re-reads the stored feed
            assert rows(page.feed_table)[0]["domain"] == "after-pause.example"

    run(scenario)


def test_stream_down_shows_reconnecting_and_polls(settings: Settings, make_event: EventFactory) -> None:
    async def scenario() -> None:
        async with open_dashboard(settings, make_event) as h:
            await wait_for(lambda: rows(h.page.feed_table))
            h.stream.connected = False
            polls = len(h.transport.paths("/api/events"))
            h.page._last_poll = 0.0
            await h.page._stats_tick()
            assert h.page.live_badge.text == "○ reconnecting"
            assert len(h.transport.paths("/api/events")) == polls + 1  # polling fallback

            h.stream.connected = True
            await h.page._stats_tick()
            assert h.page.live_badge.text == "● live"
            assert len(h.transport.paths("/api/events")) == polls + 1  # no polling while live

    run(scenario)


# --------------------------------------------------------------------------- dialogs


def test_clicking_an_event_opens_its_details(settings: Settings, make_event: EventFactory) -> None:
    async def scenario() -> None:
        async with open_dashboard(settings, make_event) as h:
            await wait_for(lambda: rows(h.page.feed_table))
            risky = rows(h.page.feed_table)[0]
            h.user.find(marker="feed-table").trigger("rowClick", [{}, risky, 0])
            await wait_for(lambda: h.page.detail_dialog.value)
            await h.user.should_see("Event details")
            await h.user.should_see(f"Event #{risky['id']}")
            await h.user.should_see("bad.example")
            await h.user.should_see("Risk indicators")
            await h.user.should_see("not proof that a device is compromised")

            h.user.find(marker="feed-table").trigger("rowClick", [{}, {"time": "no id"}, 0])  # ignored safely
            await asyncio.sleep(0.05)
            await h.user.should_see(f"Event #{risky['id']}")
            h.page.detail_dialog.close()
            assert not h.page.detail_dialog.value

    run(scenario)


def test_safe_event_details_say_no_indicators(settings: Settings, make_event: EventFactory) -> None:
    async def scenario() -> None:
        async with open_dashboard(settings, make_event) as h:
            await wait_for(lambda: rows(h.page.feed_table))
            safe = next(r for r in rows(h.page.feed_table) if r["risk_score"] == 0)
            h.user.find(marker="feed-table").trigger("rowClick", [{}, safe, 0])
            await h.user.should_see("No risk indicators were identified for this event.")

    run(scenario)


def test_clicking_a_device_opens_its_profile(settings: Settings, make_event: EventFactory) -> None:
    async def scenario() -> None:
        async with open_dashboard(settings, make_event) as h:
            await wait_for(lambda: rows(h.page.devices_table))
            h.user.find(marker="devices-table").trigger("rowClick", [{}, {"ip": RISKY_DEVICE}, 0])
            await h.user.should_see(f"Device {RISKY_DEVICE}")
            await h.user.should_see("Recent observations")
            await h.user.should_see("Risk score")
            await h.user.should_see("1 events · 1 DNS queries · 0 connection attempts")
            assert any(url.params.get("source_ip") == RISKY_DEVICE for url in h.transport.paths("/api/events"))

            quiet = "192.168.1.30"
            h.runtime.processor.process_batch([make_event(source_ip=quiet, domain="example.org", seconds=5)])
            h.user.find(marker="devices-table").trigger("rowClick", [{}, {"ip": quiet}, 0])
            await h.user.should_see(f"Device {quiet}")
            await h.user.should_see("No risk indicators observed for this device.")
            await h.user.should_not_see(f"Device {RISKY_DEVICE}")  # dialog content is replaced, not stacked

    run(scenario)


# --------------------------------------------------------------------------- geolocation (ADR-029)


def test_country_source_and_db_ip_credit(settings: Settings, make_event: EventFactory) -> None:
    async def scenario() -> None:
        async with open_dashboard(settings, make_event) as h:  # the fixture's illustrative data
            await wait_for(lambda: "SIMULATED" in h.page.country_note.text)
            assert not h.page.geo_credit.visible
        real = settings.model_copy(update={"geo_mode": "auto"})
        dbip_file(real.geoip_dir, "2026-09")
        async with open_dashboard(real, make_event) as h:
            await wait_for(lambda: "countries from DB-IP Lite 2026-09" in h.page.country_note.text)
            assert h.page.geo_credit.visible
            assert h.page.geo_credit.props["href"] == "https://db-ip.com"
            await h.user.should_see("IP Geolocation by DB-IP")
            h.runtime.geo.locator.close()  # type: ignore[attr-defined]
        unknown = settings.model_copy(update={"geo_mode": "dbip", "geoip_dir": real.geoip_dir / "empty"})
        async with open_dashboard(unknown, make_event) as h:
            await wait_for(lambda: "no geolocation database yet" in h.page.country_note.text)
            assert not h.page.geo_credit.visible

    run(scenario)


# --------------------------------------------------------------------------- downloads (17b)


def test_download_links_follow_the_feed_filter(settings: Settings, make_event: EventFactory) -> None:
    async def scenario() -> None:
        async with open_dashboard(settings, make_event) as h:
            page = h.page
            href = {fmt: lambda fmt=fmt: page.export_events[fmt].props["href"] for fmt in ("csv", "json")}
            assert href["csv"]() == "/api/export/events?format=csv"
            assert href["json"]() == "/api/export/events?format=json"
            await page._set_min_level("suspicious")
            assert href["csv"]() == "/api/export/events?format=csv&min_risk_level=suspicious"
            await page._set_min_level("safe")
            assert href["json"]() == "/api/export/events?format=json"
            devices = h.user.find(marker="download-devices-csv").elements.pop()
            assert devices.props["href"] == "/api/export/devices?format=csv" and "download" in devices.props

            # the links point at endpoints that exist and honour the filter
            http = httpx.AsyncClient(
                transport=httpx.ASGITransport(app=create_app(settings, h.runtime)), base_url="http://127.0.0.1"
            )
            async with http:
                every = (await http.get("/api/export/events?format=json")).json()
                risky = (await http.get("/api/export/events?format=json&min_risk_level=suspicious")).json()
            assert len(every) == 3 and [e["domain"] for e in risky] == ["bad.example"]

    run(scenario)


# --------------------------------------------------------------------------- coverage (ADR-026)


def test_coverage_note_is_always_on_the_page(settings: Settings, make_event: EventFactory) -> None:
    async def scenario() -> None:
        async with open_dashboard(settings, make_event) as h:
            page = h.page
            await wait_for(lambda: "Position not set" in page.coverage_label.text)
            assert "Not enough traffic yet" in page.coverage_label.text  # the 3 fixture events are months old
            assert "hound-coverage" in page.coverage_row.classes
            assert "hound-coverage-warning" not in page.coverage_row.classes

            h.user.find(marker="coverage-details").click()
            await h.user.should_see("What Hound can see · Position not set")
            await h.user.should_see("Does not see")
            await h.user.should_see(f"• {IPV6_SYN_MISSED}")
            await h.user.should_see("0 IPv4 devices (none)")

    run(scenario)


def test_coverage_warning_is_highlighted_and_explained(settings: Settings, make_event: EventFactory) -> None:
    async def scenario() -> None:
        gateway = settings.model_copy(update={"deployment_position": DeploymentPosition.GATEWAY})
        async with open_dashboard(gateway, make_event) as h:
            page = h.page
            await wait_for(lambda: "Router / gateway" in page.coverage_label.text)
            now = datetime.now(UTC)
            h.runtime.processor.process_batch(
                [make_event(source_ip=LAN_DEVICE, timestamp=now - timedelta(minutes=n)) for n in range(60)]
            )
            h.runtime.coverage = CoverageService(h.runtime.database, gateway, demo=lambda: False, cache_seconds=0)
            await page._load_coverage()
            assert page.coverage_label.text.startswith("⚠ Router / gateway: Only one device (192.168.1.10)")
            assert "hound-coverage-warning" in page.coverage_row.classes
            assert "hound-coverage" not in page.coverage_row.classes

            h.user.find(marker="coverage-details").click()
            await h.user.should_see("Sees")
            await h.user.should_see(f"• {PROFILES[DeploymentPosition.GATEWAY].misses[1]}")
            await h.user.should_see("1 IPv4 devices (192.168.1.10)")

    run(scenario)


def test_coverage_is_refreshed_once_a_minute(
    settings: Settings, make_event: EventFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:
        async with open_dashboard(settings, make_event) as h:
            await wait_for(lambda: len(h.transport.paths("/api/coverage")) == 1)
            await h.page._slow_tick()
            assert len(h.transport.paths("/api/coverage")) == 1  # not on every slow tick
            monkeypatch.setattr(dashboard_module, "COVERAGE_SECONDS", 0.0)
            await h.page._slow_tick()
            assert len(h.transport.paths("/api/coverage")) == 2

    run(scenario)


# --------------------------------------------------------------------------- failure handling


def test_unreachable_api_shows_banner_and_recovers(settings: Settings, make_event: EventFactory) -> None:
    async def scenario() -> None:
        async with open_dashboard(settings, make_event, down=True) as h:
            page = h.page
            await wait_for(lambda: page.error_banner.visible)
            await h.user.should_see("Cannot reach the Hound API")
            assert "Retrying automatically" in page.error_banner.text
            assert page.kpi_status.text == "Offline"
            await wait_for(lambda: not page.feed_loading.visible)  # the spinner never hangs on a failed load
            assert rows(page.feed_table) == []

            h.user.find(marker="feed-table").trigger("rowClick", [{}, {"id": 1}, 0])
            await wait_for(lambda: h.user.notify.contains("Could not load event"))
            h.user.find(marker="devices-table").trigger("rowClick", [{}, {"ip": LAN_DEVICE}, 0])
            await wait_for(lambda: h.user.notify.contains("Could not load device"))
            h.user.find(marker="coverage-details").click()
            await wait_for(lambda: h.user.notify.contains("Could not load coverage information"))
            assert page.coverage_label.text == "Checking what Hound can see…"
            assert not page.detail_dialog.value

            h.transport.down = False
            await page._load_stats()
            assert not page.error_banner.visible
            assert page.kpi_total.text == "3"

    run(scenario)


def test_pipeline_states_are_explained(settings: Settings, make_event: EventFactory) -> None:
    async def scenario() -> None:
        async with open_dashboard(settings, make_event) as h:
            page = h.page
            await wait_for(lambda: page.mode_badge.text == "mode: idle")
            assert page.kpi_status.text == "Listening"
            assert not page.info_banner.visible  # events already processed: no "start the daemon" hint

            page._render_pipeline({"mode": "idle", "source_state": "idle", "events_processed": 0})
            assert page.info_banner.visible and "capture daemon" in page.info_banner.text

            page._render_pipeline({"mode": "capture", "source_state": "error", "source_error": "no permission"})
            assert page.kpi_status.text == "Degraded"
            assert "no permission" in page.info_banner.text and page.info_banner.visible
            assert page.source_badge.props["color"] == "negative"

            page._render_pipeline(
                {"mode": "capture", "source_state": "restarting", "source_error": "Wi-Fi went down. Restarting"}
            )
            assert page.kpi_status.text == "Reconnecting" and page.info_banner.visible
            assert "Capture interrupted: Wi-Fi went down" in page.info_banner.text
            assert page.source_badge.props["color"] == "warning"

            page._render_pipeline({"mode": "demo", "source_state": "running"})
            assert page.kpi_status.text == "Demo" and "nothing is captured" in page.info_banner.text

            page._render_pipeline({"mode": "capture", "source_state": "running", "events_dropped": 7})
            assert page.kpi_status.text == "Capturing" and not page.info_banner.visible
            assert page.feed_note.text == "7 dropped under load"

    run(scenario)


# --------------------------------------------------------------------------- mounting


MOUNT_PROBE = textwrap.dedent(
    """
    import sys
    from fastapi.testclient import TestClient
    from app.api.app import create_app
    from app.core.config import DeploymentPosition, Settings
    from app.frontend.dashboard import mount_dashboard

    settings = Settings(_env_file=None, database_url="sqlite:///" + sys.argv[1], allowed_hosts="testserver")
    app = create_app(settings, dashboard=True)
    response = TestClient(app).get("/")
    assert response.status_code == 200, response.status_code
    assert "Hound" in response.text, "page title missing"
    try:
        mount_dashboard(app, settings)
    except RuntimeError as exc:
        assert "only be mounted once" in str(exc)
    else:
        raise SystemExit("second mount was accepted")
    assert TestClient(app).get("/health").status_code == 200  # API routes still win over the UI mount
    print("MOUNT-OK")
    """
)


def test_mounted_dashboard_serves_page_once_per_process(tmp_path: Path) -> None:
    # Separate interpreter: ui.run_with() mutates NiceGUI's process-wide state.
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    result = subprocess.run(
        [sys.executable, "-c", MOUNT_PROBE, str(tmp_path / "mount.db")],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "MOUNT-OK" in result.stdout
