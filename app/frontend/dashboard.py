"""NiceGUI dashboard, mounted on the FastAPI app.

Data flow: REST (``HoundApiClient``) for snapshots, WebSocket
(``LiveEventStream``) for new events. Incoming events are buffered and
flushed into the table on a short UI timer, so a burst of traffic never
causes one browser update per packet. If the WebSocket is down the page
falls back to polling ``/api/events``.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from typing import Any

from fastapi import FastAPI
from nicegui import app as nicegui_app
from nicegui import ui

from app.core.config import Settings
from app.frontend.client import ApiError, HoundApiClient, LiveEventStream
from app.frontend.components import (
    COUNTRY_COLUMNS,
    CSS,
    DEVICE_COLUMNS,
    FEED_COLUMNS,
    country_chart_options,
    event_details,
    kpi_card,
    risk_table,
    row_from_click,
)
from app.frontend.formatting import (
    RISK_COLOR,
    RISK_LABEL,
    country_rows,
    device_row,
    event_row,
    fmt_datetime,
    passes_min_level,
)

logger = logging.getLogger(__name__)

FEED_LIMIT = 200
FLUSH_SECONDS = 0.5
STATS_SECONDS = 2.0
SLOW_SECONDS = 5.0
STATS_MAX_AGE = 10.0
DISCLAIMER = (
    "Risk levels summarise indicators associated with elevated risk; they are heuristics, not proof of "
    "compromise. Country data is simulated unless a real GeoIP source is configured. "
    "Only monitor networks you own or are authorised to monitor."
)


class DashboardPage:
    """One browser tab's dashboard state."""

    def __init__(self, api: HoundApiClient, stream: LiveEventStream) -> None:
        self.api = api
        self.stream = stream
        self._pending: deque[dict[str, Any]] = deque(maxlen=FEED_LIMIT)
        self._stats_dirty = True
        self._slow_dirty = True
        self._last_stats = 0.0
        self._last_poll = 0.0
        self._missed = 0
        self._min_level = "safe"
        self._paused = False
        self._include_local = False

    # ------------------------------------------------------------------ layout
    def build(self) -> None:
        ui.add_css(CSS)
        dark = ui.dark_mode(None)
        self._header(dark)
        with ui.column().classes("w-full max-w-screen-2xl mx-auto q-pa-md gap-4"):
            self.error_banner = ui.label("").classes("w-full q-pa-sm rounded bg-negative text-white")
            self.error_banner.set_visibility(False)
            self.info_banner = ui.label("").classes("w-full q-pa-sm rounded hound-info")
            self.info_banner.set_visibility(False)
            self._kpis()
            with ui.tabs().classes("w-full").props("align=left inline-label") as tabs:
                feed_tab = ui.tab("feed", label="Live feed", icon="bolt")
                devices_tab = ui.tab("devices", label="Devices", icon="devices")
                countries_tab = ui.tab("countries", label="Countries", icon="public")
            with ui.tab_panels(tabs, value=feed_tab).classes("w-full"):
                with ui.tab_panel(feed_tab):
                    self._feed_panel()
                with ui.tab_panel(devices_tab):
                    self._devices_panel()
                with ui.tab_panel(countries_tab):
                    self._countries_panel()
            ui.label(DISCLAIMER).classes("hound-muted")
        self.detail_dialog = ui.dialog()

        unsubscribe = self.stream.subscribe(self._on_live_event)
        ui.context.client.on_delete(unsubscribe)
        ui.timer(FLUSH_SECONDS, self._flush_feed)
        ui.timer(STATS_SECONDS, self._stats_tick)
        ui.timer(SLOW_SECONDS, self._slow_tick)
        ui.timer(0.05, self._initial_load, once=True)

    def _header(self, dark: Any) -> None:
        with ui.header().classes("hound-header items-center justify-between q-px-md"):
            with ui.row().classes("items-center gap-3 no-wrap"):
                ui.label("🐕").classes("text-2xl")
                with ui.column().classes("gap-0"):
                    ui.label("Hound").classes("text-xl font-bold")
                    ui.label("Home network monitor").classes("text-xs opacity-80")
            with ui.row().classes("items-center gap-2"):
                self.mode_badge = ui.badge("mode …", color="blue-grey")
                self.source_badge = ui.badge("source …", color="blue-grey")
                self.live_badge = ui.badge("connecting…", color="grey")
                ui.button(icon="contrast", on_click=dark.toggle).props("flat round color=white").tooltip("Toggle theme")

    def _kpis(self) -> None:
        with ui.row().classes("w-full gap-3 items-stretch"):
            self.kpi_total = kpi_card("Total events", "stacked_line_chart")
            self.kpi_devices = kpi_card("Devices", "devices")
            self.kpi_suspicious = kpi_card("🟡 Suspicious", "warning")
            self.kpi_dangerous = kpi_card("🔴 Dangerous", "gpp_bad")
            self.kpi_minute = kpi_card("Last minute", "schedule")
            self.kpi_status = kpi_card("Status", "monitor_heart")

    def _feed_panel(self) -> None:
        with ui.row().classes("items-center gap-4 q-mb-sm"):
            ui.toggle(
                {"safe": "All", "suspicious": "Suspicious +", "dangerous": "Dangerous"},
                value="safe",
                on_change=lambda e: self._set_min_level(e.value),
            )
            ui.switch("Pause", on_change=lambda e: self._set_paused(bool(e.value)))
            self.feed_note = ui.label("").classes("hound-muted")
        self.feed_loading = ui.spinner(size="lg")
        self.feed_table = risk_table(FEED_COLUMNS, "id", "No events yet — waiting for traffic…", rows_per_page=25)
        self.feed_table.on("rowClick", lambda e: self._open_event(row_from_click(e.args)))
        ui.label("Newest first · click a row for details").classes("hound-muted")

    def _devices_panel(self) -> None:
        self.devices_table = risk_table(DEVICE_COLUMNS, "ip", "No devices observed yet.", rows_per_page=20)
        self.devices_table.on("rowClick", lambda e: self._open_device(row_from_click(e.args)))
        ui.label(
            "Device risk score = highest event score within the device risk window. Click a device to inspect it."
        ).classes("hound-muted")

    def _countries_panel(self) -> None:
        with ui.row().classes("items-center gap-4"):
            ui.switch("Include local network", on_change=lambda e: self._set_include_local(bool(e.value)))
            self.country_note = ui.label("").classes("hound-muted")
        ui.label(
            "Share of events by destination country — each event is one DNS query or one TCP connection attempt."
        ).classes("text-subtitle2")
        with ui.row().classes("w-full gap-4 items-start"):
            self.country_chart = (
                ui.echart(country_chart_options([]))
                .classes("grow")
                .style("height: 380px; min-width: 280px; flex: 2 1 420px")
            )
            self.country_table = ui.table(columns=COUNTRY_COLUMNS, rows=[], row_key="code").style("flex: 1 1 260px")
            self.country_table.props('flat bordered dense no-data-label="No public-destination events yet."')

    # ------------------------------------------------------------------ live updates
    def _on_live_event(self, event: dict[str, Any]) -> None:
        """Called by the stream for every event; only buffers (no UI work here)."""
        self._stats_dirty = True
        self._slow_dirty = True
        if self._paused:
            self._missed += 1
            return
        if passes_min_level(event.get("risk_level"), self._min_level):
            self._pending.append(event_row(event))

    def _flush_feed(self) -> None:
        if not self._pending:
            return
        new_rows = list(reversed(self._pending))
        self._pending.clear()
        self.feed_table.rows = (new_rows + list(self.feed_table.rows))[:FEED_LIMIT]
        self.feed_table.update()

    async def _stats_tick(self) -> None:
        self.live_badge.set_text("● live" if self.stream.connected else "○ reconnecting")
        self.live_badge.props(f"color={'positive' if self.stream.connected else 'grey'}")
        now = time.monotonic()
        if self._stats_dirty or now - self._last_stats > STATS_MAX_AGE:
            self._stats_dirty = False
            self._last_stats = now
            await self._load_stats()
        if not self.stream.connected and now - self._last_poll > SLOW_SECONDS:
            self._last_poll = now  # polling fallback while the WebSocket is down
            await self._load_feed()

    async def _slow_tick(self) -> None:
        if self._slow_dirty:
            self._slow_dirty = False
            await self._load_devices()
            await self._load_countries()

    # ------------------------------------------------------------------ data loading
    async def _initial_load(self) -> None:
        await self._load_stats()
        await self._load_feed()
        await self._load_devices()
        await self._load_countries()

    def _show_error(self, message: str) -> None:
        self.error_banner.set_text(f"⚠ {message}. Retrying automatically…")
        self.error_banner.set_visibility(True)

    def _clear_error(self) -> None:
        self.error_banner.set_visibility(False)

    async def _load_stats(self) -> None:
        try:
            stats = await self.api.stats()
        except ApiError as exc:
            self._show_error(str(exc))
            self.kpi_status.set_text("Offline")
            return
        self._clear_error()
        self.kpi_total.set_text(f"{stats['total_events']:,}")
        self.kpi_devices.set_text(f"{stats['devices']:,}")
        self.kpi_suspicious.set_text(f"{stats['suspicious_events']:,}")
        self.kpi_dangerous.set_text(f"{stats['dangerous_events']:,}")
        self.kpi_minute.set_text(f"{stats['events_last_minute']:,}")
        self._render_pipeline(stats["pipeline"])

    def _render_pipeline(self, pipeline: dict[str, Any]) -> None:
        mode, state = pipeline.get("mode", "idle"), pipeline.get("source_state", "idle")
        self.mode_badge.set_text(f"mode: {mode}")
        self.source_badge.set_text(f"source: {state}")
        color = {"running": "positive", "error": "negative", "idle": "blue-grey"}.get(state, "grey")
        self.source_badge.props(f"color={color}")
        if state == "error":
            self.kpi_status.set_text("Degraded")
            self.info_banner.set_text(f"Event source problem: {pipeline.get('source_error') or 'unknown error'}")
            self.info_banner.set_visibility(True)
        elif mode == "demo":
            self.kpi_status.set_text("Demo")
            self.info_banner.set_text("Demo mode: showing synthetic traffic generated locally — nothing is captured.")
            self.info_banner.set_visibility(True)
        elif mode == "idle":
            self.kpi_status.set_text("Listening")
            self.info_banner.set_text(
                "No in-process capture. Start the capture daemon (python run.py capture -i <interface>) "
                "to stream events here, or restart with --demo."
            )
            self.info_banner.set_visibility(pipeline.get("events_processed", 0) == 0)
        else:
            self.kpi_status.set_text("Capturing")
            self.info_banner.set_visibility(False)
        dropped = pipeline.get("events_dropped", 0)
        self.feed_note.set_text(
            (f"{self._missed} new events while paused · " if self._paused and self._missed else "")
            + (f"{dropped} dropped under load" if dropped else "")
        )

    async def _load_feed(self) -> None:
        params: dict[str, Any] = {"limit": FEED_LIMIT}
        if self._min_level != "safe":
            params["min_risk_level"] = self._min_level
        try:
            page = await self.api.events(**params)
        except ApiError as exc:
            self._show_error(str(exc))
            return
        finally:
            self.feed_loading.set_visibility(False)
        self._pending.clear()
        self.feed_table.rows = [event_row(e) for e in page.get("items", [])]
        self.feed_table.update()

    async def _load_devices(self) -> None:
        try:
            page = await self.api.devices(limit=200, sort="risk")
        except ApiError as exc:
            self._show_error(str(exc))
            return
        self.devices_table.rows = [device_row(d) for d in page.get("items", [])]
        self.devices_table.update()

    async def _load_countries(self) -> None:
        try:
            payload = await self.api.countries(include_local=self._include_local)
        except ApiError as exc:
            self._show_error(str(exc))
            return
        rows = country_rows(payload)
        self.country_table.rows = [{k: r[k] for k in ("country", "code", "events", "percentage")} for r in rows]
        self.country_table.update()
        self.country_chart.options.clear()
        self.country_chart.options.update(country_chart_options(rows))
        self.country_chart.update()
        simulated = " · geolocation is SIMULATED (not authoritative)" if payload.get("simulated") else ""
        self.country_note.set_text(f"{payload.get('total_events', 0):,} events{simulated}")

    # ------------------------------------------------------------------ interactions
    async def _set_min_level(self, level: str) -> None:
        self._min_level = level
        await self._load_feed()

    async def _set_paused(self, paused: bool) -> None:
        self._paused = paused
        if not paused:
            self._missed = 0
            await self._load_feed()

    async def _set_include_local(self, include: bool) -> None:
        self._include_local = include
        await self._load_countries()

    async def _open_event(self, row: dict[str, Any] | None) -> None:
        if not row or row.get("id") is None:
            return
        try:
            event = await self.api.event(int(row["id"]))
        except ApiError as exc:
            ui.notify(f"Could not load event: {exc}", type="negative")
            return
        self.detail_dialog.clear()
        with self.detail_dialog, ui.card().classes("w-full").style("max-width: 720px"):
            with ui.row().classes("w-full items-center justify-between"):
                ui.label("Event details").classes("text-h6")
                ui.button(icon="close", on_click=self.detail_dialog.close).props("flat round")
            event_details(ui.column().classes("w-full gap-1"), event)
        self.detail_dialog.open()

    async def _open_device(self, row: dict[str, Any] | None) -> None:
        if not row or not row.get("ip"):
            return
        ip = str(row["ip"])
        try:
            device = await self.api.device(ip)
            events = await self.api.events(source_ip=ip, limit=100)
        except ApiError as exc:
            ui.notify(f"Could not load device: {exc}", type="negative")
            return
        level = str(device.get("risk_level") or "safe")
        self.detail_dialog.clear()
        with self.detail_dialog, ui.card().classes("w-full").style("max-width: 1100px"):
            with ui.row().classes("w-full items-center justify-between"):
                ui.label(f"Device {ip}").classes("text-h6")
                ui.button(icon="close", on_click=self.detail_dialog.close).props("flat round")
            with ui.row().classes("items-center gap-3"):
                ui.badge(RISK_LABEL.get(level, level), color=RISK_COLOR.get(level, "grey"))
                ui.label(f"Risk score {device.get('risk_score', 0)}/100")
                ui.label(
                    f"{device.get('event_count', 0):,} events · {device.get('dns_query_count', 0):,} DNS queries · "
                    f"{device.get('connection_attempt_count', 0):,} connection attempts"
                ).classes("hound-muted")
            ui.label(
                f"First seen {fmt_datetime(device.get('first_seen'))} · "
                f"last seen {fmt_datetime(device.get('last_seen'))}"
            ).classes("hound-muted")
            observations = device.get("observations") or []
            ui.label("Recent observations").classes("text-subtitle2 q-mt-sm")
            if not observations:
                ui.label("No risk indicators observed for this device.").classes("hound-muted")
            for obs in reversed(observations):
                ui.label(f"• {obs.get('description')} ({fmt_datetime(obs.get('last_seen'))})")
            ui.label("Recent activity").classes("text-subtitle2 q-mt-sm")
            table = risk_table(FEED_COLUMNS, "id", "No stored events for this device.", rows_per_page=10)
            table.rows = [event_row(e) for e in events.get("items", [])]
            table.on("rowClick", lambda e: self._open_event(row_from_click(e.args)))
        self.detail_dialog.open()


_mounted = False


def mount_dashboard(app: FastAPI, settings: Settings) -> None:
    """Register the dashboard page and mount NiceGUI on ``app`` (once per process)."""
    global _mounted  # NiceGUI's page registry is process-wide; guard against double mounting
    if _mounted:
        raise RuntimeError("The dashboard can only be mounted once per process")
    _mounted = True

    api = HoundApiClient(settings.api_base_url)
    stream = LiveEventStream(settings.ws_events_url)
    nicegui_app.on_startup(stream.start)
    nicegui_app.on_shutdown(stream.stop)
    nicegui_app.on_shutdown(api.aclose)

    @ui.page("/", title="Hound · network monitor")
    def index() -> None:
        DashboardPage(api, stream).build()

    ui.run_with(
        app,
        mount_path="/",
        title="Hound",
        favicon="🐕",
        dark=None,
        reconnect_timeout=10.0,
        show_welcome_message=False,
    )
