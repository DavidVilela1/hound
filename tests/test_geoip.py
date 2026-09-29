"""Real geolocation from DB-IP Lite (ADR-029): reading, safe download, hot swap, reporting.

The databases here are written by ``tests/mmdb.py`` in the real .mmdb format and read by
the real ``maxminddb`` reader; downloads go through a fake ``urlopen`` — no test touches
the internet.
"""

from __future__ import annotations

import gzip
import io
import logging
import urllib.error
from collections.abc import Iterator
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app import cli
from app.api.app import create_app
from app.core.config import Settings
from app.enrichment import geoip
from app.enrichment.geo import country_name, select_geolocator
from app.enrichment.geoip import (
    DOWNLOAD_URL,
    GeoIpError,
    GeoIpUpdater,
    MmdbGeoLocator,
    country_code,
    download_dbip,
    installed_databases,
)
from app.models.events import PacketType
from app.services import doctor
from app.services.doctor import Status
from app.services.runtime import HoundRuntime, RunMode
from tests.conftest import EventFactory
from tests.mmdb import NETWORKS, country, dbip_file, write_mmdb

TODAY = date(2026, 9, 29)


def gzipped(path: Path) -> bytes:
    return gzip.compress(path.read_bytes())


class FakeResponse(io.BytesIO):
    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class FakeServer:
    """Serves ``{month: body}``; any other month is a 404."""

    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = files
        self.requests: list[Any] = []

    def __call__(self, request: Any, timeout: float) -> FakeResponse:
        self.requests.append(request)
        for month, body in self.files.items():
            if request.full_url == DOWNLOAD_URL.format(month=month):
                return FakeResponse(body)
        raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, None)  # type: ignore[arg-type]


@pytest.fixture
def published(tmp_path: Path) -> dict[str, bytes]:
    source = tmp_path / "published"
    return {
        "2026-09": gzipped(dbip_file(source, "2026-09")),
        "2026-08": gzipped(dbip_file(source, "2026-08", {**NETWORKS, "81.0.0.0/8": country("ES")})),
    }


# ------------------------------------------------------------------------------ reading
def test_lookups(tmp_path: Path) -> None:
    locator = MmdbGeoLocator.open(dbip_file(tmp_path, "2026-09"))
    try:
        assert locator.locate("8.8.8.8") == "US"
        assert locator.locate("81.20.30.40") == "PT"
        assert locator.locate("2001:4860::8888") == "US"
        assert locator.locate("9.9.9.9") is None  # public but not in the database
        assert locator.locate("192.168.1.10") == "LAN"
        assert locator.locate("fe80::1") == "LAN"
        assert locator.locate("not-an-ip") is None
        assert locator.info.month == "2026-09" and locator.info.database_type == "DBIP-Country-Lite"
        assert locator.info.built == datetime.fromtimestamp(1_788_000_000, UTC)
    finally:
        locator.close()


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ({"country": {"iso_code": "pt"}}, "PT"),
        ({"registered_country": {"iso_code": "DE"}}, "DE"),  # no physical country: registration
        ({"country": {"iso_code": "USA"}}, None),
        ({"country": {"iso_code": 12}}, None),
        ({"country": "US"}, None),
        (None, None),
        ([], None),
    ],
)
def test_country_code_is_read_defensively(record: object, expected: str | None) -> None:
    assert country_code(record) == expected


def test_unusable_files_are_refused(tmp_path: Path) -> None:
    garbage = tmp_path / "dbip-country-lite-2026-09.mmdb"
    garbage.write_bytes(b"\x00" * 4096)
    with pytest.raises(GeoIpError, match="not a readable"):
        MmdbGeoLocator.open(garbage)
    city_less = write_mmdb(tmp_path / "other.mmdb", {"81.0.0.0/8": country("PT")})  # no answer for 8.8.8.8
    with pytest.raises(GeoIpError, match="no country for 8.8.8.8"):
        MmdbGeoLocator.open(city_less)


def test_every_country_code_has_a_name() -> None:
    assert country_name("PT") == "Portugal" and country_name("BE") == "Belgium"
    assert country_name("CI") == "Côte d'Ivoire" and country_name("LAN") == "Local network"
    assert country_name("ZZ") == "ZZ" and country_name(None) == "Unknown"


# ------------------------------------------------------------------------------ download
def test_download_installs_this_months_file(tmp_path: Path, published: dict[str, bytes]) -> None:
    target = tmp_path / "geoip"
    dbip_file(target, "2026-07")  # an older release, to be replaced
    server = FakeServer(published)
    info = download_dbip(target, TODAY, urlopen=server)
    assert info.month == "2026-09" and info.path == target / "dbip-country-lite-2026-09.mmdb"
    assert [p.name for p in installed_databases(target)] == ["dbip-country-lite-2026-09.mmdb"]
    assert [p.name for p in target.iterdir()] == ["dbip-country-lite-2026-09.mmdb"]  # no .part left
    request = server.requests[0]
    assert request.full_url == "https://download.db-ip.com/free/dbip-country-lite-2026-09.mmdb.gz"
    assert request.get_header("User-agent").startswith("Hound/")


def test_early_in_the_month_last_months_file_is_used(tmp_path: Path, published: dict[str, bytes]) -> None:
    server = FakeServer({"2026-08": published["2026-08"]})
    info = download_dbip(tmp_path / "geoip", TODAY, urlopen=server)
    assert info.month == "2026-08" and len(server.requests) == 2


def test_nothing_is_downloaded_twice(tmp_path: Path, published: dict[str, bytes]) -> None:
    target = tmp_path / "geoip"
    server = FakeServer(published)
    download_dbip(target, TODAY, urlopen=server)
    download_dbip(target, TODAY, urlopen=server)
    assert len(server.requests) == 1


def test_nothing_published(tmp_path: Path) -> None:
    with pytest.raises(GeoIpError, match="No DB-IP database available"):
        download_dbip(tmp_path / "geoip", TODAY, urlopen=FakeServer({}))
    assert list((tmp_path / "geoip").iterdir()) == []


@pytest.mark.parametrize(
    ("body", "limits", "message"),
    [
        (b"not gzip at all", {}, "Download of"),
        ("truncated", {}, "ended early"),
        (gzip.compress(b"\x00" * 3000), {"MAX_DATABASE_BYTES": 2000, "CHUNK": 8}, "unpacked file larger"),
        ("valid", {"MAX_DOWNLOAD_BYTES": 100}, "download larger"),
        (gzip.compress(b"\x00" * 3000), {}, "not a readable"),  # a gzip file that is not a database
    ],
)
def test_bad_downloads_leave_nothing_behind(
    tmp_path: Path,
    published: dict[str, bytes],
    monkeypatch: pytest.MonkeyPatch,
    body: bytes | str,
    limits: dict[str, int],
    message: str,
) -> None:
    for name, value in limits.items():
        monkeypatch.setattr(geoip, name, value)
    if body == "truncated":
        body = published["2026-09"][: len(published["2026-09"]) // 2]
    elif body == "valid":
        body = published["2026-09"]
    target = tmp_path / "geoip"
    with pytest.raises(GeoIpError, match=message):
        download_dbip(target, TODAY, urlopen=FakeServer({"2026-09": body}))  # type: ignore[dict-item]
    assert list(target.iterdir()) == []


def test_server_errors_are_not_mistaken_for_missing_releases(tmp_path: Path) -> None:
    def failing(request: Any, timeout: float) -> Any:
        raise urllib.error.HTTPError(request.full_url, 503, "Unavailable", {}, None)  # type: ignore[arg-type]

    with pytest.raises(GeoIpError, match="HTTP 503"):
        download_dbip(tmp_path / "geoip", TODAY, urlopen=failing)


def test_only_db_ip_is_ever_contacted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(geoip, "DOWNLOAD_URL", "https://evil.example/{month}.gz")
    with pytest.raises(GeoIpError, match="refusing to download"):
        download_dbip(tmp_path / "geoip", TODAY, urlopen=FakeServer({}))


# ------------------------------------------------------------------------------ updater
def test_updater_downloads_once_per_retry_window_and_loads_the_file(
    tmp_path: Path, published: dict[str, bytes]
) -> None:
    target = tmp_path / "geoip"
    loaded: list[MmdbGeoLocator] = []
    server = FakeServer({})  # nothing published yet
    updater = GeoIpUpdater(
        target,
        auto_download=True,
        loaded=lambda: loaded[-1].info.path if loaded else None,
        use=loaded.append,
        download=lambda d, today: download_dbip(d, today, urlopen=server),
        today=lambda: TODAY,
    )
    updater.check()
    assert loaded == [] and len(server.requests) == 2 and "No DB-IP database" in (updater.last_error or "")
    updater.check()
    assert len(server.requests) == 2  # no hammering: next attempt only after the retry window
    server.files.update(published)
    updater._last_attempt = None  # the retry window has passed
    updater.check()
    assert [loc.info.month for loc in loaded] == ["2026-09"] and updater.last_error is None
    updater.check()
    assert len(loaded) == 1 and len(server.requests) == 3  # current: nothing to do
    for locator in loaded:
        locator.close()


def test_updater_without_auto_download_only_picks_up_files(tmp_path: Path) -> None:
    target = tmp_path / "geoip"
    loaded: list[MmdbGeoLocator] = []

    def never(directory: Path, today: date) -> Any:
        raise AssertionError("must not download")

    updater = GeoIpUpdater(
        target, auto_download=False, loaded=lambda: None, use=loaded.append, download=never, today=lambda: TODAY
    )
    updater.check()
    assert loaded == []
    dbip_file(target, "2026-09")  # e.g. from `python run.py geo update`
    updater.check()
    assert [loc.info.month for loc in loaded] == ["2026-09"]
    loaded[0].close()


# ------------------------------------------------------------------------------ selection & runtime
@pytest.mark.parametrize(
    ("mode", "installed", "demo", "source"),
    [
        ("auto", True, False, "dbip"),
        ("auto", False, False, "none"),  # live: never invent countries
        ("auto", False, True, "simulated"),  # demo without a database
        ("auto", True, True, "dbip"),
        ("dbip", False, True, "none"),
        ("simulated", True, False, "simulated"),
        ("mapping_only", True, False, "mapping"),
    ],
)
def test_source_selection(
    settings: Settings, tmp_path: Path, mode: str, installed: bool, demo: bool, source: str
) -> None:
    configured = settings.model_copy(update={"geo_mode": mode})
    if installed:
        dbip_file(configured.geoip_dir, "2026-09")
    selection = select_geolocator(configured, demo=demo)
    assert selection.source == source
    if source == "none":
        assert selection.locator.locate("8.8.8.8") is None and selection.locator.locate("10.0.0.1") == "LAN"
    if isinstance(selection.locator, MmdbGeoLocator):
        selection.locator.close()


def test_a_broken_newest_file_falls_back_to_an_older_one(settings: Settings, caplog: pytest.LogCaptureFixture) -> None:
    configured = settings.model_copy(update={"geo_mode": "auto"})
    dbip_file(configured.geoip_dir, "2026-08")
    (configured.geoip_dir / "dbip-country-lite-2026-09.mmdb").write_bytes(b"broken")
    with caplog.at_level(logging.ERROR):
        selection = select_geolocator(configured, demo=False)
    assert selection.database is not None and selection.database.month == "2026-08"
    assert "Skipping unusable geolocation database" in caplog.text
    selection.locator.close()  # type: ignore[attr-defined]


@pytest.fixture
def real_geo(settings: Settings) -> Iterator[tuple[Settings, HoundRuntime]]:
    configured = settings.model_copy(update={"geo_mode": "auto"})
    runtime = HoundRuntime(configured)
    runtime.database.initialize()
    yield configured, runtime
    runtime.stop()


def test_events_get_real_countries_and_the_api_credits_db_ip(
    real_geo: tuple[Settings, HoundRuntime], make_event: EventFactory
) -> None:
    configured, runtime = real_geo
    with TestClient(create_app(configured, runtime), base_url="http://127.0.0.1") as client:
        body = client.get("/api/stats/countries").json()
        assert (body["source"], body["simulated"], body["attribution"]) == ("none", False, None)
        runtime.processor.process_batch([make_event(packet_type=PacketType.TCP_SYN, destination_ip="81.2.3.4")])

        dbip_file(configured.geoip_dir, "2026-09")
        assert runtime.geo_updater is not None
        runtime.geo_updater.refresh_from_disk()  # what the hourly check or `reload` does
        runtime.processor.process_batch(
            [make_event(packet_type=PacketType.TCP_SYN, destination_ip="81.2.3.4", seconds=1)]
        )
        events = client.get("/api/events").json()["items"]
        assert [(e["country"], e["country_name"]) for e in events] == [("PT", "Portugal"), (None, None)]
        body = client.get("/api/stats/countries").json()
        assert (body["source"], body["database_month"], body["simulated"]) == ("dbip", "2026-09", False)
        assert body["attribution"] == "IP Geolocation by DB-IP" and body["attribution_url"] == "https://db-ip.com"


def test_a_newer_file_replaces_the_one_in_use(
    real_geo: tuple[Settings, HoundRuntime], make_event: EventFactory
) -> None:
    configured, runtime = real_geo
    assert runtime.geo_updater is not None
    dbip_file(configured.geoip_dir, "2026-08", {**NETWORKS, "81.0.0.0/8": country("ES")})
    runtime.geo_updater.refresh_from_disk()
    old = runtime.geo.locator
    dbip_file(configured.geoip_dir, "2026-09")
    runtime.geo_updater.refresh_from_disk()
    [stored] = runtime.processor.process_batch([make_event(packet_type=PacketType.TCP_SYN, destination_ip="81.2.3.4")])
    assert stored.country == "PT" and runtime.geo_description() == "DB-IP Lite 2026-09"
    assert old._reader.closed  # type: ignore[attr-defined]  # the replaced database was released


def test_reload_picks_up_a_downloaded_file(real_geo: tuple[Settings, HoundRuntime]) -> None:
    configured, runtime = real_geo
    assert runtime.reload_detection_config().geolocation == "none (countries unknown)"
    dbip_file(configured.geoip_dir, "2026-09")
    assert runtime.reload_detection_config().geolocation == "DB-IP Lite 2026-09"


def test_no_updater_in_demo_or_with_illustrative_data(settings: Settings) -> None:
    assert HoundRuntime(settings.model_copy(update={"geo_mode": "auto"}), RunMode.DEMO).geo_updater is None
    assert HoundRuntime(settings).geo_updater is None  # the fixture uses geo_mode=simulated


# ------------------------------------------------------------------------------ CLI & doctor
@pytest.fixture
def geo_cli(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> Settings:
    configured = settings.model_copy(update={"geo_mode": "auto"})
    monkeypatch.setattr(cli, "load_settings", lambda **_: configured)
    monkeypatch.setattr(cli, "configure_logging", lambda *a, **k: None)
    return configured


def test_cli_geo_update_and_status(
    geo_cli: Settings, monkeypatch: pytest.MonkeyPatch, published: dict[str, bytes], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["geo", "status"]) == 1
    assert "python run.py geo update" in capsys.readouterr().out
    server = FakeServer(published)
    real = geoip.download_dbip
    monkeypatch.setattr(geoip, "download_dbip", lambda d, today: real(d, today, urlopen=server))
    assert cli.main(["geo", "update"]) == 0
    out = capsys.readouterr().out
    assert "DB-IP Lite 2026-" in out and "python run.py reload" in out and "CC BY 4.0" in out
    assert cli.main(["geo", "status"]) == 0
    assert "Automatic monthly update: off" in capsys.readouterr().out  # the fixture turns it off


def test_cli_geo_update_failure(
    geo_cli: Settings, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def blocked(directory: Path, today: date) -> Any:
        raise GeoIpError("Download of https://download.db-ip.com/... failed: Tunnel connection failed: 403")

    monkeypatch.setattr(geoip, "download_dbip", blocked)
    assert cli.main(["geo", "update"]) == 2
    assert "Update failed" in capsys.readouterr().err


def test_doctor_geolocation(settings: Settings) -> None:
    simulated = doctor.check_geolocation(settings)
    assert simulated.status is Status.WARN and "not real" in simulated.detail
    auto = settings.model_copy(update={"geo_mode": "auto"})
    assert doctor.check_geolocation(auto).status is Status.WARN  # none, and auto-download off (fixture)
    assert doctor.check_geolocation(auto.model_copy(update={"geoip_auto_update": True})).status is Status.INFO
    assert not auto.geoip_dir.exists()  # doctor stays read-only
    dbip_file(auto.geoip_dir, "2026-09")
    current = doctor.check_geolocation(auto, today=TODAY)
    assert (current.status, current.detail) == (Status.OK, "DB-IP Lite 2026-09 (8.8.8.8 -> US)")
    stale = doctor.check_geolocation(auto, today=date(2026, 12, 15))
    assert stale.status is Status.WARN and "out of date" in stale.detail


def test_copying_env_example_gives_real_countries() -> None:
    """Regression guard: `.env.example` used to set HOUND_GEO_MODE=simulated, so a `.env`
    copied from it kept showing invented countries in live use."""
    from app.core.config import PROJECT_ROOT

    copied = Settings(_env_file=PROJECT_ROOT / ".env.example")  # type: ignore[call-arg]
    assert copied.geo_mode == "auto" and copied.geoip_auto_update is True
