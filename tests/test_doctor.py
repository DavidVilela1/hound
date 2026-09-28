"""``hound doctor``: every check's outcomes, the read-only guarantee, and the CLI command."""

from __future__ import annotations

import hashlib
import os
import socket
import sqlite3
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import SecretStr
from sqlalchemy.engine import URL

from app import cli
from app.core.config import Settings
from app.database.engine import Database
from app.ingestion.capture import InterfaceInfo
from app.services import doctor
from app.services.doctor import Check, Status
from tests.test_daemon import LiveServer, free_port, start_server

POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")


@pytest.fixture
def running_hound(settings: Settings) -> Iterator[LiveServer]:
    server = start_server(settings, free_port())
    yield server
    server.stop()


def with_db(settings: Settings, path: Path) -> Settings:
    url = URL.create("sqlite", database=path.as_posix()).render_as_string()  # percent-encoded path
    return settings.model_copy(update={"database_url": url})


def snapshot(folder: Path) -> dict[str, str]:
    return {
        str(p.relative_to(folder)): hashlib.sha256(p.read_bytes()).hexdigest() for p in folder.rglob("*") if p.is_file()
    }


# ------------------------------------------------------------------------------ python & packages
def test_python_version() -> None:
    assert doctor.check_python((3, 13, 7)).status is Status.OK
    old = doctor.check_python((3, 10, 12))
    assert old.status is Status.FAIL and "3.10.12" in old.detail and old.fix
    assert doctor.check_python().status is Status.OK  # the interpreter running the suite


def write_requirements(tmp_path: Path, lock_versions: dict[str, str]) -> tuple[Path, Path]:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("# comment\nfastapi>=0.115,<1\n\nSQLAlchemy>=2.0  # inline\n", encoding="utf-8")
    lock = tmp_path / "requirements.lock"
    lines = ["# generated"]
    for name, version in lock_versions.items():
        lines += [f"{name}=={version} \\", "    --hash=sha256:00"]
    lock.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return requirements, lock


def test_dependencies_match_differ_or_missing(tmp_path: Path) -> None:
    requirements, lock = write_requirements(tmp_path, {"fastapi": "1.0", "sqlalchemy": "2.1"})
    installed = {"fastapi": "1.0", "SQLAlchemy": "2.1"}
    ok = doctor.check_dependencies(requirements, lock, installed.get)
    assert ok.status is Status.OK and "all 2" in ok.detail

    installed["SQLAlchemy"] = "2.0.9"
    differ = doctor.check_dependencies(requirements, lock, installed.get)
    assert differ.status is Status.WARN and "SQLAlchemy 2.0.9 (lock: 2.1)" in differ.detail
    assert "requirements.lock" in (differ.fix or "")

    del installed["fastapi"]
    missing = doctor.check_dependencies(requirements, lock, installed.get)
    assert missing.status is Status.FAIL and "fastapi" in missing.detail and "venv" in (missing.fix or "")


def test_dependencies_skipped_outside_a_source_checkout(tmp_path: Path) -> None:
    check = doctor.check_dependencies(tmp_path / "requirements.txt", tmp_path / "requirements.lock")
    assert check.status is Status.INFO


def test_dependencies_against_the_real_repository() -> None:
    check = doctor.check_dependencies()  # this environment may or may not be installed from the lock
    assert check.status in (Status.OK, Status.WARN)


# ------------------------------------------------------------------------------ capture prerequisites
@pytest.mark.parametrize(
    ("flags", "status", "text"),
    [
        ((True, True), Status.OK, "Npcap found"),
        ((True, False), Status.WARN, "WinPcap"),
        ((False, False), Status.WARN, "Npcap not found"),
    ],
)
def test_capture_driver_on_windows(flags: tuple[bool, bool], status: Status, text: str) -> None:
    check = doctor.check_capture_library("win32", pcap_flags=lambda: flags, find_library=lambda _: None)
    assert check.status is status and text in check.detail
    if status is not Status.OK:
        assert "npcap.com" in (check.fix or "")


def test_capture_driver_on_linux_and_macos() -> None:
    found = doctor.check_capture_library("linux", find_library=lambda _: "libpcap.so.0.8")
    assert found.status is Status.OK and "libpcap.so.0.8" in found.detail
    missing = doctor.check_capture_library("linux", find_library=lambda _: None)
    assert missing.status is Status.WARN and "default filter only" in missing.detail and "apt" in (missing.fix or "")
    mac = doctor.check_capture_library("darwin", find_library=lambda _: None)
    assert mac.status is Status.WARN and "macOS" in mac.detail


def test_capture_driver_real_scapy_detection() -> None:
    assert doctor.check_capture_library().status in (Status.OK, Status.WARN)


def test_privileges_wording() -> None:
    assert "Run as administrator" in doctor.check_privileges(False, "win32").detail
    assert "sudo" in doctor.check_privileges(False, "linux").detail
    elevated = doctor.check_privileges(True, "win32")
    assert "Administrator" in elevated.detail and "normal user" in elevated.detail
    assert all(doctor.check_privileges(p, "linux").status is Status.INFO for p in (True, False))


WIFI = InterfaceInfo("Wi-Fi", "Intel(R) Wi-Fi 6 AX201", "192.168.1.20", "aa:bb:cc:dd:ee:ff", r"\Device\NPF_{1234}")
LO = InterfaceInfo("lo", "", "127.0.0.1", None)


@pytest.mark.parametrize("requested", ["Wi-Fi", "Intel(R) Wi-Fi 6 AX201", r"\Device\NPF_{1234}"])
def test_interface_found_by_name_description_or_npf_name(requested: str) -> None:
    check = doctor.check_interface(requested, [LO, WIFI], "Wi-Fi")
    assert check.status is Status.OK and "Wi-Fi" in check.detail and "192.168.1.20" in check.detail


def test_interface_not_found_lists_the_choices() -> None:
    check = doctor.check_interface("WiFi", [LO, WIFI], "Wi-Fi")
    assert check.status is Status.FAIL and "lo, Wi-Fi" in check.detail and "interfaces" in (check.fix or "")


def test_interface_summary_without_request() -> None:
    assert doctor.check_interface(None, [LO, WIFI], "Wi-Fi").status is Status.INFO
    assert doctor.check_interface(None, [], None).status is Status.WARN


# ------------------------------------------------------------------------------ server prerequisites
def test_bind_address(settings: Settings) -> None:
    assert doctor.check_bind_address(settings).status is Status.OK
    exposed = doctor.check_bind_address(settings.model_copy(update={"host": "0.0.0.0"}))
    assert exposed.status is Status.WARN and "127.0.0.1" in (exposed.fix or "")


def test_port_free(settings: Settings) -> None:
    check = doctor.check_port(settings.model_copy(update={"port": free_port()}), probe=lambda _: None)
    assert check.status is Status.OK and "free" in check.detail


def test_port_taken_by_another_program(settings: Settings) -> None:
    with socket.socket() as blocker:
        blocker.bind(("127.0.0.1", 0))
        blocker.listen()
        port = blocker.getsockname()[1]
        check = doctor.check_port(settings.model_copy(update={"port": port}))  # real probe: not Hound
    assert check.status is Status.FAIL and "another program" in check.detail and "--port" in (check.fix or "")


def test_port_taken_by_a_running_hound(settings: Settings, running_hound: LiveServer) -> None:
    check = doctor.check_port(settings.model_copy(update={"port": running_hound.port}))  # real /health probe
    assert check.status is Status.OK and "is running" in check.detail


def test_storage_location_flags_cloud_sync(settings: Settings, tmp_path: Path) -> None:
    assert doctor.check_storage_location(settings).status is Status.OK
    synced = with_db(settings, tmp_path / "OneDrive" / "Hound" / "data" / "hound.db")
    check = doctor.check_storage_location(synced)
    assert check.status is Status.WARN and "OneDrive" in check.detail and "HOUND_DATABASE_URL" in (check.fix or "")


# ------------------------------------------------------------------------------ database
def test_database_not_created_yet(settings: Settings, tmp_path: Path) -> None:
    check = doctor.check_database(with_db(settings, tmp_path / "new" / "hound.db"))
    assert check.status is Status.OK and "will be created" in check.detail
    assert not (tmp_path / "new").exists()


def test_database_current_and_read_only(settings: Settings, tmp_path: Path) -> None:
    db_path = tmp_path / "db" / "hound.db"
    configured = with_db(settings, db_path)
    database = Database(configured.resolved_database_url)
    database.initialize()
    database.dispose()
    before = snapshot(db_path.parent)
    check = doctor.check_database(configured)
    assert check.status is Status.OK and "current" in check.detail
    assert snapshot(db_path.parent) == before  # no -wal/-shm created, bytes unchanged


def test_database_in_use_by_a_running_server(settings: Settings, tmp_path: Path) -> None:
    db_path = tmp_path / "hound.db"
    configured = with_db(settings, db_path)
    database = Database(configured.resolved_database_url)
    database.initialize()
    writer = sqlite3.connect(db_path)  # keeps the WAL open, like a running server
    try:
        writer.execute("CREATE TABLE doctor_probe (x INTEGER)")  # any committed write fills the WAL
        writer.commit()
        assert Path(f"{db_path}-wal").exists()
        assert doctor.check_database(configured).status is Status.OK
    finally:
        writer.close()
        database.dispose()


def make_sqlite(path: Path, statements: list[str]) -> None:
    connection = sqlite3.connect(path)
    for statement in statements:
        connection.execute(statement)
    connection.commit()
    connection.close()


def test_database_newer_than_this_code(settings: Settings, tmp_path: Path) -> None:
    make_sqlite(tmp_path / "hound.db", ["CREATE TABLE events (id INTEGER)", "PRAGMA user_version = 99"])
    check = doctor.check_database(with_db(settings, tmp_path / "hound.db"))
    assert check.status is Status.FAIL and "v99" in check.detail and "newer" in check.detail


def test_database_legacy_matching_and_foreign(settings: Settings, tmp_path: Path) -> None:
    from app.database.migrations import BASELINE_V1_DDL

    legacy = tmp_path / "legacy.db"
    make_sqlite(legacy, list(BASELINE_V1_DDL))  # an earlier build: baseline tables, user_version 0
    adopted = doctor.check_database(with_db(settings, legacy))
    assert adopted.status is Status.INFO and "adopted as v1" in adopted.detail

    make_sqlite(tmp_path / "foreign.db", ["CREATE TABLE recipes (name TEXT)"])
    foreign = doctor.check_database(with_db(settings, tmp_path / "foreign.db"))
    assert foreign.status is Status.FAIL and "not a Hound database" in foreign.detail


def test_database_file_that_is_not_sqlite(settings: Settings, tmp_path: Path) -> None:
    (tmp_path / "hound.db").write_bytes(b"not a database " * 100)
    check = doctor.check_database(with_db(settings, tmp_path / "hound.db"))
    assert check.status is Status.FAIL and "cannot be read" in check.detail


def test_database_not_writable(settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    make_sqlite(tmp_path / "hound.db", ["PRAGMA user_version = 1"])
    monkeypatch.setattr(doctor, "_writable", lambda path: False)  # root ignores file modes, so simulate
    check = doctor.check_database(with_db(settings, tmp_path / "hound.db"))
    assert check.status is Status.FAIL and "not writable" in check.detail


def test_database_path_with_spaces_and_special_characters(settings: Settings, tmp_path: Path) -> None:
    folder = tmp_path / "Ambiente de Trabalho #1 %20"
    folder.mkdir()
    database = Database(with_db(settings, folder / "hound.db").resolved_database_url)
    database.initialize()
    database.dispose()
    assert (folder / "hound.db").is_file()  # created exactly here, not in a "decoded" sibling folder
    assert [p.name for p in tmp_path.iterdir() if p.is_dir()] == [folder.name]  # no stray sibling
    assert doctor.check_database(with_db(settings, folder / "hound.db")).status is Status.OK


# ------------------------------------------------------------------------------ ingest token
def test_token_from_environment(settings: Settings) -> None:
    good = settings.model_copy(update={"ingest_token": SecretStr("x" * 32)})
    assert doctor.check_ingest_token(good).status is Status.OK
    short = settings.model_copy(update={"ingest_token": SecretStr("short")})
    assert doctor.check_ingest_token(short).status is Status.FAIL


def test_token_file_states(settings: Settings) -> None:
    path = settings.resolve_path(settings.ingest_token_path)
    assert doctor.check_ingest_token(settings).status is Status.INFO  # not created yet
    path.write_text("short", encoding="utf-8")
    assert doctor.check_ingest_token(settings).status is Status.WARN
    path.write_text("y" * 40, encoding="utf-8")
    if sys.platform != "win32":
        os.chmod(path, 0o600)
    assert doctor.check_ingest_token(settings).status is Status.OK


def test_token_file_unreadable_by_this_user(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    path = settings.resolve_path(settings.ingest_token_path)
    path.write_text("w" * 40, encoding="utf-8")

    def denied(self: Path, *args: object, **kwargs: object) -> str:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "read_text", denied)  # root can read anything, so simulate
    check = doctor.check_ingest_token(settings)
    assert check.status is Status.WARN and "not readable" in check.detail and "HOUND_INGEST_TOKEN" in (check.fix or "")


@POSIX_ONLY
def test_token_file_readable_by_others(settings: Settings) -> None:
    path = settings.resolve_path(settings.ingest_token_path)
    path.write_text("z" * 40, encoding="utf-8")
    os.chmod(path, 0o644)
    check = doctor.check_ingest_token(settings)
    assert check.status is Status.WARN and "chmod 600" in (check.fix or "")


# ------------------------------------------------------------------------------ whole run & CLI
def test_run_checks_is_read_only(settings: Settings, tmp_path: Path) -> None:
    before = snapshot(tmp_path)
    checks = doctor.run_checks(settings.model_copy(update={"port": free_port()}))
    assert [c.name for c in checks][:3] == ["Python", "Packages", "Capture driver"]
    assert len(checks) == 10
    assert snapshot(tmp_path) == before  # no database, token or directory created
    assert not (tmp_path / "hound-test.db").exists()


def test_render_and_exit_code() -> None:
    checks = [
        Check("Python", Status.OK, "3.13.7"),
        Check("Interface", Status.FAIL, "'WiFi' not found", "Use a listed name."),
        Check("Packages", Status.WARN, "differs", "pip install -r requirements.lock"),
        Check("Privileges", Status.INFO, "not root", "never shown for INFO"),
    ]
    text = doctor.render(checks)
    assert "[ OK ] Python" in text and "[FAIL] Interface" in text
    assert "-> Use a listed name." in text and "-> pip install" in text
    assert "never shown" not in text
    assert text.endswith("1 problem(s), 1 warning(s).")
    assert doctor.exit_code(checks) == 1
    assert doctor.exit_code(checks[2:]) == 0


def test_cli_doctor_command(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "load_settings", lambda **_: settings.model_copy(update={"port": free_port()}))
    assert cli.main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "environment check" in out and "[ OK ] Python" in out

    assert cli.main(["doctor", "--interface", "no-such-interface-xyz"]) == 1
    assert "[FAIL] Interface" in capsys.readouterr().out
