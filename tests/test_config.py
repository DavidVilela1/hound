"""Configuration parsing and validation."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy.engine import URL, make_url

from app.core import config as config_module
from app.core.config import DEFAULT_BPF_FILTER, PROJECT_ROOT, Settings, load_settings, split_csv


def make(**kwargs: object) -> Settings:
    return Settings(_env_file=None, **kwargs)  # type: ignore[arg-type]


def test_defaults_are_local_only() -> None:
    s = make()
    assert s.host == "127.0.0.1"
    assert s.port == 8000
    assert s.is_loopback_bind
    assert s.bpf_filter == DEFAULT_BPF_FILTER
    assert s.api_base_url == "http://127.0.0.1:8000"
    assert s.ws_events_url == "ws://127.0.0.1:8000/ws/events"


def test_env_variables_use_hound_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOUND_PORT", "9123")
    monkeypatch.setenv("HOUND_LOG_LEVEL", "debug")
    monkeypatch.setenv("HOUND_NETWORK_INTERFACE", "eth1")
    monkeypatch.setenv("HOST", "0.0.0.0")  # unprefixed variables must be ignored
    s = make()
    assert s.port == 9123
    assert s.log_level == "DEBUG"
    assert s.network_interface == "eth1"
    assert s.host == "127.0.0.1"


def test_cli_overrides_take_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOUND_PORT", "9123")
    s = load_settings(port=9999, host=None)
    assert s.port == 9999


@pytest.mark.parametrize(
    "field,value",
    [
        ("port", 0),
        ("port", 70000),
        ("log_level", "LOUD"),
        ("host", "not a host"),
        ("api_url", "file:///etc/passwd"),
        ("risk_suspicious_ports", "22,abc"),
        ("trusted_dns_servers", "1.1.1.1,nope"),
        ("network_interface", "eth0\nrm -rf"),
    ],
)
def test_invalid_values_rejected(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        make(**{field: value})


def test_threshold_order_enforced() -> None:
    with pytest.raises(ValidationError):
        make(risk_suspicious_threshold=80, risk_dangerous_threshold=70)


def test_relative_paths_resolve_against_project_root(tmp_path: Path) -> None:
    s = make(database_url="sqlite:///data/x.db")
    assert make_url(s.resolved_database_url).database == (PROJECT_ROOT / "data" / "x.db").resolve().as_posix()
    assert s.resolve_path(Path("config/blocklist.txt")) == (PROJECT_ROOT / "config" / "blocklist.txt").resolve()
    absolute = tmp_path / "a.db"
    assert make_url(make(database_url=f"sqlite:///{absolute}").resolved_database_url).database == absolute.as_posix()
    assert make(database_url="sqlite:///:memory:").resolved_database_url == "sqlite:///:memory:"


# Folder names that broke the URL before it was rendered by SQLAlchemy ("%20" was decoded,
# "?" cut the path). The last two are invalid on Windows, so they run on POSIX only.
AWKWARD_FOLDERS = ["Ambiente de Trabalho #1 %20", "Área de Trabalho", "100%", "a@b;c+d"]
if sys.platform != "win32":
    AWKWARD_FOLDERS += ["what?", "tab\tname"]


@pytest.mark.parametrize("folder", AWKWARD_FOLDERS)
def test_project_folder_with_awkward_name_keeps_the_database_inside_it(
    tmp_path: Path, folder: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The real-world case: the project itself lives in such a folder and the default,
    # relative database URL is anchored there.
    root = tmp_path / folder
    monkeypatch.setattr(config_module, "PROJECT_ROOT", root)
    parsed = make_url(make(database_url="sqlite:///data/hound.db?timeout=10").resolved_database_url)
    assert parsed.database == (root / "data" / "hound.db").resolve().as_posix()
    assert dict(parsed.query) == {"timeout": "10"}  # query options survive


@pytest.mark.parametrize("folder", AWKWARD_FOLDERS)
def test_encoded_absolute_database_url_round_trips(tmp_path: Path, folder: str) -> None:
    target = (tmp_path / folder / "hound.db").as_posix()
    given = URL.create("sqlite", database=target).render_as_string()  # how such a path must be written
    assert make_url(make(database_url=given).resolved_database_url).database == target


def test_derived_collections() -> None:
    s = make(risk_suspicious_ports="23, 445", risk_risky_tlds=".ZIP,top", trusted_dns_servers="192.168.1.1")
    assert s.suspicious_ports == frozenset({23, 445})
    assert s.risky_tlds == frozenset({"zip", "top"})
    assert s.trusted_dns_server_set == frozenset({"192.168.1.1"})
    assert split_csv(" a, ,b ") == ("a", "b")


def test_wildcard_bind_uses_loopback_for_clients() -> None:
    s = make(host="0.0.0.0", port=8080)
    assert not s.is_loopback_bind
    assert s.api_base_url == "http://127.0.0.1:8080"
    assert "0.0.0.0" not in s.allowed_host_list


def test_blank_optional_values_are_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOUND_INGEST_TOKEN", "")
    monkeypatch.setenv("HOUND_DEMO_SEED", " ")
    monkeypatch.setenv("HOUND_NETWORK_INTERFACE", "")
    s = make()
    assert s.ingest_token is None and s.demo_seed is None and s.network_interface is None


def test_env_example_is_valid() -> None:
    s = Settings(_env_file=PROJECT_ROOT / ".env.example")  # type: ignore[call-arg]
    assert s.host == "127.0.0.1" and s.bpf_filter == DEFAULT_BPF_FILTER
