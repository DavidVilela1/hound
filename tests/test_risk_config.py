"""Risk settings file (``config/risk.toml``): parsing, validation, precedence, wiring."""

from __future__ import annotations

import logging
import re
from datetime import timedelta
from pathlib import Path

import pytest
import uvicorn

from app import cli
from app.core.config import PROJECT_ROOT, Settings
from app.models.processed import Enrichment
from app.models.risk import RiskLevel
from app.risk.config import RiskConfig, RiskConfigError, RiskWeights, explicit_environment, load_risk_file
from app.risk.engine import RiskEngine
from app.services import doctor
from app.services.doctor import Status
from app.services.runtime import HoundRuntime
from tests.conftest import EventFactory

SHIPPED = PROJECT_ROOT / "config" / "risk.toml"
RISK_ENV_FIELDS = {name for name in Settings.model_fields if name.startswith("risk_") or name == "trusted_dns_servers"}
RISK_ENV_FIELDS.discard("risk_config_path")


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "risk.toml"
    path.write_text(text, encoding="utf-8")
    return path


def with_file(settings: Settings, path: Path, **overrides: object) -> Settings:
    # model_validate (not model_copy) so explicitly passed values land in model_fields_set,
    # exactly like values from the environment or .env do.
    data = settings.model_dump(exclude_unset=True) | {"risk_config_path": path} | overrides
    return Settings.model_validate(data | {"_env_file": None})


# ------------------------------------------------------------------------------ the shipped file
def test_shipped_file_changes_nothing() -> None:
    assert load_risk_file(SHIPPED) == {}


def test_shipped_file_documents_the_real_defaults(tmp_path: Path) -> None:
    """Uncommenting every value must reproduce the built-in defaults exactly (no doc drift)."""
    text = re.sub(r"^# (\w+ = .*)$", r"\1", SHIPPED.read_text(encoding="utf-8"), flags=re.MULTILINE)
    values = load_risk_file(write(tmp_path, text))
    weights = values.pop("weights")
    assert len(weights) == len(RiskWeights.__dataclass_fields__)  # every weight is documented
    config = RiskConfig(weights=RiskWeights(**weights), **values)
    assert config == RiskConfig()
    documented = set(values) | {"weights"}
    assert documented == set(RiskConfig.__dataclass_fields__)  # every tunable is documented


# ------------------------------------------------------------------------------ parsing
def test_values_are_mapped_and_normalised(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        """
[levels]
suspicious = 30
[behaviour]
window_seconds = 120
port_scan = 25
[domains]
risky_tlds = [".XYZ", " top "]
unusual_query_types = ["txt"]
[ports]
suspicious = [22, 445]
[dns]
trusted_servers = [" 192.168.1.1 "]
[weights]
high_entropy_domain = 0
""",
    )
    values = load_risk_file(path)
    assert values == {
        "suspicious_threshold": 30,
        "window": timedelta(seconds=120),
        "port_scan_threshold": 25,
        "risky_tlds": frozenset({"xyz", "top"}),
        "unusual_query_types": frozenset({"TXT"}),
        "suspicious_ports": frozenset({22, 445}),
        "trusted_dns_servers": frozenset({"192.168.1.1"}),
        "weights": {"high_entropy_domain": 0},
    }


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[levels]\nsuspicous = 30\n", "levels.suspicous: unknown setting (check the spelling)"),
        ("[level]\nsuspicious = 30\n", "level: unknown setting"),
        ("[weights]\nport_scan = 150\n", "weights.port_scan"),
        ("[ports]\ncommon = [0]\n", "ports must be between 1 and 65535"),
        ("[dns]\ntrusted_servers = ['router']\n", "dns.trusted_servers"),
        ("[behaviour]\nwindow_seconds = 'a minute'\n", "behaviour.window_seconds"),
        ("[levels\nsuspicious = 30\n", "not valid TOML"),
    ],
)
def test_invalid_files_are_refused_with_the_reason(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(RiskConfigError) as info:
        load_risk_file(write(tmp_path, text))
    assert message in str(info.value)
    assert str(tmp_path) in str(info.value)


def test_missing_file_means_defaults(tmp_path: Path) -> None:
    assert load_risk_file(tmp_path / "absent.toml") == {}


# ------------------------------------------------------------------------------ precedence
def test_file_overrides_defaults_and_explicit_settings_override_the_file(settings: Settings, tmp_path: Path) -> None:
    path = write(tmp_path, "[behaviour]\nport_scan = 25\nhost_sweep = 30\n[weights]\nport_scan = 55\n")
    from_file = RiskConfig.from_settings(with_file(settings, path))
    assert (from_file.port_scan_threshold, from_file.host_sweep_threshold, from_file.weights.port_scan) == (25, 30, 55)
    assert from_file.nxdomain_threshold == RiskConfig().nxdomain_threshold  # untouched values keep defaults

    explicit = RiskConfig.from_settings(with_file(settings, path, risk_port_scan_threshold=40))
    assert explicit.port_scan_threshold == 40  # explicitly set setting wins
    assert explicit.host_sweep_threshold == 30  # the rest of the file still applies


def test_copying_env_example_does_not_override_the_file() -> None:
    copied = Settings(_env_file=PROJECT_ROOT / ".env.example")  # type: ignore[call-arg]
    assert explicit_environment(copied) == {}
    assert not (copied.model_fields_set & RISK_ENV_FIELDS)


def test_inconsistent_levels_across_sources_are_refused(settings: Settings, tmp_path: Path) -> None:
    path = write(tmp_path, "[levels]\nsuspicious = 80\n")  # above the default dangerous threshold (70)
    with pytest.raises(RiskConfigError, match="suspicious < dangerous"):
        RiskConfig.from_settings(with_file(settings, path))


# ------------------------------------------------------------------------------ effect and wiring
def test_zero_weight_switches_a_signal_off(make_event: EventFactory) -> None:
    enrichment = Enrichment(
        country=None, domain="c2.bad.example", domain_source=None, blocklist_match="bad.example",
        destination_is_public=False,
    )  # fmt: skip
    event = make_event(domain="c2.bad.example")
    assert RiskEngine().assess(event, enrichment).level is RiskLevel.DANGEROUS
    muted = RiskEngine(RiskConfig(weights=RiskWeights(blocklisted_domain=0))).assess(event, enrichment)
    assert muted.level is RiskLevel.SAFE and muted.score == 0


def test_runtime_uses_the_file(settings: Settings, tmp_path: Path) -> None:
    path = write(tmp_path, "[levels]\nsuspicious = 35\ndangerous = 80\n")
    runtime = HoundRuntime(with_file(settings, path))
    assert (runtime.risk_engine.config.suspicious_threshold, runtime.risk_engine.config.dangerous_threshold) == (35, 80)


def test_server_refuses_to_start_with_an_invalid_file(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    bad = with_file(settings, write(tmp_path, "[weights]\nblocklisted = 70\n"))
    monkeypatch.setattr(cli, "load_settings", lambda **_: bad)
    monkeypatch.setattr(cli, "configure_logging", lambda *a, **k: None)

    def server_must_not_start(*args: object, **kwargs: object) -> None:
        raise AssertionError("the web server was started despite an invalid risk file")

    monkeypatch.setattr(uvicorn, "run", server_must_not_start)  # fail fast instead of serving forever
    with caplog.at_level(logging.ERROR):
        assert cli.main(["--no-dashboard"]) == 2  # before any server starts
    assert "Cannot start" in caplog.text and "weights.blocklisted: unknown setting" in caplog.text


def test_doctor_reports_the_risk_file(settings: Settings, tmp_path: Path) -> None:
    assert doctor.check_risk_settings(settings).detail == "built-in defaults"
    tuned = with_file(settings, write(tmp_path, "[weights]\nport_scan = 30\nhost_sweep = 30\n"))
    check = doctor.check_risk_settings(tuned)
    assert check.status is Status.OK and "2 value(s) changed" in check.detail
    overridden = doctor.check_risk_settings(with_file(settings, tmp_path / "risk.toml", risk_window_seconds=90))
    assert overridden.status is Status.INFO and "risk_window_seconds" not in overridden.detail
    assert "window" in overridden.detail
    broken = doctor.check_risk_settings(with_file(settings, write(tmp_path, "[levels]\nsuspicious = 0\n")))
    assert broken.status is Status.FAIL and "levels.suspicious" in broken.detail and broken.fix
