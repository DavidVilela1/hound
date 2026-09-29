"""Risk-engine configuration: weights and thresholds in one documented place.

Sources, lowest to highest precedence (ADR-022):

1. the defaults below;
2. an optional TOML file (``config/risk.toml``, ``HOUND_RISK_CONFIG_PATH``) — strictly
   validated: unknown sections or keys are errors, so a typo cannot silently do nothing;
3. ``HOUND_RISK_*`` / ``HOUND_TRUSTED_DNS_SERVERS`` settings that were set explicitly
   (environment, ``.env`` or CLI).
"""

from __future__ import annotations

import ipaddress
import logging
import tomllib
from dataclasses import dataclass, field, replace
from datetime import timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.core.config import Settings
from app.models.risk import RiskLevel

logger = logging.getLogger(__name__)


class RiskConfigError(ValueError):
    """The risk settings file (or its combination with the environment) is invalid."""


@dataclass(frozen=True, slots=True)
class RiskWeights:
    """Points each signal adds to an event's score (the total is capped at 100)."""

    blocklisted_domain: int = 70
    port_scan: int = 40
    host_sweep: int = 40
    nxdomain_burst: int = 25
    suspicious_port: int = 25
    repeated_attempts: int = 20
    high_entropy_domain: int = 20
    untrusted_resolver: int = 15
    long_domain: int = 10
    risky_tld: int = 10
    unusual_query_type: int = 10
    uncommon_port: int = 5
    direct_ip_connection: int = 5


@dataclass(frozen=True, slots=True)
class RiskConfig:
    """Thresholds used by the signals and the score → level mapping."""

    suspicious_threshold: int = 25
    dangerous_threshold: int = 70
    window: timedelta = timedelta(seconds=60)
    repeated_attempts_threshold: int = 15
    port_scan_threshold: int = 15
    host_sweep_threshold: int = 20
    nxdomain_threshold: int = 10
    suspicious_ports: frozenset[int] = frozenset({23, 135, 139, 445, 1433, 3389, 4444, 5900, 6667})
    common_ports: frozenset[int] = frozenset({53, 80, 123, 443, 853, 993, 995, 465, 587, 5222, 5223, 8080, 8443})
    risky_tlds: frozenset[str] = frozenset(
        {"zip", "mov", "xyz", "top", "tk", "gq", "ml", "cf", "click", "country", "work"}
    )
    trusted_dns_servers: frozenset[str] = frozenset()
    entropy_threshold: float = 3.5
    entropy_min_label_length: int = 12
    long_domain_length: int = 75
    max_labels: int = 6
    unusual_query_types: frozenset[str] = frozenset({"TXT", "NULL", "ANY"})
    weights: RiskWeights = field(default_factory=RiskWeights)

    def __post_init__(self) -> None:
        if not 0 < self.suspicious_threshold < self.dangerous_threshold <= 100:
            raise ValueError("thresholds must satisfy 0 < suspicious < dangerous <= 100")

    def level_for(self, score: int) -> RiskLevel:
        if score >= self.dangerous_threshold:
            return RiskLevel.DANGEROUS
        if score >= self.suspicious_threshold:
            return RiskLevel.SUSPICIOUS
        return RiskLevel.SAFE

    @classmethod
    def from_settings(cls, settings: Settings) -> RiskConfig:
        """Defaults, then the risk file, then explicitly set environment settings."""
        path = settings.resolve_path(settings.risk_config_path)
        values = load_risk_file(path)
        overridden = explicit_environment(settings)
        if overridden and values:
            clash = sorted(set(values) & set(overridden))
            if clash:
                logger.info("Environment settings override the risk file", extra={"path": str(path), "fields": clash})
        values.update(overridden)
        weights = values.pop("weights", {})
        try:
            config = cls(weights=replace(RiskWeights(), **weights), **values)
        except (TypeError, ValueError) as exc:
            raise RiskConfigError(f"Invalid risk settings ({path}): {exc}") from exc
        return config


# ---------------------------------------------------------------------------- the TOML file


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _Levels(_Section):
    suspicious: int | None = Field(default=None, ge=1, le=100)
    dangerous: int | None = Field(default=None, ge=1, le=100)


class _Behaviour(_Section):
    window_seconds: int | None = Field(default=None, ge=5, le=3_600)
    repeated_attempts: int | None = Field(default=None, ge=2, le=10_000)
    port_scan: int | None = Field(default=None, ge=2, le=10_000)
    host_sweep: int | None = Field(default=None, ge=2, le=10_000)
    nxdomain_burst: int | None = Field(default=None, ge=2, le=10_000)


class _Domains(_Section):
    entropy_threshold: float | None = Field(default=None, gt=0, le=8)
    entropy_min_label_length: int | None = Field(default=None, ge=4, le=63)
    long_domain_length: int | None = Field(default=None, ge=20, le=253)
    max_labels: int | None = Field(default=None, ge=2, le=127)
    risky_tlds: list[str] | None = Field(default=None, max_length=1_000)
    unusual_query_types: list[str] | None = Field(default=None, max_length=100)

    @field_validator("risky_tlds")
    @classmethod
    def _tlds(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else [tld.strip().lower().lstrip(".") for tld in value if tld.strip()]

    @field_validator("unusual_query_types")
    @classmethod
    def _qtypes(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else [qtype.strip().upper() for qtype in value if qtype.strip()]


class _Ports(_Section):
    suspicious: list[int] | None = Field(default=None, max_length=10_000)
    common: list[int] | None = Field(default=None, max_length=10_000)

    @field_validator("suspicious", "common")
    @classmethod
    def _range(cls, value: list[int] | None) -> list[int] | None:
        if value is not None and any(not 1 <= port <= 65_535 for port in value):
            raise ValueError("ports must be between 1 and 65535")
        return value


class _Dns(_Section):
    trusted_servers: list[str] | None = Field(default=None, max_length=100)

    @field_validator("trusted_servers")
    @classmethod
    def _addresses(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else [str(ipaddress.ip_address(item.strip())) for item in value]


class _Weights(_Section):
    """Points per signal; 0 disables a signal's contribution."""

    blocklisted_domain: int | None = Field(default=None, ge=0, le=100)
    port_scan: int | None = Field(default=None, ge=0, le=100)
    host_sweep: int | None = Field(default=None, ge=0, le=100)
    nxdomain_burst: int | None = Field(default=None, ge=0, le=100)
    suspicious_port: int | None = Field(default=None, ge=0, le=100)
    repeated_attempts: int | None = Field(default=None, ge=0, le=100)
    high_entropy_domain: int | None = Field(default=None, ge=0, le=100)
    untrusted_resolver: int | None = Field(default=None, ge=0, le=100)
    long_domain: int | None = Field(default=None, ge=0, le=100)
    risky_tld: int | None = Field(default=None, ge=0, le=100)
    unusual_query_type: int | None = Field(default=None, ge=0, le=100)
    uncommon_port: int | None = Field(default=None, ge=0, le=100)
    direct_ip_connection: int | None = Field(default=None, ge=0, le=100)


class RiskFile(_Section):
    levels: _Levels = Field(default_factory=_Levels)
    behaviour: _Behaviour = Field(default_factory=_Behaviour)
    domains: _Domains = Field(default_factory=_Domains)
    ports: _Ports = Field(default_factory=_Ports)
    dns: _Dns = Field(default_factory=_Dns)
    weights: _Weights = Field(default_factory=_Weights)


def _given(section: BaseModel) -> dict[str, Any]:
    return {name: value for name, value in section.model_dump().items() if value is not None}


def load_risk_file(path: Path) -> dict[str, Any]:
    """``RiskConfig`` keyword overrides from the TOML file (``{}`` when the file is absent)."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        logger.info("No risk settings file; using defaults", extra={"path": str(path)})
        return {}
    except OSError as exc:
        raise RiskConfigError(f"Cannot read risk settings file {path}: {exc.strerror}") from exc
    try:
        parsed = RiskFile.model_validate(tomllib.loads(raw.decode("utf-8")))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise RiskConfigError(f"Risk settings file {path} is not valid TOML: {exc}") from exc
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in error['loc'])}: "
            + ("unknown setting (check the spelling)" if error["type"] == "extra_forbidden" else error["msg"])
            for error in exc.errors()
        )
        raise RiskConfigError(f"Risk settings file {path} has invalid values: {problems}") from exc

    levels, behaviour, domains = _given(parsed.levels), _given(parsed.behaviour), _given(parsed.domains)
    ports, dns, weights = _given(parsed.ports), _given(parsed.dns), _given(parsed.weights)
    given = sum(len(section) for section in (levels, behaviour, domains, ports, dns, weights))
    values: dict[str, Any] = {}
    renames = {"suspicious": "suspicious_threshold", "dangerous": "dangerous_threshold"}
    values.update({renames[key]: value for key, value in levels.items()})
    if "window_seconds" in behaviour:
        values["window"] = timedelta(seconds=behaviour.pop("window_seconds"))
    behaviour_fields = {
        "repeated_attempts": "repeated_attempts_threshold",
        "port_scan": "port_scan_threshold",
        "host_sweep": "host_sweep_threshold",
        "nxdomain_burst": "nxdomain_threshold",
    }
    values.update({behaviour_fields[key]: value for key, value in behaviour.items()})
    for key in ("risky_tlds", "unusual_query_types"):
        if key in domains:
            domains[key] = frozenset(domains[key])
    values.update(domains)
    values.update({f"{key}_ports": frozenset(value) for key, value in ports.items()})
    if "trusted_servers" in dns:
        values["trusted_dns_servers"] = frozenset(dns["trusted_servers"])
    if weights:
        values["weights"] = weights
    logger.info(
        "Risk settings file loaded",
        extra={"path": str(path), "values": given},
    )
    return values


def file_value_count(values: dict[str, Any]) -> int:
    """How many settings a :func:`load_risk_file` result changes (weights count one each)."""
    return len(values) - ("weights" in values) + len(values.get("weights", {}))


_ENVIRONMENT_FIELDS = {
    "risk_suspicious_threshold": ("suspicious_threshold", lambda s: s.risk_suspicious_threshold),
    "risk_dangerous_threshold": ("dangerous_threshold", lambda s: s.risk_dangerous_threshold),
    "risk_window_seconds": ("window", lambda s: timedelta(seconds=s.risk_window_seconds)),
    "risk_repeated_attempts_threshold": ("repeated_attempts_threshold", lambda s: s.risk_repeated_attempts_threshold),
    "risk_port_scan_threshold": ("port_scan_threshold", lambda s: s.risk_port_scan_threshold),
    "risk_host_sweep_threshold": ("host_sweep_threshold", lambda s: s.risk_host_sweep_threshold),
    "risk_nxdomain_threshold": ("nxdomain_threshold", lambda s: s.risk_nxdomain_threshold),
    "risk_suspicious_ports": ("suspicious_ports", lambda s: s.suspicious_ports),
    "risk_common_ports": ("common_ports", lambda s: s.common_ports),
    "risk_risky_tlds": ("risky_tlds", lambda s: s.risky_tlds),
    "trusted_dns_servers": ("trusted_dns_servers", lambda s: s.trusted_dns_server_set),
}


def explicit_environment(settings: Settings) -> dict[str, Any]:
    """Risk values from settings that were set explicitly (not left at their defaults)."""
    return {
        target: getter(settings)
        for name, (target, getter) in _ENVIRONMENT_FIELDS.items()
        if name in settings.model_fields_set
    }
