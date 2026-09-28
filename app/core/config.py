"""Centralised configuration.

All settings are read from environment variables prefixed with ``HOUND_`` and,
optionally, from a ``.env`` file in the project root. Command-line flags
override both (they are passed as keyword arguments to :class:`Settings`).

The ``HOUND_`` prefix is deliberate: generic names such as ``HOST`` are set by
some shells (zsh exports ``HOST`` as the machine name on several systems), and
silently binding the API to a LAN-facing hostname would violate Hound's
local-only default.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Literal
from urllib.parse import urlencode

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url

PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
"""Directory that contains ``run.py``; relative paths are resolved against it."""

DEFAULT_BPF_FILTER = "udp port 53 or tcp port 53 or (tcp[tcpflags] & tcp-syn != 0)"
LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})
VALID_LOG_LEVELS: frozenset[str] = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
HARD_MAX_PAGE_SIZE = 1000


def split_csv(value: str) -> tuple[str, ...]:
    """Split a comma-separated setting into trimmed, non-empty items."""
    return tuple(item.strip() for item in value.split(",") if item.strip())


class Settings(BaseSettings):
    """Runtime configuration for every Hound component."""

    model_config = SettingsConfigDict(
        env_prefix="HOUND_",
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Server -----------------------------------------------------------
    host: str = Field(default="127.0.0.1", description="Interface the API/dashboard binds to.")
    port: int = Field(default=8000, ge=1, le=65535)
    allowed_hosts: str = Field(
        default="127.0.0.1,localhost,::1",
        description="Comma-separated Host header allow-list (DNS-rebinding protection).",
    )
    api_url: str | None = Field(
        default=None, description="Base URL of the Hound API used by the dashboard and capture daemon."
    )
    enable_dashboard: bool = True

    # --- Storage ----------------------------------------------------------
    database_url: str = "sqlite:///data/hound.db"
    retention_max_events: int = Field(default=250_000, ge=1_000, le=50_000_000)

    # --- Capture ----------------------------------------------------------
    network_interface: str | None = None
    bpf_filter: str = Field(default=DEFAULT_BPF_FILTER, min_length=1, max_length=1024)
    ingest_token: SecretStr | None = None
    ingest_token_path: Path = Path("data/.ingest_token")

    # --- Pipeline ---------------------------------------------------------
    queue_max_size: int = Field(default=10_000, ge=100, le=1_000_000)
    batch_size: int = Field(default=200, ge=1, le=5_000)
    flush_interval_seconds: float = Field(default=0.5, gt=0, le=10)
    ws_client_queue_size: int = Field(default=500, ge=10, le=10_000)
    max_page_size: int = Field(default=500, ge=10, le=HARD_MAX_PAGE_SIZE)

    # --- Enrichment -------------------------------------------------------
    blocklist_path: Path = Path("config/blocklist.txt")
    geo_mode: Literal["simulated", "mapping_only"] = "simulated"
    geo_ranges_path: Path = Path("config/geo_ranges.csv")
    dns_cache_size: int = Field(default=10_000, ge=100, le=1_000_000)
    dns_cache_ttl_seconds: int = Field(default=3_600, ge=10, le=86_400)

    # --- Risk engine ------------------------------------------------------
    risk_suspicious_threshold: int = Field(default=25, ge=1, le=100)
    risk_dangerous_threshold: int = Field(default=70, ge=1, le=100)
    risk_window_seconds: int = Field(default=60, ge=5, le=3_600)
    risk_repeated_attempts_threshold: int = Field(default=15, ge=2, le=10_000)
    risk_port_scan_threshold: int = Field(default=15, ge=2, le=10_000)
    risk_host_sweep_threshold: int = Field(default=20, ge=2, le=10_000)
    risk_nxdomain_threshold: int = Field(default=10, ge=2, le=10_000)
    risk_suspicious_ports: str = "23,135,139,445,1433,3389,4444,5900,6667"
    risk_common_ports: str = "53,80,123,443,853,993,995,465,587,5222,5223,8080,8443"
    risk_risky_tlds: str = "zip,mov,xyz,top,tk,gq,ml,cf,click,country,work"
    trusted_dns_servers: str = Field(
        default="", description="Comma-separated resolver IPs; empty disables the untrusted-resolver signal."
    )
    device_risk_window_minutes: int = Field(default=60, ge=1, le=10_080)

    # --- Demo -------------------------------------------------------------
    demo_events_per_second: float = Field(default=4.0, gt=0, le=500)
    demo_seed: int | None = None

    # --- Logging ----------------------------------------------------------
    log_level: str = "INFO"
    log_format: Literal["text", "json"] = "text"

    # ------------------------------------------------------------------ validators
    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        level = value.strip().upper()
        if level not in VALID_LOG_LEVELS:
            raise ValueError(f"log_level must be one of {sorted(VALID_LOG_LEVELS)}")
        return level

    @field_validator("host")
    @classmethod
    def _validate_host(cls, value: str) -> str:
        value = value.strip()
        if value == "localhost":
            return value
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("host must be an IP address or 'localhost'") from exc

    @field_validator("network_interface")
    @classmethod
    def _validate_interface(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        value = value.strip()
        if len(value) > 256 or any(ch in value for ch in "\x00\n\r"):
            raise ValueError("network_interface contains invalid characters")
        return value

    @field_validator("ingest_token", "demo_seed", mode="before")
    @classmethod
    def _blank_is_none(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator("api_url")
    @classmethod
    def _validate_api_url(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        value = value.strip().rstrip("/")
        if not value.startswith(("http://", "https://")):
            raise ValueError("api_url must start with http:// or https://")
        return value

    @field_validator("risk_suspicious_ports", "risk_common_ports")
    @classmethod
    def _validate_ports(cls, value: str) -> str:
        for item in split_csv(value):
            if not item.isdigit() or not 0 < int(item) <= 65535:
                raise ValueError(f"invalid port in list: {item!r}")
        return value

    @field_validator("trusted_dns_servers")
    @classmethod
    def _validate_dns_servers(cls, value: str) -> str:
        for item in split_csv(value):
            ipaddress.ip_address(item)
        return value

    @model_validator(mode="after")
    def _validate_thresholds(self) -> Settings:
        if self.risk_suspicious_threshold >= self.risk_dangerous_threshold:
            raise ValueError("risk_suspicious_threshold must be lower than risk_dangerous_threshold")
        return self

    # ------------------------------------------------------------------ helpers
    def resolve_path(self, path: Path) -> Path:
        """Resolve ``path`` relative to the project root unless already absolute."""
        path = path.expanduser()
        return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()

    @property
    def resolved_database_url(self) -> str:
        """Database URL with relative SQLite paths anchored at the project root."""
        url = make_url(self.database_url)
        if url.get_backend_name() != "sqlite" or not url.database or url.database == ":memory:":
            return self.database_url
        db_path = Path(url.database).expanduser()
        if not db_path.is_absolute():
            db_path = (PROJECT_ROOT / db_path).resolve()
        query = f"?{urlencode(dict(url.query), doseq=True)}" if url.query else ""
        return f"{url.drivername}:///{db_path.as_posix()}{query}"

    @property
    def allowed_host_list(self) -> list[str]:
        hosts = list(split_csv(self.allowed_hosts))
        if self.host not in hosts and self.host not in {"0.0.0.0", "::"}:
            hosts.append(self.host)
        return hosts

    @property
    def is_loopback_bind(self) -> bool:
        if self.host == "localhost":
            return True
        return ipaddress.ip_address(self.host).is_loopback

    @property
    def api_base_url(self) -> str:
        """URL local clients (dashboard, capture daemon) use to reach the API."""
        if self.api_url:
            return self.api_url
        host = self.host
        if host in {"0.0.0.0", "::"}:
            host = "127.0.0.1"
        if ":" in host:
            host = f"[{host}]"
        return f"http://{host}:{self.port}"

    @property
    def ws_events_url(self) -> str:
        base = self.api_base_url
        scheme, rest = base.split("://", 1)
        return f"{'wss' if scheme == 'https' else 'ws'}://{rest}/ws/events"

    @property
    def suspicious_ports(self) -> frozenset[int]:
        return frozenset(int(p) for p in split_csv(self.risk_suspicious_ports))

    @property
    def common_ports(self) -> frozenset[int]:
        return frozenset(int(p) for p in split_csv(self.risk_common_ports))

    @property
    def risky_tlds(self) -> frozenset[str]:
        return frozenset(t.lower().lstrip(".") for t in split_csv(self.risk_risky_tlds))

    @property
    def trusted_dns_server_set(self) -> frozenset[str]:
        return frozenset(str(ipaddress.ip_address(ip)) for ip in split_csv(self.trusted_dns_servers))


def load_settings(**overrides: object) -> Settings:
    """Build settings from env/.env, applying non-``None`` overrides (e.g. CLI flags)."""
    clean = {key: value for key, value in overrides.items() if value is not None}
    return Settings(**clean)  # type: ignore[arg-type]
