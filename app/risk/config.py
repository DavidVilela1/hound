"""Risk-engine configuration: weights and thresholds in one documented place."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from app.core.config import Settings
from app.models.risk import RiskLevel


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
        return cls(
            suspicious_threshold=settings.risk_suspicious_threshold,
            dangerous_threshold=settings.risk_dangerous_threshold,
            window=timedelta(seconds=settings.risk_window_seconds),
            repeated_attempts_threshold=settings.risk_repeated_attempts_threshold,
            port_scan_threshold=settings.risk_port_scan_threshold,
            host_sweep_threshold=settings.risk_host_sweep_threshold,
            nxdomain_threshold=settings.risk_nxdomain_threshold,
            suspicious_ports=settings.suspicious_ports,
            common_ports=settings.common_ports,
            risky_tlds=settings.risky_tlds,
            trusted_dns_servers=settings.trusted_dns_server_set,
        )
