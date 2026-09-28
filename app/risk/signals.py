"""Individual, independently testable risk signals.

Each signal inspects a :class:`RiskContext` and either returns a
:class:`RiskReason` (with the points it contributes) or ``None``. Signals
describe *indicators*; none of them is proof of compromise.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from app.core.netutils import shannon_entropy
from app.models.events import NetworkEvent, PacketType
from app.models.processed import Enrichment
from app.models.risk import RiskReason
from app.risk.behavior import BehaviorSnapshot
from app.risk.config import RiskConfig

PORT_NAMES: dict[int, str] = {
    23: "Telnet",
    135: "MS-RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    3389: "RDP",
    4444: "Metasploit default",
    5900: "VNC",
    6667: "IRC",
}


@dataclass(frozen=True, slots=True)
class RiskContext:
    event: NetworkEvent
    enrichment: Enrichment
    behavior: BehaviorSnapshot
    config: RiskConfig

    @property
    def is_syn(self) -> bool:
        return self.event.packet_type is PacketType.TCP_SYN

    @property
    def is_dns_query(self) -> bool:
        return self.event.packet_type is PacketType.DNS_QUERY


class RiskSignal(Protocol):
    code: str

    def evaluate(self, ctx: RiskContext) -> RiskReason | None: ...


def _reason(code: str, points: int, description: str) -> RiskReason:
    return RiskReason(code=code, points=points, description=description)


class BlocklistedDomainSignal:
    code = "BLOCKLISTED_DOMAIN"

    def evaluate(self, ctx: RiskContext) -> RiskReason | None:
        match = ctx.enrichment.blocklist_match
        if not match:
            return None
        return _reason(
            self.code,
            ctx.config.weights.blocklisted_domain,
            f"Domain {ctx.enrichment.domain} matches blocklist entry {match}",
        )


class PortScanSignal:
    code = "PORT_SCAN_PATTERN"

    def evaluate(self, ctx: RiskContext) -> RiskReason | None:
        count = ctx.behavior.ports_on_target_host
        if not ctx.is_syn or count < ctx.config.port_scan_threshold:
            return None
        return _reason(
            self.code,
            ctx.config.weights.port_scan,
            f"{count} different ports probed on {ctx.event.destination_ip} within "
            f"{int(ctx.config.window.total_seconds())}s (port-scan-like pattern)",
        )


class HostSweepSignal:
    code = "HOST_SWEEP_PATTERN"

    def evaluate(self, ctx: RiskContext) -> RiskReason | None:
        count = ctx.behavior.local_hosts_contacted
        if not ctx.is_syn or ctx.enrichment.destination_is_public or count < ctx.config.host_sweep_threshold:
            return None
        return _reason(
            self.code,
            ctx.config.weights.host_sweep,
            f"{count} local hosts contacted within {int(ctx.config.window.total_seconds())}s "
            "(network-sweep-like pattern)",
        )


class RepeatedAttemptsSignal:
    code = "REPEATED_CONNECTION_ATTEMPTS"

    def evaluate(self, ctx: RiskContext) -> RiskReason | None:
        count = ctx.behavior.attempts_to_target
        if not ctx.is_syn or count < ctx.config.repeated_attempts_threshold:
            return None
        return _reason(
            self.code,
            ctx.config.weights.repeated_attempts,
            f"{count} connection attempts to {ctx.event.destination_ip}:{ctx.event.destination_port} "
            f"within {int(ctx.config.window.total_seconds())}s",
        )


class SuspiciousPortSignal:
    code = "SUSPICIOUS_PORT"

    def evaluate(self, ctx: RiskContext) -> RiskReason | None:
        port = ctx.event.destination_port
        if not ctx.is_syn or not ctx.enrichment.destination_is_public or port not in ctx.config.suspicious_ports:
            return None
        name = PORT_NAMES.get(port or 0, "service")
        return _reason(
            self.code,
            ctx.config.weights.suspicious_port,
            f"Connection attempt to port {port} ({name}) on a public address",
        )


class UncommonPortSignal:
    code = "UNCOMMON_PORT"

    def evaluate(self, ctx: RiskContext) -> RiskReason | None:
        port = ctx.event.destination_port
        cfg = ctx.config
        if (
            not ctx.is_syn
            or not ctx.enrichment.destination_is_public
            or port is None
            or port in cfg.common_ports
            or port in cfg.suspicious_ports
        ):
            return None
        return _reason(self.code, cfg.weights.uncommon_port, f"Connection attempt to uncommon port {port}")


class DirectIpConnectionSignal:
    code = "NO_PRIOR_DNS_LOOKUP"

    def evaluate(self, ctx: RiskContext) -> RiskReason | None:
        if not ctx.is_syn or not ctx.enrichment.destination_is_public or ctx.enrichment.domain:
            return None
        return _reason(
            self.code,
            ctx.config.weights.direct_ip_connection,
            "Connection to a public IP with no preceding DNS lookup observed",
        )


class NxdomainBurstSignal:
    code = "NXDOMAIN_BURST"

    def evaluate(self, ctx: RiskContext) -> RiskReason | None:
        count = ctx.behavior.nxdomain_count
        if not ctx.is_dns_query or count < ctx.config.nxdomain_threshold:
            return None
        return _reason(
            self.code,
            ctx.config.weights.nxdomain_burst,
            f"Device received {count} failed DNS lookups (NXDOMAIN) within {int(ctx.config.window.total_seconds())}s",
        )


class HighEntropyDomainSignal:
    code = "HIGH_ENTROPY_DOMAIN"

    def evaluate(self, ctx: RiskContext) -> RiskReason | None:
        domain = ctx.enrichment.domain
        if not domain or not ctx.is_dns_query:
            return None
        cfg = ctx.config
        labels = [
            label
            for label in domain.split(".")[:-1]
            if len(label) >= cfg.entropy_min_label_length and not label.startswith("xn--")
        ]
        if not labels:
            return None
        label = max(labels, key=shannon_entropy)
        entropy = shannon_entropy(label)
        if entropy < cfg.entropy_threshold:
            return None
        return _reason(
            self.code,
            cfg.weights.high_entropy_domain,
            f"Domain label '{label}' looks randomly generated (entropy {entropy:.2f} bits/char)",
        )


class LongDomainSignal:
    code = "LONG_DOMAIN"

    def evaluate(self, ctx: RiskContext) -> RiskReason | None:
        domain = ctx.enrichment.domain
        if not domain or not ctx.is_dns_query:
            return None
        cfg = ctx.config
        labels = domain.count(".") + 1
        if len(domain) < cfg.long_domain_length and labels <= cfg.max_labels:
            return None
        return _reason(
            self.code,
            cfg.weights.long_domain,
            f"Unusually long domain name ({len(domain)} characters, {labels} labels)",
        )


class RiskyTldSignal:
    code = "RISKY_TLD"

    def evaluate(self, ctx: RiskContext) -> RiskReason | None:
        domain = ctx.enrichment.domain
        if not domain or not ctx.is_dns_query:
            return None
        tld = domain.rsplit(".", 1)[-1]
        if tld not in ctx.config.risky_tlds:
            return None
        return _reason(
            self.code,
            ctx.config.weights.risky_tld,
            f"Top-level domain .{tld} is frequently associated with abuse",
        )


class UnusualQueryTypeSignal:
    code = "UNUSUAL_DNS_QUERY_TYPE"

    def evaluate(self, ctx: RiskContext) -> RiskReason | None:
        qtype = ctx.event.dns_query_type
        if not ctx.is_dns_query or qtype not in ctx.config.unusual_query_types:
            return None
        return _reason(
            self.code,
            ctx.config.weights.unusual_query_type,
            f"DNS {qtype} query (a record type also used by DNS-tunnelling tools)",
        )


class UntrustedResolverSignal:
    code = "UNTRUSTED_DNS_RESOLVER"

    def evaluate(self, ctx: RiskContext) -> RiskReason | None:
        trusted = ctx.config.trusted_dns_servers
        if not trusted or not ctx.is_dns_query or ctx.event.destination_ip in trusted:
            return None
        return _reason(
            self.code,
            ctx.config.weights.untrusted_resolver,
            f"DNS query sent to {ctx.event.destination_ip}, which is not a configured resolver",
        )


def default_signals() -> list[RiskSignal]:
    return [
        BlocklistedDomainSignal(),
        PortScanSignal(),
        HostSweepSignal(),
        RepeatedAttemptsSignal(),
        SuspiciousPortSignal(),
        UncommonPortSignal(),
        DirectIpConnectionSignal(),
        NxdomainBurstSignal(),
        HighEntropyDomainSignal(),
        LongDomainSignal(),
        RiskyTldSignal(),
        UnusualQueryTypeSignal(),
        UntrustedResolverSignal(),
    ]
