"""Transparent, deterministic risk scoring.

``score = min(100, Σ points of every signal that fired)``

``level = DANGEROUS if score ≥ dangerous_threshold
          else SUSPICIOUS if score ≥ suspicious_threshold
          else SAFE``

The same sequence of events always yields the same scores. The engine keeps
bounded per-device state (see :mod:`app.risk.behavior`) and is intended to be
driven from a single processing thread.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.core.netutils import is_local_address
from app.models.events import NetworkEvent, PacketType
from app.models.processed import Enrichment
from app.models.risk import RiskAssessment, RiskReason
from app.risk.behavior import BehaviorSnapshot, DeviceBehaviorTracker
from app.risk.config import RiskConfig
from app.risk.signals import RiskContext, RiskSignal, default_signals

NXDOMAIN_RCODE = 3
MAX_SCORE = 100
ALLOWLISTED = "ALLOWLISTED"
BLOCKLISTED = "BLOCKLISTED_DOMAIN"


def apply_allowlist(reasons: Sequence[RiskReason], enrichment: Enrichment) -> list[RiskReason]:
    """Drop indicators the owner's allowlist covers, recording them in one 0-point reason.

    A domain entry covers every indicator of the event (it is a decision about that exact
    name, stronger than a blocklist entry above it). A device entry covers behavioural
    indicators but never a blocklist hit: a trusted device contacting a known-bad domain
    is still reported.
    """
    if enrichment.allowlisted_domain:
        entry, kind, suppressed = enrichment.allowlisted_domain, "domain", list(reasons)
    elif enrichment.allowlisted_device:
        entry, kind = enrichment.allowlisted_device, "device"
        suppressed = [reason for reason in reasons if reason.code != BLOCKLISTED]
    else:
        return list(reasons)
    if not suppressed:
        return list(reasons)
    kept = [reason for reason in reasons if reason not in suppressed]
    codes = ", ".join(reason.code for reason in suppressed)
    note = RiskReason(
        code=ALLOWLISTED,
        points=0,
        description=f"Allowlisted {kind} {entry}: {len(suppressed)} indicator(s) not counted ({codes})",
    )
    return [*kept, note]


class RiskEngine:
    def __init__(
        self,
        config: RiskConfig | None = None,
        *,
        tracker: DeviceBehaviorTracker | None = None,
        signals: Sequence[RiskSignal] | None = None,
    ) -> None:
        self.config = config or RiskConfig()
        self._tracker = tracker or DeviceBehaviorTracker(self.config.window)
        self._signals = list(signals) if signals is not None else default_signals()

    def observe(self, event: NetworkEvent) -> None:
        """Update behavioural state from events that are not scored (DNS responses)."""
        if event.packet_type is PacketType.DNS_RESPONSE and event.dns_rcode == NXDOMAIN_RCODE:
            # The response travels resolver → device, so the device is the destination.
            self._tracker.record_nxdomain(event.destination_ip, event.timestamp)

    def assess(self, event: NetworkEvent, enrichment: Enrichment) -> RiskAssessment:
        behavior = self._behavior_for(event)
        ctx = RiskContext(event=event, enrichment=enrichment, behavior=behavior, config=self.config)
        reasons = [reason for signal in self._signals if (reason := signal.evaluate(ctx)) is not None]
        reasons = apply_allowlist(reasons, enrichment)
        reasons.sort(key=lambda r: (-r.points, r.code))
        score = min(MAX_SCORE, sum(r.points for r in reasons))
        return RiskAssessment(score=score, level=self.config.level_for(score), reasons=tuple(reasons))

    def _behavior_for(self, event: NetworkEvent) -> BehaviorSnapshot:
        if event.packet_type is PacketType.TCP_SYN:
            return self._tracker.record_attempt(
                event.source_ip,
                event.destination_ip,
                event.destination_port,
                event.timestamp,
                local=is_local_address(event.destination_ip),
            )
        return self._tracker.snapshot(event.source_ip, event.timestamp)
