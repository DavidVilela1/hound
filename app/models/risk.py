"""Risk-assessment value objects."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class RiskLevel(StrEnum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"

    @property
    def label(self) -> str:
        return {"safe": "🟢 SAFE", "suspicious": "🟡 SUSPICIOUS", "dangerous": "🔴 DANGEROUS"}[self.value]

    @property
    def rank(self) -> int:
        return {"safe": 0, "suspicious": 1, "dangerous": 2}[self.value]


@dataclass(frozen=True, slots=True)
class RiskReason:
    """One signal that contributed points to a risk score."""

    code: str
    points: int
    description: str

    def as_dict(self) -> dict[str, object]:
        return {"code": self.code, "points": self.points, "description": self.description}


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """Deterministic outcome of the risk engine for one event."""

    score: int
    level: RiskLevel
    reasons: tuple[RiskReason, ...] = ()

    @property
    def summary(self) -> str | None:
        """Description of the highest-weighted reason, if any."""
        if not self.reasons:
            return None
        return max(self.reasons, key=lambda r: r.points).description
