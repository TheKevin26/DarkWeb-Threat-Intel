"""Threat score (0-100) for a document. Transparent, additive, and easy to tune."""

from __future__ import annotations

from datetime import datetime

from .classifier import SEVERITY
from .ioc import IOC, SENSITIVE_TYPES
from .watchlist import WatchHit

_HIT_WEIGHT = {"low": 5, "medium": 10, "high": 20, "critical": 30}


def threat_score(
    category: str,
    confidence: float,
    iocs: list[IOC],
    hits: list[WatchHit],
    published_at: datetime | None = None,
    now: datetime | None = None,
) -> float:
    # content severity: up to 55 points, scaled by classifier confidence
    score = 55 * SEVERITY.get(category, 0.1) * (0.5 + 0.5 * confidence)

    # leaked sensitive data and actionable technical indicators
    sensitive = sum(1 for i in iocs if i.type in SENSITIVE_TYPES)
    score += min(20, sensitive * 2.0)
    score += min(6, sum(1 for i in iocs if i.type in {"cve", "sha256", "md5", "sha1"}) * 3.0)

    score += min(40, sum(_HIT_WEIGHT.get(h.severity, 10) for h in hits))

    if published_at and now:
        age_days = (now - published_at).days
        if age_days <= 7:
            score += 5
        elif age_days > 180:
            score -= 5

    return round(max(0.0, min(100.0, score)), 1)
