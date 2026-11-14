"""Collector interface. Collectors yield ``RawItem`` (content) and ``Health`` (uptime) events."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class RawItem:
    source_name: str
    source_kind: str  # tor | api | telegram | clearnet | demo
    url: str
    content: str  # HTML or plain text
    is_html: bool = True
    source_url: str | None = None
    title: str | None = None
    author: str | None = None
    published_at: datetime | None = None
    victim: dict | None = None  # structured leak-site victim, if the item is one
    victims: list[dict] = field(default_factory=list)  # several victims parsed from one leak-site page
    meta: dict = field(default_factory=dict)


@dataclass
class Health:
    source_name: str
    source_kind: str
    source_url: str | None
    ok: bool
    status_code: int | None = None
    latency_ms: float | None = None
    error: str | None = None
    checked_at: datetime | None = None  # defaults to now; demo data back-fills history


Event = RawItem | Health


class Collector:
    name = "base"

    def collect(self) -> Iterator[Event]:  # pragma: no cover - interface
        raise NotImplementedError
