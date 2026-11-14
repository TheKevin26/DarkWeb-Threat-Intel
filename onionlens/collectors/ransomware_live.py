"""ransomware.live public dataset - ransomware leak-site victim postings, gathered without touching Tor.

The free JSON dump (newest first) is published at https://data.ransomware.live/victims.json.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from datetime import datetime, timezone

import httpx

from .base import Collector, Event, Health, RawItem

log = logging.getLogger(__name__)

DATASET = "https://data.ransomware.live/victims.json"


def _parse_dt(value) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _first(d: dict, *keys):
    for k in keys:
        if d.get(k):
            return d[k]
    return None


def parse_victims(items: list[dict], limit: int) -> Iterator[RawItem]:
    for v in items[:limit]:
        name = _first(v, "post_title", "victim", "name")
        group = _first(v, "group_name", "group")
        if not name or not group:
            continue
        country = (_first(v, "country") or "").upper() or None
        sector = _first(v, "activity", "sector")
        if sector in ("Not Found", ""):
            sector = None
        desc = (_first(v, "description", "summary") or "").strip()
        domain = _first(v, "website", "domain")
        discovered = _parse_dt(_first(v, "discovered", "published", "attackdate"))
        text = (
            f"Ransomware group {group} listed victim {name} on its leak site.\n"
            f"Country: {country or 'unknown'}. Sector: {sector or 'unknown'}. Website: {domain or 'n/a'}.\n"
            f"{desc}\nThe group threatens that exfiltrated data will be published unless a ransom is paid."
        )
        yield RawItem(
            source_name="ransomware.live",
            source_kind="api",
            source_url=DATASET,
            url=_first(v, "post_url", "url") or f"ransomware.live://{group}/{name}",
            content=text,
            is_html=False,
            title=f"[{group}] {name}",
            author=group,
            published_at=discovered,
            victim={
                "name": name[:300], "group_name": group[:100], "country": country, "sector": sector,
                "domain": (domain or None) and domain[:300], "description": desc[:2000] or None,
                "discovered_at": discovered,
            },
        )


class RansomwareLiveCollector(Collector):
    name = "ransomware.live"

    def __init__(self, url: str = DATASET, limit: int = 500):
        self.url = url
        self.limit = limit

    def collect(self) -> Iterator[Event]:
        t0 = time.perf_counter()
        try:
            resp = httpx.get(self.url, timeout=120, headers={"User-Agent": "onionlens/0.1"}, follow_redirects=True)
            latency = (time.perf_counter() - t0) * 1000
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            yield Health(self.name, "api", self.url, ok=False, error=str(exc)[:300])
            return
        yield Health(self.name, "api", self.url, ok=True, status_code=resp.status_code, latency_ms=latency)
        items = data if isinstance(data, list) else data.get("victims") or data.get("data") or []
        items.sort(key=lambda v: v.get("discovered") or "", reverse=True)
        yield from parse_victims(items, self.limit)
