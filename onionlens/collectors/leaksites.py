"""Direct Tor collection from ransomware data-leak sites (DLS).

The list of current leak-site .onion addresses comes from ransomware.live's public group directory,
so no hand-picked criminal URLs are hard-coded. For each site that ransomware.live currently reports
as online, the crawler fetches the front page only (depth 0, text/HTML, no downloads, no forms)
through Tor. Victim postings are then extracted from the page (see ``leak_parsers``) and stored as
victims seen by *our own* crawl, alongside the third-party feed.
"""

from __future__ import annotations

import logging
import random
from collections.abc import Iterator

import httpx

from ..config import get_settings
from .base import Collector, Event, Health, RawItem
from .leak_parsers import parse_leak_page
from .tor_crawler import TorCrawler

log = logging.getLogger(__name__)

GROUPS = "https://data.ransomware.live/groups.json"


def leak_site_seeds(groups: list[dict], max_sites: int, priority: list[str] | None = None) -> list[dict]:
    seeds = []
    for g in groups:
        for loc in g.get("locations") or []:
            if not loc.get("available") or not loc.get("enabled", True):
                continue
            if (loc.get("type") or "DLS").upper() != "DLS":
                continue
            fqdn = (loc.get("fqdn") or "").strip().lower()
            if not fqdn.endswith(".onion"):
                continue
            url = loc.get("slug") or f"http://{fqdn}/"
            if not url.startswith("http"):
                url = f"http://{fqdn}/"
            seeds.append({"name": f"{g['name']} leak site", "url": url, "max_pages": 1, "max_depth": 0, "group": g["name"]})
            break  # one location per group is enough
    random.shuffle(seeds)  # spread load across runs
    if priority:
        rank = {name.lower(): i for i, name in enumerate(priority)}
        seeds.sort(key=lambda s: rank.get(s["group"].lower(), len(rank)))
    return seeds[:max_sites]


def active_groups(limit: int = 30) -> list[str]:
    """Groups with the most victims in our database over the last 30 days (most active first)."""
    from datetime import timedelta

    from sqlalchemy import func, select

    from ..db import session_scope
    from ..models import Victim, utcnow

    with session_scope() as s:
        rows = s.execute(
            select(Victim.group_name, func.count())
            .where(Victim.discovered_at >= utcnow() - timedelta(days=30))
            .group_by(Victim.group_name)
            .order_by(func.count().desc())
            .limit(limit)
        ).all()
    return [g for g, _ in rows]


class LeakSiteCollector(Collector):
    name = "leaksites"

    def __init__(self, max_sites: int = 30, groups: list[str] | None = None):
        self.max_sites = max_sites
        self.groups = groups

    def collect(self) -> Iterator[Event]:
        try:
            groups = httpx.get(GROUPS, timeout=60, headers={"User-Agent": "onionlens/0.1"}).raise_for_status().json()
        except Exception as exc:
            yield Health("ransomware.live groups", "api", GROUPS, ok=False, error=str(exc)[:300])
            return
        if self.groups:
            wanted = {g.lower() for g in self.groups}
            groups = [g for g in groups if g["name"].lower() in wanted]
        try:
            priority = active_groups()
        except Exception:  # empty / missing DB
            priority = []
        seeds = leak_site_seeds(groups, self.max_sites, priority)
        log.info("crawling %d ransomware leak sites over Tor", len(seeds))
        group_of = {s["name"]: s["group"] for s in seeds}
        settings = get_settings().model_copy(update={"crawl_delay_seconds": 1.0})
        for ev in TorCrawler(settings=settings, seeds=seeds).collect():
            if isinstance(ev, RawItem):
                ev.source_kind = "tor"
                group = group_of.get(ev.source_name, ev.source_name.removesuffix(" leak site"))
                ev.author = group
                ev.victims = parse_leak_page(ev.content, group, base_url=ev.url) if ev.is_html else []
                ev.meta["group"] = group
            yield ev
