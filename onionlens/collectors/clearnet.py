"""Generic clearnet URL collector - public paste sites, RSS-less forums, researcher feeds.

URLs come from ``clearnet_urls`` in seeds.yaml. Same text-only / size-capped rules as the Tor crawler.
"""

from __future__ import annotations

import time
from collections.abc import Iterator

import httpx

from ..config import get_settings, load_yaml
from .base import Collector, Event, Health, RawItem


class ClearnetCollector(Collector):
    name = "clearnet"

    def __init__(self, urls: list[dict] | None = None):
        s = get_settings()
        self.settings = s
        self.urls = urls if urls is not None else (load_yaml(s.seeds_file).get("clearnet_urls") or [])

    def collect(self) -> Iterator[Event]:
        s = self.settings
        with httpx.Client(timeout=30, headers={"User-Agent": s.user_agent}, follow_redirects=True) as client:
            for entry in self.urls:
                url, name = entry["url"], entry.get("name", entry["url"])
                t0 = time.perf_counter()
                try:
                    resp = client.get(url)
                except Exception as exc:
                    yield Health(name, "clearnet", url, ok=False, error=str(exc)[:300])
                    continue
                ctype = resp.headers.get("content-type", "")
                yield Health(name, "clearnet", url, ok=resp.is_success, status_code=resp.status_code,
                             latency_ms=(time.perf_counter() - t0) * 1000)
                if resp.is_success and ctype.startswith(("text/", "application/xhtml")):
                    yield RawItem(name, "clearnet", url, resp.text[: s.crawl_max_bytes], is_html="html" in ctype,
                                  source_url=url)
                time.sleep(1)
