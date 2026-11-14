"""Ahmia (clearnet .onion search engine) - discover onion pages mentioning watchlist terms.

Only search-result metadata (title, snippet, onion URL) is collected; the onion sites themselves are
not visited. Promising hosts can then be reviewed and added to ``config/seeds.yaml`` by an analyst.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from urllib.parse import parse_qs, urlparse

import httpx
from bs4 import BeautifulSoup

from ..config import get_settings
from .base import Collector, Event, Health, RawItem

log = logging.getLogger(__name__)

BASE = "https://ahmia.fi"


class AhmiaCollector(Collector):
    name = "ahmia"

    def __init__(self, queries: list[str], max_results: int = 30):
        self.queries = queries
        self.max_results = max_results

    def collect(self) -> Iterator[Event]:
        s = get_settings()
        headers = {"User-Agent": s.user_agent}
        with httpx.Client(timeout=45, headers=headers, follow_redirects=True) as client:
            t0 = time.perf_counter()
            try:
                home = client.get(BASE + "/")
                home.raise_for_status()
            except Exception as exc:
                yield Health(self.name, "clearnet", BASE, ok=False, error=str(exc)[:300])
                return
            yield Health(self.name, "clearnet", BASE, ok=True, status_code=home.status_code,
                         latency_ms=(time.perf_counter() - t0) * 1000)
            # Ahmia's search form carries a rotating hidden token field.
            token = {}
            form = BeautifulSoup(home.text, "html.parser").find("form")
            if form:
                for inp in form.find_all("input", {"type": "hidden"}):
                    if inp.get("name"):
                        token[inp["name"]] = inp.get("value", "")
            for q in self.queries:
                try:
                    resp = client.get(BASE + "/search/", params={"q": q, **token})
                    resp.raise_for_status()
                except Exception as exc:
                    log.warning("ahmia query %r failed: %s", q, exc)
                    continue
                yield from self._parse(resp.text, q)
                time.sleep(2)

    def _parse(self, html: str, query: str) -> Iterator[RawItem]:
        soup = BeautifulSoup(html, "html.parser")
        for li in soup.select("li.result")[: self.max_results]:
            a = li.find("a")
            if not a:
                continue
            href = a.get("href", "")
            target = parse_qs(urlparse(href).query).get("redirect_url", [href])[0]
            title = a.get_text(" ", strip=True)
            snippet = (li.find("p").get_text(" ", strip=True) if li.find("p") else "")
            cite = li.find("cite")
            onion = cite.get_text(strip=True) if cite else target
            yield RawItem(
                source_name=self.name,
                source_kind="clearnet",
                source_url=BASE,
                url=target,
                content=f"{title}\n{snippet}\nOnion: {onion}\nSearch query: {query}",
                is_html=False,
                title=title[:500],
                meta={"query": query},
            )
