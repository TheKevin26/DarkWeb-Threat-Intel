"""Allowlist-only Tor crawler.

Safety properties:
* Refuses to run unless traffic is confirmed to exit through Tor (check.torproject.org).
* Only fetches hosts listed in ``config/seeds.yaml`` - links to other hosts are recorded as
  indicators but never followed.
* Text only: non-HTML/text responses are discarded before the body is read; bodies are capped.
* No JavaScript execution, no form submission, no logins, no downloads.
* Polite: fixed delay between requests, page and depth limits.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from collections.abc import Iterator
from urllib.parse import urldefrag, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from ..config import Settings, get_settings, load_yaml
from .base import Collector, Event, Health, RawItem
from .forum_parsers import extract_listings, extract_posts

log = logging.getLogger(__name__)

_ALLOWED_CT = ("text/html", "text/plain", "application/xhtml+xml")
_SKIP_EXT = (".jpg", ".jpeg", ".png", ".gif", ".zip", ".rar", ".7z", ".exe", ".pdf", ".mp4", ".iso", ".tar", ".gz")


class TorNotAvailable(RuntimeError):
    pass


def seed_auth(seed: dict) -> dict | None:
    """Session material for a seed, supplied by the analyst. Never a password: OnionLens does not log in.

    seeds.yaml:  cookie_env: MYFORUM_COOKIE     (env var holding "name=value; name2=value2")
                 headers: {...}                 (optional extra headers)
    """
    import os

    cookies: dict[str, str] = {}
    raw = os.environ.get(seed["cookie_env"], "") if seed.get("cookie_env") else ""
    for part in raw.split(";"):
        k, _, v = part.strip().partition("=")
        if k and v:
            cookies[k] = v
    cookies.update(seed.get("cookies") or {})
    headers = seed.get("headers") or {}
    return {"cookies": cookies, "headers": headers} if (cookies or headers) else None


def make_client(settings: Settings, proxy: str | None = None, verify: bool = True) -> httpx.Client:
    # httpcore's SOCKS5 implementation passes the hostname to the proxy, so .onion names (and DNS)
    # are resolved by Tor, never locally.
    return httpx.Client(
        proxy=proxy or settings.tor_proxy,
        verify=verify,
        timeout=settings.crawl_timeout_seconds,
        headers={"User-Agent": settings.user_agent, "Accept": "text/html,text/plain;q=0.9"},
        follow_redirects=True,
        max_redirects=3,
    )


def verify_tor(client: httpx.Client, settings: Settings) -> str:
    try:
        data = client.get(settings.tor_check_url, timeout=30).json()
    except Exception as exc:
        raise TorNotAvailable(f"cannot reach Tor check endpoint: {exc}") from exc
    if not data.get("IsTor"):
        raise TorNotAvailable("traffic is NOT exiting through Tor - refusing to crawl")
    return data.get("IP", "?")


def find_tor(settings: Settings | None = None) -> dict:
    """Try the configured proxy, then the fallbacks. Returns {available, proxy, exit_ip, tried, error}."""
    settings = settings or get_settings()
    candidates = [settings.tor_proxy] + [p.strip() for p in settings.tor_fallback_proxies.split(",") if p.strip()]
    errors = []
    for proxy in dict.fromkeys(candidates):
        try:
            with make_client(settings, proxy) as client:
                ip = verify_tor(client, settings)
            return {"available": True, "proxy": proxy, "exit_ip": ip, "tried": candidates, "error": None}
        except Exception as exc:
            errors.append(f"{proxy}: {str(exc)[:120]}")
    return {"available": False, "proxy": None, "exit_ip": None, "tried": candidates, "error": "; ".join(errors)}


class TorCrawler(Collector):
    name = "tor"

    def __init__(self, settings: Settings | None = None, seeds: list[dict] | None = None):
        self.settings = settings or get_settings()
        cfg = load_yaml(self.settings.seeds_file)
        self.seeds = seeds if seeds is not None else (cfg.get("onion_seeds") or [])

    def collect(self) -> Iterator[Event]:
        if not self.seeds:
            log.warning("no onion seeds configured in %s - nothing to crawl", self.settings.seeds_file)
            return
        tor = find_tor(self.settings)
        if not tor["available"]:
            raise TorNotAvailable(f"Tor not reachable ({tor['error']}). Start Tor Browser or the tor service.")
        # .onion addresses are self-authenticating (the address is the service's public key), so TLS
        # certificate checks add nothing there - many leak sites use self-signed certs. Clearnet stays verified.
        all_onion = all((urlparse(sd["url"]).hostname or "").endswith(".onion") for sd in self.seeds)
        with make_client(self.settings, tor["proxy"], verify=not all_onion) as client:
            log.info("Tor verified via %s (exit %s)", tor["proxy"], tor["exit_ip"])
            for seed in self.seeds:
                auth = seed_auth(seed)
                if auth:
                    # a site the analyst holds a session for: separate client so cookies never leak to other hosts
                    onion = (urlparse(seed["url"]).hostname or "").endswith(".onion")
                    with make_client(self.settings, tor["proxy"], verify=not onion) as site_client:
                        site_client.cookies.update(auth.get("cookies", {}))
                        site_client.headers.update(auth.get("headers", {}))
                        yield from self._crawl_site(site_client, seed)
                else:
                    yield from self._crawl_site(client, seed)

    def _crawl_site(self, client: httpx.Client, seed: dict) -> Iterator[Event]:
        start = seed["url"]
        name = seed.get("name") or urlparse(start).hostname
        host = urlparse(start).hostname
        allowed_hosts = {host, *seed.get("extra_hosts", [])}
        max_pages = int(seed.get("max_pages", self.settings.crawl_max_pages))
        max_depth = int(seed.get("max_depth", self.settings.crawl_max_depth))

        queue: deque[tuple[str, int]] = deque([(start, 0)])
        seen: set[str] = set()
        pages = 0
        first = True
        while queue and pages < max_pages:
            url, depth = queue.popleft()
            if url in seen:
                continue
            seen.add(url)
            t0 = time.perf_counter()
            try:
                body, status, ctype = self._fetch(client, url)
            except Exception as exc:
                if first:
                    yield Health(name, "tor", start, ok=False, error=str(exc)[:300])
                    return
                log.debug("fetch failed %s: %s", url, exc)
                continue
            latency = (time.perf_counter() - t0) * 1000
            if first:
                yield Health(name, "tor", start, ok=200 <= status < 400, status_code=status, latency_ms=latency)
                first = False
            if body is None:
                continue
            pages += 1
            is_html = "html" in ctype
            yield from self._items(seed, name, start, url, body, is_html)

            if is_html and depth < max_depth:
                for link in self._links(url, body):
                    if urlparse(link).hostname in allowed_hosts and link not in seen:
                        queue.append((link, depth + 1))
            time.sleep(self.settings.crawl_delay_seconds)

    @staticmethod
    def _items(seed: dict, name: str, start: str, url: str, body: str, is_html: bool) -> Iterator[RawItem]:
        """One item per page, or one per post / listing for forum and market seeds."""
        kind = (seed.get("type") or "site").lower()
        if is_html and kind == "forum":
            posts = extract_posts(body, url)
            for p in posts:
                yield RawItem(source_name=name, source_kind="tor", source_url=start, url=p["url"], content=p["text"],
                              is_html=False, author=p["author"], published_at=p["published_at"],
                              meta={"engine": p["engine"], "page": url})
            if posts:
                return
        if is_html and kind == "market":
            listings = extract_listings(body, url)
            for li in listings:
                text = "\n".join([li["title"], f"Price: {li['price']}", f"Vendor: {li['vendor'] or 'unknown'}", li["text"]])
                yield RawItem(source_name=name, source_kind="tor", source_url=start, url=li["url"], content=text,
                              is_html=False, title=li["title"], author=li["vendor"], meta={"page": url})
            if listings:
                return
        yield RawItem(source_name=name, source_kind="tor", source_url=start, url=url, content=body, is_html=is_html)

    def _fetch(self, client: httpx.Client, url: str) -> tuple[str | None, int, str]:
        with client.stream("GET", url) as resp:
            ctype = resp.headers.get("content-type", "").lower()
            if resp.status_code >= 400 or not ctype.startswith(_ALLOWED_CT):
                return None, resp.status_code, ctype
            chunks, size = [], 0
            for chunk in resp.iter_bytes():
                size += len(chunk)
                if size > self.settings.crawl_max_bytes:
                    break
                chunks.append(chunk)
            enc = resp.encoding or "utf-8"
            return b"".join(chunks).decode(enc, errors="replace"), resp.status_code, ctype

    @staticmethod
    def _links(base: str, html: str) -> list[str]:
        soup = BeautifulSoup(html, "html.parser")
        out = []
        for a in soup.find_all("a", href=True):
            href = urldefrag(urljoin(base, a["href"]))[0]
            p = urlparse(href)
            if p.scheme in ("http", "https") and not p.path.lower().endswith(_SKIP_EXT):
                # never follow logout / action endpoints
                if not any(x in href.lower() for x in ("logout", "login", "register", "action=", "delete")):
                    out.append(href)
        return out
