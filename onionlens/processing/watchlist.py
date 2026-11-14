"""Watchlist matching - detects when monitored assets show up in collected data."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from .ioc import IOC


@dataclass
class WatchTerm:
    kind: str  # domain | keyword | email_domain | ip_range | bin
    value: str
    severity: str = "high"


@dataclass
class WatchHit:
    term: WatchTerm
    matched: str
    snippet: str
    severity: str


_SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def _bump(sev: str) -> str:
    i = _SEVERITY_ORDER.index(sev) if sev in _SEVERITY_ORDER else 2
    return _SEVERITY_ORDER[min(i + 1, len(_SEVERITY_ORDER) - 1)]


def _snippet(text: str, start: int, end: int, width: int = 120) -> str:
    a, b = max(0, start - width), min(len(text), end + width)
    return ("…" if a else "") + text[a:b].replace("\n", " ") + ("…" if b < len(text) else "")


def match_watchlist(text: str, iocs: list[IOC], terms: list[WatchTerm]) -> list[WatchHit]:
    hits: list[WatchHit] = []
    seen: set[tuple[str, str]] = set()

    def add(term: WatchTerm, matched: str, snippet: str, severity: str) -> None:
        key = (term.kind + term.value, matched)
        if key not in seen:
            seen.add(key)
            hits.append(WatchHit(term, matched, snippet, severity))

    for term in terms:
        val = term.value.strip().lower()
        if not val:
            continue
        if term.kind in ("domain", "email_domain"):
            # leaked credentials for a monitored domain are the most severe signal
            for ioc in iocs:
                ctx = (ioc.context or "").lower()
                if ioc.type == "credential" and (ctx == val or ctx.endswith("." + val)):
                    add(term, ioc.value, f"Leaked credential for {ctx}", _bump(term.severity))
                elif ioc.type == "email" and (ctx == val or ctx.endswith("." + val)):
                    add(term, ioc.value, f"Email address on {ctx}", term.severity)
                elif term.kind == "domain" and ioc.type == "domain" and (ioc.raw == val or ioc.raw.endswith("." + val)):
                    m = re.search(re.escape(ioc.raw), text, re.IGNORECASE)
                    add(term, ioc.raw, _snippet(text, m.start(), m.end()) if m else ioc.raw, term.severity)
        elif term.kind == "keyword":
            for m in re.finditer(r"(?<!\w)" + re.escape(val) + r"(?!\w)", text, re.IGNORECASE):
                add(term, m.group(0), _snippet(text, m.start(), m.end()), term.severity)
                break
        elif term.kind == "ip_range":
            try:
                net = ipaddress.ip_network(val, strict=False)
            except ValueError:
                continue
            for ioc in iocs:
                if ioc.type == "ipv4" and ipaddress.ip_address(ioc.raw) in net:
                    add(term, ioc.raw, f"IP {ioc.raw} in monitored range {val}", term.severity)
        elif term.kind == "bin":
            for ioc in iocs:
                if ioc.type == "card" and ioc.value.startswith(val):
                    add(term, ioc.value, f"Card with monitored BIN {val}", _bump(term.severity))
    return hits
