"""Generic helpers for pulling repeated records (victim cards, forum posts, listings) out of HTML."""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime

from bs4 import BeautifulSoup, Tag

MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}

_DATE_PATTERNS = [
    (re.compile(r"\b(20\d{2})[-/.](\d{1,2})[-/.](\d{1,2})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?)?"), "ymd"),
    (re.compile(r"\b(\d{1,2})[./](\d{1,2})[./](20\d{2})\b"), "dmy"),
    (re.compile(r"\b(\d{1,2})\s+(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?,?\s+(20\d{2})", re.I), "d_mon_y"),
    (re.compile(r"\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(20\d{2})", re.I), "mon_d_y"),
]


def parse_date(text: str) -> datetime | None:
    """Best-effort date parser for the formats commonly seen on leak sites and forums."""
    if not text:
        return None
    for rx, kind in _DATE_PATTERNS:
        m = rx.search(text)
        if not m:
            continue
        try:
            if kind == "ymd":
                y, mo, d = int(m[1]), int(m[2]), int(m[3])
                hh, mm, ss = int(m[4] or 0), int(m[5] or 0), int(m[6] or 0)
                return datetime(y, mo, d, hh, mm, ss)
            if kind == "dmy":
                d, mo, y = int(m[1]), int(m[2]), int(m[3])
                if mo > 12:  # US order
                    d, mo = mo, d
                return datetime(y, mo, d)
            if kind == "d_mon_y":
                return datetime(int(m[3]), MONTHS[m[2][:3].lower()], int(m[1]))
            if kind == "mon_d_y":
                return datetime(int(m[3]), MONTHS[m[1][:3].lower()], int(m[2]))
        except ValueError:
            continue
    return None


def clean(text: str | None) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def soup_of(html: str) -> BeautifulSoup:
    soup = BeautifulSoup(html, "html.parser")
    for t in soup(["script", "style", "noscript", "svg", "head", "form", "iframe"]):
        t.decompose()
    return soup


def _signature(el: Tag) -> tuple[str, tuple[str, ...]]:
    return el.name, tuple(sorted(c for c in (el.get("class") or []) if not re.search(r"\d", c)))


def repeated_blocks(soup: BeautifulSoup, min_count: int = 3, min_len: int = 12, max_len: int = 4000) -> list[Tag]:
    """Return the most plausible set of repeated sibling elements (cards / rows / posts).

    Siblings that share a tag + class signature are grouped; the group with the best
    count x typical-text-length score wins. Navigation-like groups (very short text) are ignored.
    """
    groups: dict[tuple, list[Tag]] = defaultdict(list)
    for el in soup.find_all(True):
        if el.name in ("html", "body", "head", "br", "span", "b", "i", "strong", "em", "option", "img"):
            continue
        parent = el.parent
        if parent is None:
            continue
        groups[(id(parent), _signature(el))].append(el)

    best, best_score = [], 0.0
    for (_, (tag, classes)), els in groups.items():
        if len(els) < min_count:
            continue
        lens = sorted(len(clean(e.get_text(" "))) for e in els)
        median = lens[len(lens) // 2]
        if median < min_len or median > max_len:
            continue
        if tag in ("li", "a") and median < 25:  # menus
            continue
        score = len(els) * min(median, 400) * (1.3 if classes else 1.0)
        if score > best_score:
            best, best_score = els, score
    return best


def first_text(el: Tag, selectors: list[str]) -> str:
    for sel in selectors:
        found = el.select_one(sel)
        if found:
            t = clean(found.get_text(" "))
            if t:
                return t
    return ""
