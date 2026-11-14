"""Victim extraction from ransomware leak-site (DLS) pages collected over Tor.

Each group's site is built differently, so known layouts get a small selector spec (written against
real pages crawled by OnionLens), and every other site falls back to generic repeated-card detection.
Only names, domains, dates, sectors and countries are extracted; nothing is downloaded.

Sites that render their victim list with JavaScript (e.g. some React/Vue leak sites) return an empty
HTML shell to a text-only crawler and yield no victims - executing attacker JavaScript is deliberately
not supported.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from bs4 import Tag

from ..countries import COUNTRIES
from .htmlblocks import clean, parse_date, repeated_blocks, soup_of

# group key (lowercase, alphanumerics only) -> selectors
SPECS: dict[str, dict] = {
    "qilin": {"block": "div.item_box", "name": "a.item_box-title", "sector": "p.item_box-info",
              "domain_href": "a.item_box-info__link"},
    "osiris": {"block": "a.co-card", "name": ".co-name", "country": ".co-country", "date": ".co-meta"},
    "exitium": {"block": "div.target-card", "name_attr": "data-title", "date_attr": "data-date", "text_attr": "data-text"},
    "ransomexx": {"block": "li", "name": "h4 a", "require": "h4"},
    "n0n": {"block": "div.modal", "name": "h3", "meta": ".meta"},
    "climaxinc": {"block": "article.post", "name": ".post-title .sr-only", "sector": ".post-cat", "date": "time"},
    "curiousworm": {"block": "div.target-card", "fields": True},
    "arcusmedia": {"block": "article.post", "name": ".entry-title a", "date": "time.published"},
    "vexyransomware": {"block": "div.target-box", "name": ".company-name", "date": ".date-row"},
    "vortex": {"block": "div.card", "name": "h3", "date": "time"},
}

JUNK_NAMES = {"redacted", "learn more", "get data", "company", "hidden", "read more", "more", "download", "leaked",
              "published", "unknown", "n/a", "victim", "target", "home", "contact", "news", "paid", "files", "file",
              "fresh leaks", "leaks", "data", "full leak", "new", "sold", "private", "soon", "blog", "about", "faq",
              "rules", "partners", "affiliates", "press", "mirror", "mirrors"}
_SIZE_SUFFIX = re.compile(r"\s*[-–—|:(]\s*\d[\d.,]*\s*\+?\s*(?:[kmgt]i?b|bytes|gb|tb|mb)\)?\s*$", re.I)
_NAME_PREFIX = re.compile(r"^(?:data leak link for|data from|data of|leak of|leaked data of|full leak of|to)\s+", re.I)
DOMAIN_BLOCKLIST = ("zoominfo.com", "linkedin.com", "google.com", "facebook.com", "twitter.com", "x.com", "wikipedia.org",
                    "youtube.com", "instagram.com", "github.com", "w3.org", "bit.ly")
_DOMAIN_RE = re.compile(r"\b(?:https?://)?(?:www\.)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b", re.I)
_FILE_TLDS = {"zip", "rar", "png", "jpg", "jpeg", "gif", "pdf", "html", "htm", "php", "js", "css", "txt", "onion", "7z"}
_AMBIGUOUS_CCTLDS = {"io", "co", "me", "tv", "ai", "cc", "to", "ly", "fm", "gg", "ws", "so", "sh", "la", "is", "it"}
_DATA_HINT = re.compile(r"\b(revenue|employees|leaked|published|exfiltrat|gb|tb|files|records|data|website|countdown)\b", re.I)

_COUNTRY_ALIASES = {
    "usa": "US", "u.s.": "US", "u.s.a.": "US", "united states of america": "US", "america": "US", "us": "US",
    "uk": "GB", "england": "GB", "great britain": "GB", "scotland": "GB", "brasil": "BR", "deutschland": "DE",
    "korea": "KR", "republic of korea": "KR", "uae": "AE", "viet nam": "VN", "czech republic": "CZ",
    "russian federation": "RU", "the netherlands": "NL", "holland": "NL", "türkiye": "TR", "turkiye": "TR",
}
_COUNTRY_NAMES = {name.lower(): code for code, (name, _) in COUNTRIES.items()}
_COUNTRY_NAMES.update(_COUNTRY_ALIASES)
_COUNTRY_RE = re.compile(
    r"(?<![a-z])(" + "|".join(re.escape(n) for n in sorted(_COUNTRY_NAMES, key=len, reverse=True) if len(n) > 2) + r")(?![a-z])",
    re.I,
)
_US_STATES = {"alabama", "alaska", "arizona", "arkansas", "california", "colorado", "connecticut", "delaware", "florida",
              "georgia", "hawaii", "idaho", "illinois", "indiana", "iowa", "kansas", "kentucky", "louisiana", "maine",
              "maryland", "massachusetts", "michigan", "minnesota", "mississippi", "missouri", "montana", "nebraska",
              "nevada", "new hampshire", "new jersey", "new mexico", "new york", "north carolina", "north dakota", "ohio",
              "oklahoma", "oregon", "pennsylvania", "rhode island", "south carolina", "south dakota", "tennessee", "texas",
              "utah", "vermont", "virginia", "washington", "west virginia", "wisconsin", "wyoming"}


def group_key(group: str) -> str:
    return re.sub(r"[^a-z0-9]", "", group.lower())


def norm_domain(value: str | None) -> str | None:
    if not value:
        return None
    v = value.strip().lower()
    if "://" in v:
        v = urlparse(v).netloc or v
    v = v.split("/")[0].split(":")[0].removeprefix("www.")
    if "." not in v or v.endswith(".onion") or any(v == b or v.endswith("." + b) for b in DOMAIN_BLOCKLIST):
        return None
    if v.rsplit(".", 1)[-1] in _FILE_TLDS:
        return None
    return v


def find_domain(text: str) -> str | None:
    for m in _DOMAIN_RE.finditer(text):
        d = norm_domain(m.group(1))
        if d:
            return d
    return None


def country_from_text(text: str) -> str | None:
    if not text:
        return None
    m = _COUNTRY_RE.search(text)
    if m:
        return _COUNTRY_NAMES.get(m.group(1).lower())
    low = text.lower()
    if re.search(r"\((us|usa)\)|\bus\b", low) or any(re.search(rf"\b{s}\b", low) for s in _US_STATES):
        return "US"
    for tag in re.findall(r"#([a-z][a-z ]+)", low):
        if tag.strip() in _COUNTRY_NAMES:
            return _COUNTRY_NAMES[tag.strip()]
    return None


def country_from_domain(domain: str | None) -> str | None:
    if not domain:
        return None
    tld = domain.rsplit(".", 1)[-1]
    if tld == "uk":
        return "GB"
    if len(tld) == 2 and tld not in _AMBIGUOUS_CCTLDS and tld.upper() in COUNTRIES:
        return tld.upper()
    return None


def _txt(el: Tag, sel: str | None) -> str:
    if not sel:
        return ""
    found = el.select_one(sel)
    if not found:
        return ""
    return clean(found.get("datetime") or found.get_text(" "))


def clean_name(name: str) -> tuple[str, str | None]:
    """Strip size suffixes, 'Name | domain' tails and narrative prefixes. Returns (name, domain-from-name)."""
    domain = None
    name = _SIZE_SUFFIX.sub("", name.strip())
    if " | " in name:  # "Qualiflex Solutions | qualiflex.solutions"
        left, _, right = name.partition(" | ")
        domain = norm_domain(right) if re.fullmatch(r"[\w.-]+\.[a-z]{2,24}", right.strip(), re.I) else None
        name = left.strip()
    name = _NAME_PREFIX.sub("", name).strip(" -–—:|")
    return name, domain


def _valid_name(name: str, strict: bool = False) -> bool:
    n = name.strip().lower()
    if not (2 <= len(n) <= 150) or n.endswith("?") or n in JUNK_NAMES or "*" not in n and "hidden name" in n:
        return False
    if "*" in n or "@" in n or re.fullmatch(r"[\*\-_#. x0-9]+", n) or n.startswith(("what ", "how ", "why ", "faq")):
        return False
    if strict and (len(n.split()) > 7 or re.search(r"\b(published|we'll|we will|hello world|part\s?\d)\b", n)):
        return False  # generic layouts: sentence-like titles are blog posts, not victim names
    return True


def _extract(el: Tag, spec: dict) -> dict | None:
    text = clean(el.get_text(" "))
    if spec.get("text_attr") and el.get(spec["text_attr"]):
        text = f"{el.get(spec['text_attr'])} {text}"

    fields: dict[str, str] = {}
    if spec.get("fields"):  # label/value rows; values may be split into one <span> per character
        for f in el.select(".field"):
            label = clean((f.select_one(".label") or f).get_text(" ")).rstrip(":").lower()
            val = f.select_one(".value")
            if val:
                fields[label] = clean(val.get_text(""))

    name = ""
    if spec.get("name_attr"):
        name = clean(el.get(spec["name_attr"]))
    name = name or _txt(el, spec.get("name")) or fields.get("company", "")
    if not name and not spec:
        for sel in ("h1", "h2", "h3", "h4", "h5", ".title", ".name", "strong", "b", "a"):
            name = _txt(el, sel)
            if name:
                break
    domain = None
    m = re.search(r"\(([^()\s]+\.[a-z]{2,24})\)\s*$", name, re.I)  # "Go2Joy (go2joy.vn)"
    if m:
        domain = norm_domain(m.group(1))
        name = name[: m.start()].strip()
    if spec.get("domain_href"):
        a = el.select_one(spec["domain_href"])
        if a and a.get("href"):
            domain = domain or norm_domain(a["href"])
    name, name_domain = clean_name(name)
    domain = domain or name_domain
    domain = domain or norm_domain(name if re.fullmatch(r"[\w.-]+\.[a-z]{2,24}", name, re.I) else None) or find_domain(text)
    if not _valid_name(name, strict=not spec):
        return None

    date = None
    if spec.get("date_attr") and el.get(spec["date_attr"]):
        date = parse_date(el.get(spec["date_attr"]))
    date = date or parse_date(_txt(el, spec.get("date"))) or parse_date(text)

    meta = _txt(el, spec.get("meta"))
    sector = _txt(el, spec.get("sector")) or (meta.split("·")[0].strip() if "·" in meta else None)
    country = (country_from_text(_txt(el, spec.get("country"))) or country_from_text(meta)
               or country_from_text(text) or country_from_domain(domain))

    if not spec and not (domain or date or _DATA_HINT.search(text)):
        return None
    return {
        "name": name[:300],
        "domain": domain,
        "country": country,
        "sector": (sector or None) and sector[:100],
        "discovered_at": date,
        "description": text[:600] or None,
    }


def parse_leak_page(html: str, group: str, base_url: str | None = None) -> list[dict]:
    """Extract victim postings from a leak-site page. Returns a list of victim dicts (possibly empty)."""
    if not html or len(html) < 200:
        return []
    soup = soup_of(html)
    spec = SPECS.get(group_key(group))
    blocks: list[Tag] = []
    if spec:
        blocks = [b for b in soup.select(spec["block"]) if not spec.get("require") or b.select_one(spec["require"])]
    if not blocks:
        spec = {}
        blocks = repeated_blocks(soup)
    victims, seen = [], set()
    for b in blocks:
        v = _extract(b, spec or {})
        if v and v["name"].lower() not in seen:
            seen.add(v["name"].lower())
            v["group_name"] = group
            victims.append(v)
    return victims
