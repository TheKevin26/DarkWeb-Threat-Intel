"""Split forum threads and market pages into individual posts / listings.

Supports the forum engines most dark web forums run on (XenForo, phpBB, MyBB, SMF, vBulletin) plus
a generic repeated-block fallback, and a generic market-listing extractor. Each post becomes its own
document, so the author handle, date and wallets are attributed precisely, which makes actor linking
far more accurate than treating a whole thread page as one blob.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

from .htmlblocks import clean, first_text, parse_date, repeated_blocks, soup_of

# engine -> (post selector, author selectors, body selectors, date selectors)
ENGINES = {
    "xenforo": ("article.message", ["[data-author]", ".message-name", ".username"], [".bbWrapper", ".message-userContent"], ["time"]),
    "phpbb": ("div.post", [".author .username", ".author a", "a.username", ".username-coloured"], [".content", ".postbody"], ["time", ".author"]),
    "mybb": ("div.post", [".post_author strong", ".post_author a", ".author_information a"], [".post_body"], [".post_date"]),
    "smf": ("div.post_wrapper", [".poster h4 a", ".poster h4", ".poster a"], [".post .inner", ".inner"], [".keyinfo .smalltext", ".smalltext"]),
    "vbulletin": ("li.postcontainer, li.postbitlegacy, div.postcontainer", [".username", ".popupmenu a"], [".postcontent", ".content"], [".postdate", ".date"]),
}

_PRICE_RE = re.compile(r"(?:\$|USD|EUR|€)\s?\d[\d,.]*|\d[\d,.]*\s?(?:USD|EUR|BTC|XMR|\$)", re.I)


def detect_engine(html: str) -> str | None:
    low = html[:20000].lower()
    if "xenforo" in low or 'data-template="thread_view"' in low:
        return "xenforo"
    if "phpbb" in low:
        return "phpbb"
    if "mybb" in low:
        return "mybb"
    if "smf" in low and ("simple machines" in low or "smf_" in low):
        return "smf"
    if "vbulletin" in low:
        return "vbulletin"
    return None


def extract_posts(html: str, base_url: str) -> list[dict]:
    """Return [{author, published_at, text, anchor}] for every post on a forum thread page."""
    soup = soup_of(html)
    engine = detect_engine(html)
    posts: list[dict] = []
    if engine:
        sel, author_sel, body_sel, date_sel = ENGINES[engine]
        for i, el in enumerate(soup.select(sel)):
            author = el.get("data-author") or first_text(el, author_sel)
            body_el = next((el.select_one(b) for b in body_sel if el.select_one(b)), el)
            date_el = next((el.select_one(d) for d in date_sel if el.select_one(d)), None)
            date = parse_date((date_el.get("datetime") or date_el.get_text(" ")) if date_el else "")
            text = clean(body_el.get_text(" "))
            if text:
                posts.append({"author": author[:100] or None, "published_at": date, "text": text,
                              "anchor": el.get("id") or f"post-{i}", "engine": engine})
    if not posts:
        for i, el in enumerate(repeated_blocks(soup, min_len=30)):
            text = clean(el.get_text(" "))
            posts.append({"author": None, "published_at": parse_date(text), "text": text, "anchor": f"block-{i}",
                          "engine": "generic"})
    for p in posts:
        p["url"] = f"{base_url}#{p['anchor']}"
    return posts


def extract_listings(html: str, base_url: str) -> list[dict]:
    """Market pages: repeated product cards that carry a price."""
    soup = soup_of(html)
    out = []
    for i, el in enumerate(repeated_blocks(soup, min_len=15)):
        text = clean(el.get_text(" "))
        price = _PRICE_RE.search(text)
        if not price:
            continue
        link = el.find("a", href=True)
        title = first_text(el, ["h1", "h2", "h3", "h4", ".title", ".name", "a"]) or text[:80]
        vendor = first_text(el, [".vendor", ".seller", "[class*=vendor]", "[class*=seller]"])
        out.append({
            "title": title[:300], "price": price.group(0), "vendor": vendor or None, "text": text,
            "url": urljoin(base_url, link["href"]) if link else f"{base_url}#listing-{i}",
        })
    return out
