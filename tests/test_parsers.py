"""Leak-site, forum and market parsers - fixtures mirror real layouts with fictional data."""

from datetime import datetime

from onionlens.collectors.forum_parsers import detect_engine, extract_listings, extract_posts
from onionlens.collectors.htmlblocks import parse_date
from onionlens.collectors.leak_parsers import country_from_domain, parse_leak_page
from onionlens.pipeline import victim_key

QILIN_LIKE = """<html><body>
<div data-key="1"><div class="item_box"><a class="item_box-title" href="/b?u=1">Northwind Logistics</a>
  <p class="item_box-info">Transportation</p><a class="item_box-info__link" href="http://www.northwind.example.de">Company url</a>
  <div>Nov 12, 2026</div></div></div>
<div data-key="2"><div class="item_box"><a class="item_box-title" href="/b?u=2">Bluepeak Dental</a>
  <p class="item_box-info">Healthcare</p><a class="item_box-info__link" href="https://bluepeak.example.com">Company url</a>
  <div>Nov 10, 2026</div></div></div>
</body></html>""" + " " * 200

RANSOMEXX_LIKE = """<html><body><ul>
<li><h4><b><a href="/2026/06/20/x/">Granite Hotels (granitehotels.example.vn)</a></b></h4>
<i><p>We have released the complete database.</p></i><b>Date: </b>Sat 20 June 2026<br/></li>
<li><h4><b><a href="/2026/04/17/y/">Helix Auction</a></b></h4><p>951MB leaked.</p><b>Date: </b>Fri 17 April 2026
<span><a href="/tag/japan.html">#japan </a></span></li>
<li><a href="/about">About us</a></li>
</ul></body></html>"""

GENERIC_CARDS = """<html><body><div class="grid">
<div class="victim"><h3>Oakridge Partners</h3><p>Website: oakridge.example.co.uk</p><p>120 GB exfiltrated · 2026-10-02</p></div>
<div class="victim"><h3>Redacted</h3><p>Countdown 4 days</p></div>
<div class="victim"><h3>Summit Pharma</h3><p>Website: summitpharma.example.com</p><p>Published 2026-09-30 · 1.2 TB</p></div>
<div class="victim"><h3>What should we do?</h3><p>Do not contact law enforcement.</p></div>
</div></body></html>"""


def test_qilin_layout():
    vs = parse_leak_page(QILIN_LIKE, "qilin")
    assert [v["name"] for v in vs] == ["Northwind Logistics", "Bluepeak Dental"]
    assert vs[0]["domain"] == "northwind.example.de" and vs[0]["country"] == "DE"
    assert vs[0]["sector"] == "Transportation" and vs[0]["discovered_at"] == datetime(2026, 11, 12)


def test_ransomexx_layout_domain_in_name_and_tag_country():
    vs = parse_leak_page(RANSOMEXX_LIKE, "ransomexx")
    assert [v["name"] for v in vs] == ["Granite Hotels", "Helix Auction"]
    assert vs[0]["domain"] == "granitehotels.example.vn" and vs[0]["country"] == "VN"
    assert vs[1]["country"] == "JP" and vs[1]["discovered_at"] == datetime(2026, 4, 17)


def test_generic_fallback_skips_redacted_and_faq():
    vs = parse_leak_page(GENERIC_CARDS, "some-new-group")
    names = [v["name"] for v in vs]
    assert names == ["Oakridge Partners", "Summit Pharma"]
    assert vs[0]["country"] == "GB" and vs[0]["discovered_at"] == datetime(2026, 10, 2)


def test_masked_names_rejected():
    html = GENERIC_CARDS.replace("Summit Pharma", "s****t.com")
    assert "s****t.com" not in [v["name"] for v in parse_leak_page(html, "x")]


def test_helpers():
    assert parse_date("posted 2026-11-14T08:30:00Z") == datetime(2026, 11, 14, 8, 30)
    assert parse_date("March 3rd, 2025") == datetime(2025, 3, 3)
    assert parse_date("14.11.2026") == datetime(2026, 11, 14)
    assert country_from_domain("shop.example.com.br") == "BR"
    assert country_from_domain("startup.io") is None  # .io is used generically
    assert victim_key("ACME, Inc.") == victim_key("Acme") == victim_key("ACME Group LLC")


PHPBB_LIKE = """<html><head><meta name="generator" content="phpBB"></head><body>
<div id="p101" class="post"><div class="postbody"><p class="author">by <a class="username" href="#">v0idwalker</a>
<time datetime="2026-11-01T10:00:00+00:00">Sun Nov 01</time></p>
<div class="content">Selling fresh combolist, 2M lines. Contact jabber: v0id@exploit.im</div></div></div>
<div id="p102" class="post"><div class="postbody"><p class="author">by <a class="username" href="#">buyer42</a>
<time datetime="2026-11-01T11:00:00+00:00">Sun Nov 01</time></p><div class="content">vouch, legit seller</div></div></div>
</body></html>"""

MARKET_LIKE = """<html><body><div class="listings">
<div class="item"><h4>Fresh CVV pack (US)</h4><span class="vendor">BinLord</span><span>Price: $25</span></div>
<div class="item"><h4>RDP access - logistics company</h4><span class="vendor">Kr0nos</span><span>0.02 BTC</span></div>
<div class="item"><h4>Guide: OPSEC basics</h4><span class="vendor">mod</span><span>free download</span></div>
</div></body></html>"""


def test_forum_post_splitting():
    assert detect_engine(PHPBB_LIKE) == "phpbb"
    posts = extract_posts(PHPBB_LIKE, "http://forum.onion/t/1")
    assert [p["author"] for p in posts] == ["v0idwalker", "buyer42"]
    assert posts[0]["published_at"] == datetime(2026, 11, 1, 10, 0)
    assert posts[0]["url"] == "http://forum.onion/t/1#p101" and "combolist" in posts[0]["text"]


def test_market_listings():
    items = extract_listings(MARKET_LIKE, "http://market.onion/c/1")
    assert [i["title"] for i in items] == ["Fresh CVV pack (US)", "RDP access - logistics company"]
    assert items[0]["vendor"] == "BinLord" and items[1]["price"].endswith("BTC")


def test_name_cleanup_and_junk_rejection():
    from onionlens.collectors.leak_parsers import _valid_name, clean_name

    assert clean_name("SOLENIS - 1.65tb") == ("SOLENIS", None)
    assert clean_name("ARTHREX - 700+ GB") == ("ARTHREX", None)
    assert clean_name("Qualiflex Solutions | qualiflex.solutions") == ("Qualiflex Solutions", "qualiflex.solutions")
    assert clean_name("Data from Al Tadawi Specialty Hospital, Dubai")[0] == "Al Tadawi Specialty Hospital, Dubai"
    for junk in ("PAID", "Files", "Fresh Leaks", "contact@onionmail.org", "ki Hidden name o.com", "t**a.com"):
        assert not _valid_name(junk, strict=True), junk
    assert not _valid_name("NetworkBlackBox Application Part3 Published.", strict=True)
    assert _valid_name("Valentin Hotel", strict=True)
