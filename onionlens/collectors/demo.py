"""Synthetic demo dataset.

Generates a realistic-looking but entirely fictional corpus - forum posts, market listings, pastes,
Telegram messages and leak-site victims - so the platform can be explored without Tor. All
organizations use the reserved ``.example`` TLD, all credentials and cards are fake, and every source
name is tagged ``[demo]``.
"""

from __future__ import annotations

import hashlib
import random
import string
from collections.abc import Iterator
from datetime import datetime, timedelta

from ..models import utcnow
from ..processing.ioc import B58_ALPHABET
from .base import Collector, Event, Health, RawItem

SOURCES = [
    ("nightfall-forum [demo]", "tor"),
    ("obsidian-market [demo]", "tor"),
    ("breachboard [demo]", "tor"),
    ("exploit-den [demo]", "tor"),
    ("paste.void [demo]", "clearnet"),
    ("telegram:combo_cloud [demo]", "telegram"),
    ("telegram:access_hub [demo]", "telegram"),
]

GROUPS = ["Hydra9", "BlackVeil", "NullSector", "Cobalt Moth", "IronLynx", "Vortex", "Silent Tide", "RedLedger",
          "Kraken0", "Ashfall", "MirrorMask", "Phantom Grid"]
GROUP_WEIGHTS = [18, 15, 12, 10, 9, 8, 7, 6, 5, 4, 3, 3]

SECTORS = ["Manufacturing", "Professional Services", "Technology", "Healthcare", "Retail & E-Commerce",
           "Financial Services", "Education", "Transportation", "Government & Defense", "Energy & Utilities",
           "Hospitality", "Agriculture and Food Production"]
SECTOR_WEIGHTS = [20, 18, 13, 10, 8, 7, 6, 5, 5, 4, 2, 2]

COUNTRIES = ["US", "GB", "DE", "CA", "IT", "FR", "BR", "IN", "AU", "ES", "JP", "MX", "CH", "NL", "SG", "AE",
             "TR", "IL", "SE", "KR", "ZA", "PL", "AR", "ID"]
COUNTRY_WEIGHTS = [40, 6, 6, 5, 4, 4, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1]

ORG_A = ["Northwind", "Bluepeak", "Granite", "Silverline", "Oakridge", "Helix", "Meridian", "Crescent", "Summit",
         "Pioneer", "Atlas", "Harbor", "Redwood", "Lumen", "Vertex", "Keystone", "Ironclad", "Sterling", "Evergreen",
         "Cascade", "Falcon", "Orion", "Quantum", "Sapphire", "Beacon", "Trident", "Aurora", "Nimbus", "Cobalt"]
ORG_B = ["Logistics", "Dental Group", "Manufacturing", "Health Systems", "Partners", "Industries", "Bank",
         "Insurance", "Technologies", "Foods", "Energy", "Law Group", "University", "Hospital", "Retail",
         "Engineering", "Pharma", "Holdings", "Systems", "Motors"]

WATCH_ORG = "Acme Industries"
WATCH_DOMAIN = "acme-industries.example"

FIRST = ["john", "maria", "li", "ahmed", "olga", "james", "sofia", "raj", "emma", "lucas", "chen", "anna", "omar",
         "ivan", "sara", "david", "nina", "paul", "yuki", "carlos"]
LAST = ["smith", "garcia", "wang", "khan", "petrova", "brown", "rossi", "patel", "muller", "silva", "lee", "novak"]


def _b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58_ALPHABET[r] + out
    pad = len(b) - len(b.lstrip(b"\x00"))
    return "1" * pad + out


def fake_btc(rng: random.Random) -> str:
    payload = bytes([0]) + rng.randbytes(20)
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return _b58encode(payload + chk)


def fake_xmr(rng: random.Random) -> str:
    return "4" + rng.choice("0123456789AB") + "".join(rng.choice(B58_ALPHABET) for _ in range(93))


def fake_onion(rng: random.Random) -> str:
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(56)) + ".onion"


def fake_pgp(rng: random.Random) -> str:
    h = "".join(rng.choice("0123456789ABCDEF") for _ in range(40))
    return " ".join(h[i : i + 4] for i in range(0, 40, 4))


def fake_tox(rng: random.Random) -> str:
    return "".join(rng.choice("0123456789ABCDEF") for _ in range(76))


def fake_card(rng: random.Random, bin_: str) -> str:
    digits = [int(c) for c in bin_] + [rng.randint(0, 9) for _ in range(15 - len(bin_))]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return "".join(map(str, digits)) + str((10 - total % 10) % 10)


def fake_password(rng: random.Random) -> str:
    base = rng.choice(["Summer", "Welcome", "Passw0rd", "Qwerty", "Dragon", "Monkey", "Spring", "Company"])
    return base + str(rng.randint(1, 2026)) + rng.choice(["!", "#", "", "$", "@"])


class Persona:
    def __init__(self, rng: random.Random, handle: str, specialty: str):
        self.handle = handle
        self.alias = handle.rstrip("0123456789") + rng.choice(["_x", "77", "_pro", "0x", "_ru", "_shop"])
        self.specialty = specialty
        self.pgp = fake_pgp(rng)
        self.btc = fake_btc(rng)
        self.xmr = fake_xmr(rng)
        self.jabber = f"{handle.lower()}@{rng.choice(['exploit.im', 'jabber.calyxinstitute.org', 'xmpp.jp'])}"
        self.tox = fake_tox(rng)
        self.telegram = handle.lower() + rng.choice(["_bot", "_shop", "_official", "_support"])
        self.sites = rng.sample([s for s, k in SOURCES if k != "telegram"], k=rng.randint(1, 3))


PERSONA_SPECS = [
    ("ShadowBroker88", "credential_leak"), ("Kr0nos", "access_broker"), ("v0idwalker", "malware"),
    ("NetSpecter", "exploit"), ("CarderKing", "fraud"), ("DumpMaster", "credential_leak"),
    ("Gh0stRAT_dev", "malware"), ("Initial_Ace", "access_broker"), ("ZeroCool_x", "exploit"),
    ("BinLord", "fraud"), ("StealerOps", "credential_leak"), ("DDoSaaS", "hacking_services"),
    ("Pharmakon", "drugs"), ("LockSmith", "ransomware"), ("Ph1shKit", "fraud"),
]


class DemoCollector(Collector):
    name = "demo"

    def __init__(self, seed: int = 1337, documents: int = 420, victims: int = 260, days: int = 90):
        self.rng = random.Random(seed)
        self.n_docs = documents
        self.n_victims = victims
        self.days = days
        self.now = utcnow()
        self.personas = [Persona(self.rng, h, s) for h, s in PERSONA_SPECS]
        self.site_onion = {s: fake_onion(self.rng) for s, k in SOURCES if k == "tor"}

    # --- helpers -----------------------------------------------------------------------------

    def _when(self, days: int | None = None) -> datetime:
        days = days or self.days
        # skew toward recent activity, with a mid-period spike
        r = self.rng.random()
        offset = days * (r ** 1.6) if self.rng.random() > 0.15 else self.rng.uniform(38, 46)
        return self.now - timedelta(days=offset, hours=self.rng.uniform(0, 23), minutes=self.rng.uniform(0, 59))

    def _org(self) -> tuple[str, str]:
        a, b = self.rng.choice(ORG_A), self.rng.choice(ORG_B)
        suffix = self.rng.choice(["Inc", "LLC", "Ltd", "GmbH", "Group", "Corp"])
        domain = f"{a.lower()}-{b.split()[0].lower()}.example"
        return f"{a} {b} {suffix}", domain

    def _emails(self, domain: str, n: int, with_pw: bool) -> str:
        lines = []
        for _ in range(n):
            local = f"{self.rng.choice(FIRST)}.{self.rng.choice(LAST)}{self.rng.choice(['', str(self.rng.randint(1, 99))])}"
            lines.append(f"{local}@{domain}:{fake_password(self.rng)}" if with_pw else f"{local}@{domain}")
        return "\n".join(lines)

    def _sig(self, p: Persona, rich: bool = True) -> str:
        parts = [f"Contact: jabber: {p.jabber}"]
        if rich:
            parts.append(f"PGP fingerprint: {p.pgp}")
        if self.rng.random() < 0.6:
            parts.append(f"Tox: {p.tox}")
        if self.rng.random() < 0.5:
            parts.append(f"Telegram: @{p.telegram}")
        return "\n".join(parts)

    def _pay(self, p: Persona) -> str:
        return (f"Payment BTC: {p.btc}" if self.rng.random() < 0.65 else f"Payment XMR only: {p.xmr}")

    # --- post templates ----------------------------------------------------------------------

    def _post(self, p: Persona, target_watch: bool) -> tuple[str, str]:
        r = self.rng
        org, domain = (WATCH_ORG + " Inc", WATCH_DOMAIN) if target_watch else self._org()
        country = r.choices(COUNTRIES, COUNTRY_WEIGHTS)[0]
        price = r.choice([150, 300, 500, 800, 1200, 2500, 5000, 12000])
        cve = r.choice(["CVE-2024-3400", "CVE-2023-4966", "CVE-2024-21762", "CVE-2023-34362", "CVE-2024-1709",
                        "CVE-2025-0282", "CVE-2023-22515", "CVE-2024-23897"])
        sha = hashlib.sha256(r.randbytes(16)).hexdigest()
        cat = p.specialty if r.random() < 0.85 else r.choice([s for _, s in PERSONA_SPECS])

        if cat == "credential_leak":
            n = r.randint(4, 9)
            title = f"[LEAK] {org} database dump - {r.randint(20, 900)}k records"
            body = (f"Posted by {p.handle}\nFresh leaked database from {org} ({domain}). Full SQL dump incl. "
                    f"emails, password hashes and plaintext credentials. Combolist sample below:\n"
                    f"{self._emails(domain, n, True)}\n\nFull dump {price}$ via escrow. {self._pay(p)}\n{self._sig(p)}")
        elif cat == "access_broker":
            title = f"Selling initial access - {r.choice(SECTORS)} company, {country}"
            body = (f"Seller: {p.handle}\nSelling corporate network access to {org}. Revenue ${r.randint(20, 900)}M, "
                    f"{r.randint(200, 9000)} employees. Access type: {r.choice(['RDP', 'Citrix', 'Fortinet VPN access', 'ESXi root'])}"
                    f" with domain admin rights. Entry via {cve}. Price {price}$. {self._pay(p)}\n{self._sig(p)}")
        elif cat == "malware":
            tool = r.choice(["stealer", "loader", "crypter", "RAT", "botnet panel", "keylogger"])
            title = f"{p.handle} {tool} v{r.randint(2, 6)}.{r.randint(0, 9)} - FUD, AV bypass"
            body = (f"Author: {p.handle}\nNew {tool} build with EDR bypass and obfuscated payload. Builder + C2 panel "
                    f"included. Sample SHA256: {sha}\nSubscription {price}$/month. {self._pay(p)}\n{self._sig(p)}")
        elif cat == "exploit":
            title = f"0day / {cve} exploit - unauthenticated RCE"
            body = (f"Posted by {p.handle}\nWorking PoC exploit for {cve}, unauthenticated RCE, privilege escalation "
                    f"chain included. Tested on latest builds. Hash of archive: {sha}\nPrice {price}$. {self._pay(p)}\n"
                    f"{self._sig(p)}")
        elif cat == "fraud":
            bin_ = "457173" if target_watch else r.choice(["542418", "401288", "520082", "455951", "531260"])
            cards = "\n".join(f"{fake_card(r, bin_)}|{r.randint(1, 12):02d}/{r.randint(27, 31)}|{r.randint(100, 999)}"
                              for _ in range(r.randint(2, 5)))
            title = f"Fresh CVV dumps {country} - high balance bins"
            body = (f"Vendor: {p.handle}\nCarding shop update. CVV and fullz, cashout guides, bank logs. Sample:\n{cards}\n"
                    f"Bins {bin_}. {self._pay(p)}\n{self._sig(p, rich=False)}")
        elif cat == "hacking_services":
            title = "DDoS for hire / stresser - L4 + L7"
            body = (f"Seller: {p.handle}\nBooter and stresser service, bulletproof hosting, account takeover on request. "
                    f"Targets like {domain} taken down in minutes. {self._pay(p)}\n{self._sig(p, rich=False)}")
        elif cat == "drugs":
            title = f"Vendor shop - stealth shipping {country}"
            body = (f"Vendor: {p.handle}\nPills, MDMA, cannabis. Grams and bulk. Stealth shipping worldwide. "
                    f"{self._pay(p)}\nPGP fingerprint: {p.pgp}")
        else:  # ransomware affiliate recruitment
            title = "RaaS affiliate program - 80/20 split"
            body = (f"Posted by {p.handle}\nRansomware affiliate program recruiting pentesters. Locker for Windows/ESXi, "
                    f"decryptor, leak site and negotiation panel provided. Double extortion. {self._pay(p)}\n{self._sig(p)}")
        return title, body

    def _russian_post(self, p: Persona) -> tuple[str, str]:
        return (
            "Продам доступ к корпоративной сети",
            f"Автор: {p.handle}\nПродаю доступ RDP к сети компании, права доменного администратора. "
            f"Оплата только через гаранта. {self._pay(p)}\nКонтакт jabber: {p.jabber}",
        )

    # --- generation --------------------------------------------------------------------------

    def collect(self) -> Iterator[Event]:
        r = self.rng
        # uptime history (one check per source per ~3 days)
        for name, kind in SOURCES:
            for d in range(self.days, 0, -3):
                ok = r.random() > (0.25 if kind == "tor" else 0.05)
                yield Health(name, kind, self._source_url(name), ok=ok, status_code=200 if ok else None,
                             latency_ms=r.uniform(1800, 9000) if kind == "tor" else r.uniform(80, 600),
                             error=None if ok else "timeout", checked_at=self.now - timedelta(days=d))

        watch_posts = set(r.sample(range(self.n_docs), k=9))
        for i in range(self.n_docs):
            p = r.choice(self.personas)
            if i % 37 == 0:
                title, body = self._russian_post(p)
            else:
                title, body = self._post(p, target_watch=i in watch_posts)
            telegram = r.random() < 0.18
            if telegram:
                site, kind = r.choice([(s, k) for s, k in SOURCES if k == "telegram"])
            else:
                site = r.choice(p.sites)
                kind = dict(SOURCES)[site]
            # personas use their alias on a second site -> linking must resolve it
            if site != p.sites[0] and not telegram:
                body = body.replace(p.handle, p.alias)
            when = self._when()
            url = self._doc_url(site, i)
            html = f"<html><head><title>{title}</title></head><body><h1>{title}</h1><div class='post'>" + \
                   body.replace("\n", "<br>") + "</div></body></html>"
            yield RawItem(site, kind, url, html, is_html=True, source_url=self._source_url(site), title=title,
                          published_at=when, meta={"collected_at": when + timedelta(hours=r.uniform(0.5, 30))})

        # leak-site victims
        for j in range(self.n_victims):
            group = r.choices(GROUPS, GROUP_WEIGHTS)[0]
            if j == 3:
                org, domain, sector, country = WATCH_ORG, WATCH_DOMAIN, "Manufacturing", "US"
            else:
                org, domain = self._org()
                sector = r.choices(SECTORS, SECTOR_WEIGHTS)[0]
                country = r.choices(COUNTRIES, COUNTRY_WEIGHTS)[0]
            when = self._when(120)
            size = r.choice(["120 GB", "450 GB", "1.2 TB", "38 GB", "2.7 TB", "900 GB"])
            text = (f"Ransomware group {group} listed victim {org} on its leak site.\nCountry: {country}. Sector: "
                    f"{sector}. Website: {domain}.\n{size} of exfiltrated data including finance, HR and customer "
                    f"records. Countdown: data will be published in {r.randint(2, 14)} days unless the ransom is paid.")
            yield RawItem(
                f"{group} leak site [demo]", "tor", f"http://{fake_onion(r)}/post/{j}", text, is_html=False,
                title=f"[{group}] {org}", author=group, published_at=when,
                victim={"name": org, "group_name": group, "country": country, "sector": sector, "domain": domain,
                        "description": f"{size} exfiltrated", "discovered_at": when},
                meta={"collected_at": when + timedelta(hours=r.uniform(0.2, 12))},
            )

    def _source_url(self, site: str) -> str:
        if site in self.site_onion:
            return f"http://{self.site_onion[site]}/"
        if site.startswith("telegram:"):
            return "https://t.me/" + site.split(":")[1].split()[0]
        return "https://" + site.split()[0] + ".example/"

    def _doc_url(self, site: str, i: int) -> str:
        base = self._source_url(site).rstrip("/")
        slug = "".join(self.rng.choice(string.ascii_lowercase) for _ in range(6))
        return f"{base}/thread/{i}-{slug}" if not site.startswith("telegram") else f"{base}/{1000 + i}"
