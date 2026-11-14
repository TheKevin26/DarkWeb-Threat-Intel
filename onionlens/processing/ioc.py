"""Indicator-of-compromise extraction.

Runs on *redacted* text, so secrets never reach the indicator table. Each extractor validates its
matches (checksums, ranges, TLD sanity) to keep false positives down.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass

from ..safety import mask_email

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Indicator types considered "identity-bearing" - used for actor linking.
LINKING_TYPES = {
    "handle", "btc_address", "xmr_address", "eth_address", "pgp_fingerprint", "jabber", "tox_id", "telegram",
}
# Types that represent leaked sensitive data.
SENSITIVE_TYPES = {"credential", "card", "email"}


@dataclass(frozen=True)
class IOC:
    type: str
    value: str  # display value (masked if sensitive)
    raw: str  # normalized raw value - only ever hashed, never stored
    context: str | None = None

    @property
    def value_hash(self) -> str:
        return hashlib.sha256(f"{self.type}:{self.raw}".encode()).hexdigest()


# --- validators ------------------------------------------------------------------------------


def _b58decode(s: str) -> bytes | None:
    num = 0
    for ch in s:
        idx = B58_ALPHABET.find(ch)
        if idx < 0:
            return None
        num = num * 58 + idx
    full = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + full


def valid_btc_base58(addr: str) -> bool:
    raw = _b58decode(addr)
    if raw is None or len(raw) != 25:
        return False
    payload, checksum = raw[:-4], raw[-4:]
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum


_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def valid_bech32(addr: str) -> bool:
    addr = addr.lower()
    hrp, _, data = addr.rpartition("1")
    if hrp != "bc" or len(data) < 6 or any(c not in _BECH32_CHARSET for c in data):
        return False
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + [_BECH32_CHARSET.find(c) for c in data]
    return _bech32_polymod(values) in (1, 0x2BC830A3)  # bech32 / bech32m


_COMMON_TLDS = {
    "com", "net", "org", "io", "ru", "cn", "de", "uk", "fr", "info", "biz", "co", "us", "su", "to", "cc",
    "me", "xyz", "top", "onion", "gov", "edu", "mil", "in", "br", "jp", "it", "nl", "es", "pl", "ua", "kz",
    "ch", "se", "no", "ca", "au", "example", "test", "app", "dev", "ly", "sh", "ws", "pw", "tk", "site",
}
# Internal / non-routable ranges are noise. Documentation ranges (TEST-NET) are kept on purpose so
# they can be used in watchlists and tests.
_NON_ROUTABLE = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
)]
_FILE_EXT = {"php", "html", "htm", "js", "css", "png", "jpg", "jpeg", "gif", "txt", "zip", "rar", "exe", "pdf", "doc"}


# --- patterns --------------------------------------------------------------------------------

RE_ONION = re.compile(r"\b(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion\b", re.IGNORECASE)
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
RE_CREDENTIAL = re.compile(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24})\s*[:;|]\s*\[REDACTED:\d+\]")
RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE)
RE_BTC_B58 = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
RE_BTC_BECH = re.compile(r"\bbc1[ac-hj-np-z02-9]{11,71}\b", re.IGNORECASE)
RE_XMR = re.compile(r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
RE_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
RE_PGP_FPR = re.compile(r"\b(?:[A-F0-9]{4}\s?){10}\b")
RE_PGP_BLOCK = re.compile(r"-----BEGIN PGP PUBLIC KEY BLOCK-----")
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
RE_CARD_MASKED = re.compile(r"\b(\d{6})\*{3,9}(\d{4})\b")
RE_JABBER = re.compile(r"(?i)\b(?:jabber|xmpp|jid)\s*[:\-]?\s*([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24})")
RE_TOX = re.compile(r"\b[A-F0-9]{76}\b")
RE_TELEGRAM = re.compile(r"(?:t\.me/|telegram\s*[:\-]\s*@?)([A-Za-z][A-Za-z0-9_]{4,31})", re.IGNORECASE)
RE_HANDLE = re.compile(
    r"(?i)\b(?:posted\s+by\s+|(?:author|seller|vendor|user(?:name)?|op)\s*:\s*)@?([A-Za-z][A-Za-z0-9_.\-]{2,30})\b"
)
_HANDLE_STOP = {
    "the", "admin", "anonymous", "guest", "email", "jabber", "telegram", "tox", "xmpp", "this", "our", "us",
    "me", "you", "price", "escrow", "pm", "dm", "seller", "vendor", "user", "contact", "date", "here",
}


def extract_iocs(text: str) -> list[IOC]:
    found: dict[str, IOC] = {}

    def add(ioc: IOC) -> None:
        found.setdefault(ioc.value_hash, ioc)

    for m in RE_ONION.finditer(text):
        v = m.group(0).lower()
        add(IOC("onion", v, v))

    jabber_ids = set()
    for m in RE_JABBER.finditer(text):
        v = m.group(1).lower()
        jabber_ids.add(v)
        add(IOC("jabber", v, v))

    cred_emails = set()
    for m in RE_CREDENTIAL.finditer(text):
        email = m.group(1).lower()
        cred_emails.add(email)
        domain = email.split("@", 1)[1]
        add(IOC("credential", mask_email(email), email, context=domain))

    for m in RE_EMAIL.finditer(text):
        email = m.group(0).lower()
        if email in jabber_ids or email in cred_emails:
            continue
        domain = email.split("@", 1)[1]
        add(IOC("email", mask_email(email), email, context=domain))

    for m in RE_IPV4.finditer(text):
        try:
            ip = ipaddress.ip_address(m.group(0))
        except ValueError:
            continue
        if any(ip in net for net in _NON_ROUTABLE) or ip.is_multicast or ip.is_reserved:
            continue
        add(IOC("ipv4", str(ip), str(ip)))

    for m in RE_BTC_B58.finditer(text):
        if valid_btc_base58(m.group(0)):
            add(IOC("btc_address", m.group(0), m.group(0)))
    for m in RE_BTC_BECH.finditer(text):
        if valid_bech32(m.group(0)):
            v = m.group(0).lower()
            add(IOC("btc_address", v, v))
    for m in RE_XMR.finditer(text):
        add(IOC("xmr_address", m.group(0), m.group(0)))
    for m in RE_ETH.finditer(text):
        v = m.group(0).lower()
        add(IOC("eth_address", v, v))

    tox = set()
    for m in RE_TOX.finditer(text):
        tox.add(m.group(0))
        add(IOC("tox_id", m.group(0), m.group(0)))

    pgp = set()
    for m in RE_PGP_FPR.finditer(text):
        fpr = re.sub(r"\s", "", m.group(0)).upper()
        if len(fpr) == 40 and len(set(fpr)) > 4:
            pgp.add(fpr)
            add(IOC("pgp_fingerprint", " ".join(fpr[i : i + 4] for i in range(0, 40, 4)), fpr))

    for rx, kind in ((RE_SHA256, "sha256"), (RE_SHA1, "sha1"), (RE_MD5, "md5")):
        for m in rx.finditer(text):
            v = m.group(0).lower()
            if v.upper() in pgp or any(v.upper() in t for t in tox) or len(set(v)) < 6:
                continue
            add(IOC(kind, v, v))

    for m in RE_CVE.finditer(text):
        v = m.group(0).upper()
        add(IOC("cve", v, v))

    for m in RE_CARD_MASKED.finditer(text):
        add(IOC("card", m.group(0), m.group(0), context=f"BIN {m.group(1)}"))

    for m in RE_TELEGRAM.finditer(text):
        v = m.group(1).lower()
        add(IOC("telegram", "@" + v, v))

    for m in RE_HANDLE.finditer(text):
        v = m.group(1).strip(".-_")
        if v.lower() in _HANDLE_STOP or len(v) < 3 or "@" in v or "." in v:
            continue
        add(IOC("handle", v, v.lower()))

    email_domains = {i.context for i in found.values() if i.type in {"email", "credential"}}
    for m in RE_DOMAIN.finditer(text):
        v = m.group(0).lower().rstrip(".")
        tld = v.rsplit(".", 1)[-1]
        if tld == "onion" or tld in _FILE_EXT or tld not in _COMMON_TLDS:
            continue
        if v in email_domains or RE_IPV4.fullmatch(v):
            continue
        add(IOC("domain", v, v))

    return list(found.values())
