"""Content classification.

Two engines:

* ``keyword`` (default) - weighted lexicon scoring. Fast, offline, explainable: every score can be
  traced back to the terms that produced it.
* ``zeroshot`` - HuggingFace zero-shot NLI model (``pip install onionlens[ml]``). Better recall on
  unusual phrasing, much slower. Falls back to ``keyword`` if transformers is unavailable.
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from functools import lru_cache

log = logging.getLogger(__name__)

CATEGORIES: dict[str, dict[str, float]] = {
    "credential_leak": {
        "combolist": 3, "combo list": 3, "database dump": 3, "db dump": 3, "leaked database": 3,
        "credentials": 2, "logins": 2.5, "email:pass": 3, "user:pass": 3, "stealer logs": 3,
        "infostealer": 2.5, "redline": 2, "lumma": 2, "raccoon": 1.5, "cookies": 1, "breach": 2, "leak": 1.5,
        "leaked": 1.5, "accounts": 1, "hashes": 1, "plaintext": 1.5, "fullz": 2, "records": 1, "sql dump": 3,
        "[redacted": 2, "db leak": 3, "login": 1.5, "passwords": 2, "password": 1.5, "creds": 2, "ssn": 2,
        "office365": 2, "o365": 2, "unsalted": 2.5, "md5": 1.5, "bcrypt": 2, "email password": 3,
        "account dump": 3,
    },
    "ransomware": {
        "ransomware": 3, "encrypted": 1.5, "decryptor": 3, "leak site": 2.5, "data will be published": 3,
        "countdown": 2, "negotiation": 2, "ransom": 2.5, "exfiltrated": 2, "victim": 1.5, "affiliate": 2,
        "raas": 3, "double extortion": 3, "publish": 1, "deadline": 1.5, "lockbit": 2, "files of": 1,
        "encrypt": 2, "encryption": 1.5, "locker": 2.5, "partner program": 2, "affiliates": 2,
        "leak blog": 3, "publication": 2, "pay to avoid": 3, "data released": 2.5, "data will be leaked": 3,
        "refused to pay": 3, "ignore us": 2.5, "esxi": 1, "breached": 1,
    },
    "malware": {
        "malware": 2.5, "rat": 1.5, "remote access trojan": 3, "botnet": 3, "loader": 2, "crypter": 3,
        "fud": 2.5, "keylogger": 3, "stealer": 2, "c2": 2, "payload": 2, "dropper": 3, "rootkit": 3,
        "builder": 1.5, "obfuscat": 1.5, "av bypass": 3, "edr bypass": 3, "source code": 1, "panel": 1,
        "trojan": 3, "hvnc": 3, "vnc module": 2.5, "edr": 1.5, "injects": 2.5, "sms interception": 2.5,
        "process hollowing": 3, "sandbox evasion": 3, "clipper": 3, "infostealer": 2,
    },
    "exploit": {
        "exploit": 3, "0day": 3, "zero-day": 3, "zero day": 3, "cve-": 2.5, "rce": 2.5, "poc": 2,
        "privilege escalation": 2.5, "lpe": 2, "vulnerability": 2, "sqli": 2, "unauthenticated": 1.5,
        "sql injection": 3, "auth bypass": 3, "remote code execution": 3, "deserialization": 3, "n-day": 3,
        "unpatched": 2, "sandbox escape": 3, "kernel": 1.5, "chain": 1,
    },
    "access_broker": {
        "initial access": 3, "rdp": 2.5, "vpn access": 3, "citrix": 2, "domain admin": 3, "access to": 1.5,
        "shell access": 2.5, "network access": 3, "revenue": 1.5, "employees": 1, "webshell": 2.5,
        "fortinet": 1.5, "esxi": 1.5, "corporate network": 2.5, "shell on": 2.5, "pivot": 2.5,
        "auction": 1.5, "console access": 3, "ad creds": 2.5, "ssh": 1.5, "root keys": 2.5,
    },
    "fraud": {
        "carding": 3, "cvv": 3, "dumps": 1.5, "bank logs": 3, "cashout": 3, "cash out": 3, "money mule": 3,
        "paypal": 1.5, "fake id": 2.5, "counterfeit": 2.5, "scam page": 3, "phishing kit": 3, "otp bot": 3,
        "sim swap": 3, "bins": 2, "drop": 1, "refund": 1.5, "gift card": 2, "mules": 2.5, "fake ids": 3,
        "drivers license": 2.5, "scannable": 2.5, "transfers": 1, "gift card method": 3, "method": 1,
    },
    "drugs": {
        "cocaine": 3, "heroin": 3, "mdma": 3, "lsd": 3, "cannabis": 2.5, "weed": 2, "meth": 3, "fentanyl": 3,
        "pills": 1.5, "grams": 1.5, "stealth shipping": 2.5, "vendor shop": 1.5, "opioid": 2.5,
        "oxycodone": 3, "xanax": 3, "psilocybin": 3, "mushrooms": 2.5, "shrooms": 3, "2c-b": 3,
        "ketamine": 3, "strains": 2, "stealth": 1.5, "prescription": 2, "pharmacy": 1.5, "vendor": 1,
        "speed": 1, "tabs": 1.5,
    },
    "hacking_services": {
        "hacker for hire": 3, "hire a hacker": 3, "ddos": 3, "ddos for hire": 3, "booter": 3, "stresser": 3,
        "account takeover": 2.5, "social media hack": 3, "doxing": 2.5, "dox": 2, "pentest": 1, "spam": 1.5,
        "bulletproof hosting": 3, "money laundering": 2, "mixer": 2, "tumbler": 2, "spam service": 3,
        "hack any": 3, "email account": 1.5, "inbox": 1.5, "dox service": 3, "takeover": 1.5,
        "account recovery": 2.5, "laundering": 2.5,
    },
}

LABELS = {
    "credential_leak": "Credential leak",
    "ransomware": "Ransomware / extortion",
    "malware": "Malware",
    "exploit": "Exploits & vulnerabilities",
    "access_broker": "Initial access broker",
    "fraud": "Fraud & carding",
    "drugs": "Drugs",
    "hacking_services": "Hacking services",
    "other": "Other",
}

# Base severity per category (0-1), used by the threat scorer.
SEVERITY = {
    "ransomware": 0.9, "access_broker": 0.9, "credential_leak": 0.8, "exploit": 0.8, "malware": 0.7,
    "fraud": 0.6, "hacking_services": 0.5, "drugs": 0.2, "other": 0.1,
}

_COMPILED = {
    cat: [
        (term, re.compile(r"(?<![a-z0-9])" + re.escape(term) + (r"(?:s|es)?(?![a-z0-9])" if term[-1].isalnum() else "")), w)
        for term, w in terms.items()
    ]
    for cat, terms in CATEGORIES.items()
}


MIN_SCORE = 2.0  # one strong term is enough to commit to a category
_NEWS_RE = re.compile(
    r"\b(researchers?|according to|arrested|police|law enforcement operation|published a report|report on|"
    r"news:|press release|our blog|how we patched|interesting read)\b"
)


@dataclass
class Classification:
    category: str
    confidence: float
    scores: dict[str, float] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)


def classify_keyword(text: str) -> Classification:
    low = text.lower()
    raw: dict[str, float] = {}
    evidence: dict[str, list[str]] = {}
    for cat, patterns in _COMPILED.items():
        total = 0.0
        for term, rx, w in patterns:
            n = len(rx.findall(low))
            if n:
                total += w * (1 + math.log(n))
                evidence.setdefault(cat, []).append(term)
        raw[cat] = total
    if _NEWS_RE.search(low):  # reporting *about* threats is not itself a threat
        raw = {k: v * 0.35 for k, v in raw.items()}
    best = max(raw, key=raw.get)
    if raw[best] < MIN_SCORE:
        return Classification("other", 0.0, {k: 0.0 for k in raw}, [])
    # softmax over raw scores -> confidence in the winning category
    exps = {k: math.exp(v / 2) for k, v in raw.items()}
    z = sum(exps.values())
    scores = {k: round(v / z, 4) for k, v in exps.items()}
    return Classification(best, scores[best], scores, evidence.get(best, [])[:8])


@lru_cache(maxsize=1)
def _zeroshot_pipeline():  # pragma: no cover - heavy optional dependency
    from transformers import pipeline

    return pipeline("zero-shot-classification", model="facebook/bart-large-mnli")


def classify_zeroshot(text: str) -> Classification:  # pragma: no cover - heavy optional dependency
    clf = _zeroshot_pipeline()
    labels = [k for k in LABELS if k != "other"]
    out = clf(text[:2000], candidate_labels=[LABELS[k] for k in labels], multi_label=False)
    by_label = {v: k for k, v in LABELS.items()}
    scores = {by_label[l]: round(s, 4) for l, s in zip(out["labels"], out["scores"])}
    best = max(scores, key=scores.get)
    if scores[best] < 0.3:
        return Classification("other", scores[best], scores)
    return Classification(best, scores[best], scores)


def classify(text: str, engine: str = "keyword") -> Classification:
    if engine == "zeroshot":
        try:
            return classify_zeroshot(text)
        except Exception as exc:  # pragma: no cover
            log.warning("zero-shot classifier unavailable (%s); falling back to keyword engine", exc)
    return classify_keyword(text)
