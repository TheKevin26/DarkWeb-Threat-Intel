"""Safety layer: hard content blocklist and PII redaction.

Everything that enters the pipeline passes through here *before* it is stored.

* ``is_prohibited`` drops child-sexual-abuse material indicators outright. Matching items are
  never written to disk or the database; only a hashed URL and a reason are logged for audit.
* ``redact`` masks secrets (passwords, card numbers, SSNs) so the platform stores evidence that a
  credential leaked without becoming a credential dump itself.
"""

from __future__ import annotations

import hashlib
import re

# Deliberately conservative: false positives only cost us a dropped page.
_PROHIBITED_PATTERNS = [
    r"\bchild\s*porn",
    r"\bc\.?p\.?\s*(links|videos|pics|archive)\b",
    r"\bpthc\b",
    r"\bjailbait\b",
    r"\bpre-?teen\s*(nude|sex|porn)",
    r"\blolita\s*(porn|nude|sex|video)",
    r"\bunderage\s*(sex|porn|nude)",
    r"\bcsam\b",
]
_PROHIBITED_RE = re.compile("|".join(_PROHIBITED_PATTERNS), re.IGNORECASE)


def is_prohibited(text: str) -> str | None:
    """Return a reason string if the content must be dropped, else ``None``."""
    if _PROHIBITED_RE.search(text or ""):
        return "prohibited:csam-indicator"
    return None


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()


# --- redaction -------------------------------------------------------------------------------

_EMAIL_PASS_RE = re.compile(
    r"(?P<email>[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?P<sep>\s*[:;|]\s*)(?P<pw>[^\s:;|]{3,128})"
)
_LABELLED_PASS_RE = re.compile(r"(?i)(?P<label>\b(?:pass(?:word)?|pwd|pw)\s*[:=]\s*)(?P<pw>\S{3,128})")
_CARD_RE = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def mask_card(raw: str) -> str:
    digits = re.sub(r"\D", "", raw)
    return f"{digits[:6]}{'*' * (len(digits) - 10)}{digits[-4:]}"


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    return f"{local[:1]}***@{domain.lower()}"


def _mask_pw(pw: str) -> str:
    return f"[REDACTED:{len(pw)}]"


def redact(text: str) -> str:
    """Mask passwords, valid card numbers and SSNs. Emails are kept (needed for matching)."""

    text = _EMAIL_PASS_RE.sub(lambda m: f"{m['email']}{m['sep']}{_mask_pw(m['pw'])}", text)
    text = _LABELLED_PASS_RE.sub(lambda m: f"{m['label']}{_mask_pw(m['pw'])}", text)

    def _card(m: re.Match) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            return mask_card(digits)
        return m.group(0)

    text = _CARD_RE.sub(_card, text)
    text = _SSN_RE.sub("***-**-****", text)
    return text
