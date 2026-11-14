"""Language detection and optional offline translation (Argos Translate)."""

from __future__ import annotations

import logging
from functools import lru_cache

log = logging.getLogger(__name__)


def detect_language(text: str) -> str | None:
    sample = (text or "").strip()[:2000]
    if len(sample) < 20:
        return None
    try:
        from langdetect import DetectorFactory, detect

        DetectorFactory.seed = 0  # deterministic results
        return detect(sample)
    except Exception:
        return None


@lru_cache(maxsize=16)
def _argos_translation(src: str, dst: str):  # pragma: no cover - optional
    import argostranslate.translate as tr

    langs = {lang.code: lang for lang in tr.get_installed_languages()}
    if src not in langs or dst not in langs:
        return None
    return langs[src].get_translation(langs[dst])


def translate_to_english(text: str, lang: str | None) -> str | None:
    """Translate to English if an offline model is installed. Never sends text to a third party."""
    if not lang or lang == "en":
        return None
    try:
        t = _argos_translation(lang, "en")
        return t.translate(text[:20_000]) if t else None
    except Exception as exc:  # pragma: no cover
        log.debug("translation unavailable: %s", exc)
        return None
