"""Named-entity recognition: organizations, people, locations.

Uses spaCy (``en_core_web_sm``) when installed; otherwise a lightweight rule-based fallback that
catches company names with legal suffixes and country names - enough to drive victim detection.
"""

from __future__ import annotations

import logging
import re
from functools import lru_cache

log = logging.getLogger(__name__)

COUNTRIES = [
    "United States", "USA", "United Kingdom", "UK", "Germany", "France", "Italy", "Spain", "Canada", "Brazil",
    "Mexico", "India", "China", "Japan", "Australia", "Russia", "Ukraine", "Netherlands", "Belgium", "Sweden",
    "Norway", "Poland", "Switzerland", "Austria", "Israel", "Turkey", "South Korea", "Singapore", "Indonesia",
    "Argentina", "Chile", "Colombia", "South Africa", "Nigeria", "Egypt", "Saudi Arabia", "UAE", "Iran",
    "Vietnam", "Thailand", "Malaysia", "Philippines", "Portugal", "Greece", "Ireland", "Denmark", "Finland",
    "Czech Republic", "Romania", "Hungary", "New Zealand", "Taiwan", "Pakistan", "Bangladesh", "Peru",
]
_COUNTRY_RE = re.compile(r"\b(" + "|".join(re.escape(c) for c in sorted(COUNTRIES, key=len, reverse=True)) + r")\b")
_ORG_RE = re.compile(
    r"\b((?:[A-Z][A-Za-z0-9&\-]+\s){0,4}[A-Z][A-Za-z0-9&\-]+\s"
    r"(?:Inc|Corp|Corporation|Ltd|LLC|GmbH|S\.A|SA|AG|PLC|Group|Bank|Holdings|Technologies|Systems|Hospital|"
    r"University|Insurance|Logistics|Industries|Solutions|Partners|Pharma|Energy)\b\.?)"
)


@lru_cache(maxsize=1)
def _spacy():  # pragma: no cover - optional
    import spacy

    return spacy.load("en_core_web_sm")


def _regex_entities(text: str) -> list[dict]:
    ents: dict[tuple[str, str], dict] = {}
    for m in _ORG_RE.finditer(text):
        name = m.group(1).strip().rstrip(".")
        ents[("ORG", name)] = {"label": "ORG", "text": name}
    for m in _COUNTRY_RE.finditer(text):
        ents[("GPE", m.group(1))] = {"label": "GPE", "text": m.group(1)}
    return list(ents.values())


def extract_entities(text: str, engine: str = "auto") -> list[dict]:
    if engine in ("auto", "spacy"):
        try:
            nlp = _spacy()
            doc = nlp(text[:100_000])
            seen: dict[tuple[str, str], dict] = {}
            for e in doc.ents:
                if e.label_ in {"ORG", "PERSON", "GPE", "NORP", "PRODUCT", "MONEY"}:
                    seen[(e.label_, e.text)] = {"label": e.label_, "text": e.text.strip()}
            return list(seen.values())
        except Exception as exc:
            if engine == "spacy":
                log.warning("spaCy unavailable (%s); using regex NER", exc)
    return _regex_entities(text)
