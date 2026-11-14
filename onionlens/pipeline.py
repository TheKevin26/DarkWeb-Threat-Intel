"""Processing pipeline: RawItem -> safety -> text -> dedupe -> NLP/IOC -> watchlist -> score -> storage."""

from __future__ import annotations

import gzip
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from bs4 import BeautifulSoup
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .config import Settings, get_settings, load_yaml
from .collectors.base import Health, RawItem
from .exporters.attack import map_techniques
from .models import (
    Alert,
    Document,
    DroppedItem,
    Indicator,
    PageSnapshot,
    Source,
    SourceCheck,
    Victim,
    VictimSighting,
    WatchlistItem,
    utcnow,
)
from .processing.classifier import classify
from .processing.entities import extract_entities
from .processing.ioc import extract_iocs
from .processing.language import detect_language, translate_to_english
from .processing.scoring import threat_score
from .processing.watchlist import WatchTerm, match_watchlist
from .safety import is_prohibited, redact, sha256
from .search import index_document

log = logging.getLogger(__name__)


@dataclass
class RunStats:
    processed: int = 0
    new_documents: int = 0
    duplicates: int = 0
    changed_pages: int = 0
    dropped: int = 0
    indicators: int = 0
    alerts: int = 0
    victims: int = 0
    health_checks: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


_LEGAL = re.compile(r"\b(inc|llc|ltd|limited|gmbh|corp|corporation|co|company|s\.?a|ag|plc|group|srl|bv|pty|llp)\b\.?", re.I)


def victim_key(name: str) -> str:
    """Normalise a victim name for cross-source matching ("ACME, Inc." == "Acme")."""
    return re.sub(r"[^a-z0-9]", "", _LEGAL.sub("", name.lower()))


def backfill_sightings(session: Session) -> int:
    """Give every victim a sighting for the source that first reported it (idempotent)."""
    rows = session.execute(
        select(Victim.id, Victim.source_id, Victim.discovered_at)
        .outerjoin(VictimSighting, (VictimSighting.victim_id == Victim.id) & (VictimSighting.source_id == Victim.source_id))
        .where(VictimSighting.id.is_(None), Victim.source_id.is_not(None))
    ).all()
    for vid, sid, when in rows:
        session.add(VictimSighting(victim_id=vid, source_id=sid, first_seen=when, last_seen=when))
    session.flush()
    return len(rows)


def html_to_text(html: str) -> tuple[str, str | None]:
    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.get_text(strip=True) if soup.title else None
    for tag in soup(["head", "script", "style", "noscript", "svg", "img", "iframe", "form"]):
        tag.decompose()
    for br in soup.find_all("br"):
        br.replace_with("\n")
    text = soup.get_text("\n")
    lines = [ln.strip() for ln in text.splitlines()]
    return "\n".join(ln for ln in lines if ln), title


def sync_watchlist_from_file(session: Session, settings: Settings | None = None) -> int:
    """Seed the DB watchlist from config/watchlist.yaml (idempotent)."""
    settings = settings or get_settings()
    cfg = load_yaml(settings.watchlist_file)
    added = 0
    existing = {(w.kind, w.value) for w in session.scalars(select(WatchlistItem))}
    for kind_plural, kind in (("domains", "domain"), ("keywords", "keyword"), ("email_domains", "email_domain"),
                              ("ip_ranges", "ip_range"), ("bins", "bin")):
        for entry in cfg.get(kind_plural) or []:
            value, sev = (entry, "high") if isinstance(entry, str) else (entry["value"], entry.get("severity", "high"))
            if (kind, value) not in existing:
                session.add(WatchlistItem(kind=kind, value=value, severity=sev))
                existing.add((kind, value))
                added += 1
    session.flush()
    return added


class Pipeline:
    def __init__(self, session: Session, settings: Settings | None = None):
        self.s = session
        self.settings = settings or get_settings()
        self.stats = RunStats()
        self._sources: dict[str, Source] = {}
        self._indicator_cache: dict[tuple[str, str], Indicator] = {}
        self._latest_check: dict = {}
        self._victim_cache: dict[str, list[Victim]] = {}
        self.watch_terms = [WatchTerm(w.kind, w.value, w.severity) for w in session.scalars(select(WatchlistItem))]

    # --- sources -----------------------------------------------------------------------------

    def _source(self, name: str, kind: str, url: str | None) -> Source:
        if name in self._sources:
            return self._sources[name]
        src = self.s.scalar(select(Source).where(Source.name == name))
        if src is None:
            src = Source(name=name, kind=kind, url=url)
            self.s.add(src)
            self.s.flush()
        self._sources[name] = src
        return src

    def record_health(self, h: Health) -> None:
        src = self._source(h.source_name, h.source_kind, h.source_url)
        when = h.checked_at or utcnow()
        self.s.add(SourceCheck(source_id=src.id, checked_at=when, ok=h.ok, status_code=h.status_code,
                               latency_ms=h.latency_ms, error=h.error))
        if when >= self._latest_check.get(src.name, when):
            self._latest_check[src.name] = when
            src.last_status = "up" if h.ok else "down"
        if h.ok:
            src.last_seen = max(src.last_seen or when, when)
        self.stats.health_checks += 1

    # --- documents ---------------------------------------------------------------------------

    def _store_raw(self, content: str, digest: str) -> str:
        path: Path = self.settings.raw_dir / digest[:2] / f"{digest}.gz"
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            with gzip.open(path, "wt", encoding="utf-8") as fh:
                fh.write(content)
        return str(path.relative_to(self.settings.raw_dir))

    def _indicator(self, ioc, seen_at) -> Indicator:
        key = (ioc.type, ioc.value_hash)
        ind = self._indicator_cache.get(key)
        if ind is None:
            ind = self.s.scalar(select(Indicator).where(Indicator.type == ioc.type, Indicator.value_hash == ioc.value_hash))
        if ind is None:
            ind = Indicator(type=ioc.type, value=ioc.value[:500], value_hash=ioc.value_hash, context=ioc.context,
                            first_seen=seen_at, last_seen=seen_at, sightings=0)
            self.s.add(ind)
            self.stats.indicators += 1
        ind.sightings += 1
        ind.first_seen = min(ind.first_seen, seen_at)
        ind.last_seen = max(ind.last_seen, seen_at)
        self._indicator_cache[key] = ind
        return ind

    def process(self, item: RawItem) -> Document | None:
        self.stats.processed += 1
        content = item.content or ""

        # 1. safety gate - before anything touches disk
        reason = is_prohibited(content)
        if reason:
            self.s.add(DroppedItem(url_hash=sha256(item.url), reason=reason))
            self.stats.dropped += 1
            log.warning("dropped item from %s (%s)", item.source_name, reason)
            return None

        # 2. text extraction
        if item.is_html:
            text, html_title = html_to_text(content)
        else:
            text, html_title = content.strip(), None
        title = item.title or html_title
        digest = sha256(text)

        # 3. change detection / dedupe
        last = self.s.scalar(
            select(PageSnapshot).where(PageSnapshot.url == item.url).order_by(PageSnapshot.fetched_at.desc()).limit(1)
        )
        dup_id = self.s.scalar(select(Document.id).where(Document.content_hash == digest))
        if (last is not None and last.content_hash == digest) or dup_id:
            self.stats.duplicates += 1
            if (item.victims or item.victim) and dup_id:
                # unchanged page: still confirm its victims (sightings, newly added parsers, date repair)
                dup = self.s.get(Document, dup_id)
                src = self._source(item.source_name, item.source_kind, item.source_url)
                for v in [*item.victims, *([item.victim] if item.victim else [])]:
                    self._victim(v, src, dup, item.meta.get("collected_at") or utcnow())
            return None
        changed = last is not None
        collected_at = item.meta.get("collected_at") or utcnow()
        self.s.add(PageSnapshot(url=item.url, content_hash=digest, fetched_at=collected_at, changed=changed))
        if changed:
            self.stats.changed_pages += 1

        src = self._source(item.source_name, item.source_kind, item.source_url)
        raw_path = self._store_raw(redact(content), digest)

        # 4. analysis on redacted text
        clean = redact(text)
        lang = detect_language(clean)
        translated = translate_to_english(clean, lang) if self.settings.translate else None
        analysis_text = translated or clean
        cls = classify(f"{title or ''}\n{analysis_text}", self.settings.classifier)
        if item.meta.get("group") or item.victims:
            # a page from a known ransomware leak site is extortion content by definition, even when its
            # text is just a list of company names that the text classifier cannot recognise
            cls.category = "ransomware"
            cls.confidence = max(cls.confidence, 0.95)
            cls.evidence = ["source: ransomware leak site", *cls.evidence][:8]
        iocs = extract_iocs(clean)
        entities = extract_entities(analysis_text, self.settings.ner)
        hits = match_watchlist(f"{title or ''}\n{clean}", iocs, self.watch_terms)
        techniques = map_techniques(cls.category, analysis_text, any(i.type == "cve" for i in iocs))
        score = threat_score(cls.category, cls.confidence, iocs, hits, item.published_at, utcnow())

        doc = Document(
            source_id=src.id, url=item.url[:1000], title=(title or "")[:500] or None, author=item.author,
            text=clean, translated_text=translated, content_hash=digest, raw_path=raw_path, language=lang,
            category=cls.category, category_confidence=cls.confidence,
            category_scores={"scores": cls.scores, "evidence": cls.evidence}, entities=entities,
            attack_techniques=techniques, threat_score=score, published_at=item.published_at,
            collected_at=collected_at,
        )
        doc.indicators = [self._indicator(i, item.published_at or collected_at) for i in iocs]
        self.s.add(doc)
        self.s.flush()

        for h in hits:
            self.s.add(Alert(document_id=doc.id, watch_kind=h.term.kind, watch_value=h.term.value,
                             matched=h.matched[:500], snippet=h.snippet, severity=h.severity, created_at=collected_at))
            self.stats.alerts += 1

        if item.victim:
            self._victim(item.victim, src, doc, collected_at)
        for v in item.victims:
            self._victim(v, src, doc, collected_at)

        src.last_seen = max(src.last_seen or collected_at, collected_at)
        if src.last_status == "unknown":
            src.last_status = "up"
        self.stats.new_documents += 1
        index_document(doc, src.name)
        return doc

    def _group_victims(self, group: str) -> list[Victim]:
        key = group.lower()
        if key not in self._victim_cache:
            self._victim_cache[key] = list(self.s.scalars(select(Victim).where(func.lower(Victim.group_name) == key)))
        return self._victim_cache[key]

    def _sight(self, victim: Victim, src: Source, when) -> None:
        sighting = self.s.scalar(
            select(VictimSighting).where(VictimSighting.victim_id == victim.id, VictimSighting.source_id == src.id)
        )
        if sighting is None:
            self.s.add(VictimSighting(victim_id=victim.id, source_id=src.id, first_seen=when, last_seen=when))
        else:
            sighting.last_seen = max(sighting.last_seen, when)

    def _victim(self, v: dict, src: Source, doc: Document, collected_at) -> None:
        name_key, domain = victim_key(v["name"]), (v.get("domain") or "").lower() or None
        existing = next(
            (x for x in self._group_victims(v["group_name"])
             if victim_key(x.name) == name_key or (domain and (x.domain or "").lower() == domain)),
            None,
        )
        if existing:
            # same victim reported by another source: record the sighting and fill gaps
            self._sight(existing, src, collected_at)
            # keep the earliest real posting date any source knows (a crawl may only know "first seen today")
            if v.get("discovered_at") and v["discovered_at"] < existing.discovered_at:
                existing.discovered_at = v["discovered_at"]
            existing.country = existing.country or v.get("country")
            existing.sector = existing.sector or v.get("sector")
            existing.domain = existing.domain or v.get("domain")
            return
        victim = Victim(
            name=v["name"], domain=v.get("domain"), group_name=v["group_name"], country=v.get("country"),
            sector=v.get("sector"), description=v.get("description"),
            discovered_at=v.get("discovered_at") or collected_at, source_id=src.id, document_id=doc.id,
        )
        self.s.add(victim)
        self.s.flush()
        self._group_victims(v["group_name"]).append(victim)
        self._sight(victim, src, collected_at)
        self.stats.victims += 1
        # victim name/domain on the watchlist -> critical alert
        name_l, dom_l = victim.name.lower(), (victim.domain or "").lower()
        for t in self.watch_terms:
            val = t.value.lower()
            if (t.kind == "keyword" and val in name_l) or (t.kind == "domain" and dom_l and (dom_l == val or dom_l.endswith("." + val))):
                self.s.add(Alert(document_id=doc.id, victim_id=victim.id, watch_kind=t.kind, watch_value=t.value,
                                 matched=victim.name, severity="critical", created_at=collected_at,
                                 snippet=f"{victim.group_name} ransomware group listed {victim.name} as a victim"))
                self.stats.alerts += 1
                break

    def run(self, events: Iterable[RawItem | Health], commit_every: int = 50) -> RunStats:
        for n, ev in enumerate(events, 1):
            try:
                with self.s.begin_nested():  # savepoint: a bad item rolls back alone
                    if isinstance(ev, Health):
                        self.record_health(ev)
                    else:
                        self.process(ev)
            except Exception as exc:  # keep going - one bad page must not kill a crawl
                log.exception("failed to process event")
                self.stats.errors.append(f"{type(exc).__name__}: {exc}"[:300])
                self._sources.clear()
                self._indicator_cache.clear()
                self._victim_cache.clear()
            if n % commit_every == 0:
                self.s.commit()
        self.s.commit()
        return self.stats


def _sightings_by_victim(session: Session) -> dict[int, set[int]]:
    out: dict[int, set[int]] = {}
    for vid, sid in session.execute(select(VictimSighting.victim_id, VictimSighting.source_id)):
        out.setdefault(vid, set()).add(sid)
    return out


def reparse_leak_pages(session: Session) -> dict:
    """Re-run the victim parsers over every stored leak-site page (after parser improvements). No network."""
    from .collectors.leak_parsers import parse_leak_page

    settings = get_settings()
    # drop victims that only our crawl ever reported, so they are rebuilt with the current parsers
    leak_src = set(session.scalars(select(Source.id).where(Source.kind == "tor", Source.name.like("% leak site"))))
    crawl_only = [
        vid for vid, srcs in _sightings_by_victim(session).items() if srcs and srcs <= leak_src
    ]
    for i in range(0, len(crawl_only), 500):
        session.execute(delete(Victim).where(Victim.id.in_(crawl_only[i:i + 500])))
    session.flush()
    pipe = Pipeline(session, settings)
    docs = session.execute(
        select(Document, Source).join(Source)
        .where(Source.kind == "tor", Source.name.like("% leak site"), ~Source.name.like("%[demo]%"))
    ).all()
    pages = found = 0
    before = pipe.stats.victims
    for doc, src in docs:
        if not doc.raw_path:
            continue
        path = settings.raw_dir / doc.raw_path
        if not path.exists():
            continue
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            html = fh.read()
        victims = parse_leak_page(html, src.name.removesuffix(" leak site"))
        pages += 1
        found += len(victims)
        for v in victims:
            pipe._victim(v, src, doc, doc.collected_at)
        if doc.category != "ransomware":  # leak-site pages are extortion content by source
            doc.category, doc.category_confidence = "ransomware", max(doc.category_confidence, 0.95)
    session.commit()
    return {"pages": pages, "victims_parsed": found, "new_victims": pipe.stats.victims - before}


def run_collector(name: str, session: Session, **kwargs) -> RunStats:
    from .collectors import get_collector

    sync_watchlist_from_file(session)
    backfill_sightings(session)
    session.commit()
    collector = get_collector(name, **kwargs)
    return Pipeline(session).run(collector.collect())
