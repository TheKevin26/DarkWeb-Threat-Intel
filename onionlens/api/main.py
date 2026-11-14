"""REST API consumed by the React dashboard. Interactive docs at /docs."""

from __future__ import annotations

import csv
import io
import json
import threading
import uuid
from collections import Counter, defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from .. import __version__, scheduler
from ..collectors import COLLECTORS, JOBS
from ..jobs import run_job
from ..config import ROOT, get_settings
from ..countries import country_name, country_numeric
from ..db import SessionLocal, init_db, session_scope
from ..exporters import misp, stix
from ..exporters.attack import describe
from ..models import (
    Alert,
    Document,
    Indicator,
    Source,
    SourceCheck,
    Victim,
    VictimSighting,
    WalletCheck,
    WatchlistItem,
    document_indicators,
    utcnow,
)
from ..processing.classifier import LABELS
from ..processing.linking import actor_clusters, build_graph, graph_to_cytoscape, indicator_neighbors
from ..search import search_ids

settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    if settings.tor_autostart:
        import threading

        from ..tor_manager import start_tor

        threading.Thread(target=start_tor, name="tor-autostart", daemon=True).start()
    scheduler.start()
    yield
    scheduler.stop()


app = FastAPI(title="OnionLens API", version=__version__, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def require_key(x_api_key: str | None = Header(default=None)) -> None:
    if settings.api_key and x_api_key != settings.api_key:
        raise HTTPException(401, "invalid or missing X-API-Key")


Auth = Depends(require_key)


def _since(days: int | None) -> datetime | None:
    return utcnow() - timedelta(days=days) if days else None


def _when(doc_pub: datetime | None, doc_col: datetime) -> datetime:
    return doc_pub or doc_col


DEMO_TAG = "%[demo]%"


def _real_sources():
    """Condition matching sources that are NOT synthetic demo data."""
    return ~Source.name.like(DEMO_TAG)


# --- overview --------------------------------------------------------------------------------


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/api/stats", dependencies=[Auth])
def stats(days: int | None = Query(90), real_only: bool = False, db: Session = Depends(get_db)) -> dict:
    since = _since(days)
    stmt = select(Document.published_at, Document.collected_at, Document.category, Document.threat_score,
                  Document.language, Document.attack_techniques)
    if real_only:
        stmt = stmt.join(Source).where(_real_sources())
    rows_all = db.execute(stmt).all()
    rows = [r for r in rows_all if not since or _when(r[0], r[1]) >= since]

    timeline: dict[str, int] = defaultdict(int)
    by_cat: Counter = Counter()
    langs: Counter = Counter()
    techniques: Counter = Counter()
    high = 0
    for pub, col, cat, score, lang, techs in rows:
        timeline[_when(pub, col).date().isoformat()] += 1
        by_cat[cat] += 1
        langs[lang or "unknown"] += 1
        techniques.update(techs or [])
        high += score >= 60

    # fill missing days so the line is continuous
    if rows:
        start = since.date() if since else min(datetime.fromisoformat(d).date() for d in timeline)
        end = utcnow().date()
        series = []
        d = start
        while d <= end:
            series.append({"date": d.isoformat(), "count": timeline.get(d.isoformat(), 0)})
            d += timedelta(days=1)
    else:
        series = []

    if real_only:
        ind_q = (
            select(Indicator.type, func.count(func.distinct(Indicator.id)))
            .join(document_indicators, document_indicators.c.indicator_id == Indicator.id)
            .join(Document, Document.id == document_indicators.c.document_id)
            .join(Source)
            .where(_real_sources())
            .group_by(Indicator.type)
        )
    else:
        ind_q = select(Indicator.type, func.count()).group_by(Indicator.type)
    if since:
        ind_q = ind_q.where(Indicator.last_seen >= since)
    ind_types = dict(db.execute(ind_q).all())

    alert_q = select(Alert.severity, func.count()).where(Alert.status == "new").group_by(Alert.severity)
    if real_only:
        alert_q = alert_q.join(Document, Alert.document_id == Document.id).join(Source).where(_real_sources())
    alerts_open = dict(db.execute(alert_q).all())

    victims_q = select(func.count()).select_from(Victim)
    if real_only:
        victims_q = victims_q.join(Source, Victim.source_id == Source.id).where(_real_sources())
    if since:
        victims_q = victims_q.where(Victim.discovered_at >= since)
    sources_q = select(func.count()).select_from(Source)
    if real_only:
        sources_q = sources_q.where(_real_sources())

    # period-over-period change for the documents KPI
    prev = 0
    if since and days:
        prev_since = since - timedelta(days=days)
        prev = sum(1 for r in rows_all if prev_since <= _when(r[0], r[1]) < since)

    return {
        "documents": len(rows),
        "documents_prev": prev,
        "high_risk": high,
        "indicators": sum(ind_types.values()),
        "indicator_types": ind_types,
        "victims": db.scalar(victims_q),
        "alerts_open": alerts_open,
        "sources": db.scalar(sources_q),
        "sources_up": db.scalar(sources_q.where(Source.last_status == "up")),
        "timeline": series,
        "categories": [{"id": k, "label": LABELS.get(k, k), "count": v} for k, v in by_cat.most_common()],
        "languages": [{"code": k, "count": v} for k, v in langs.most_common(8)],
        "attack": [{**describe(t), "count": c} for t, c in techniques.most_common(15)],
    }


# --- documents -------------------------------------------------------------------------------


def _doc_summary(d: Document) -> dict:
    return {
        "id": d.id, "title": d.title, "url": d.url, "source": d.source.name, "source_kind": d.source.kind,
        "category": d.category, "category_label": LABELS.get(d.category, d.category),
        "confidence": d.category_confidence, "threat_score": d.threat_score, "language": d.language,
        "published_at": d.published_at, "collected_at": d.collected_at,
        "snippet": d.text[:240], "indicator_count": len(d.indicators), "alert_count": len(d.alerts),
    }


@app.get("/api/documents", dependencies=[Auth])
def documents(
    q: str = "", category: str | None = None, source: str | None = None, min_score: float = 0,
    days: int | None = None, sort: str = "recent", limit: int = Query(50, le=500), offset: int = 0,
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(Document).options(selectinload(Document.source), selectinload(Document.indicators),
                                    selectinload(Document.alerts))
    ids = search_ids(db, q)
    if ids is not None:
        if not ids:
            return {"total": 0, "items": []}
        stmt = stmt.where(Document.id.in_(ids))
    if category:
        stmt = stmt.where(Document.category == category)
    if source:
        stmt = stmt.join(Source).where(Source.name == source)
    if min_score:
        stmt = stmt.where(Document.threat_score >= min_score)
    if days:
        stmt = stmt.where(func.coalesce(Document.published_at, Document.collected_at) >= _since(days))
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    order = Document.threat_score.desc() if sort == "score" else func.coalesce(Document.published_at, Document.collected_at).desc()
    items = db.scalars(stmt.order_by(order).limit(limit).offset(offset)).all()
    return {"total": total, "items": [_doc_summary(d) for d in items]}


@app.get("/api/documents/{doc_id}", dependencies=[Auth])
def document(doc_id: int, db: Session = Depends(get_db)) -> dict:
    d = db.get(Document, doc_id)
    if not d:
        raise HTTPException(404)
    return {
        **_doc_summary(d),
        "text": d.text, "translated_text": d.translated_text, "author": d.author,
        "category_scores": (d.category_scores or {}).get("scores", {}),
        "evidence": (d.category_scores or {}).get("evidence", []),
        "entities": d.entities, "attack": [describe(t) for t in d.attack_techniques or []],
        "indicators": [{"id": i.id, "type": i.type, "value": i.value, "sightings": i.sightings} for i in d.indicators],
        "alerts": [{"id": a.id, "severity": a.severity, "matched": a.matched, "watch_value": a.watch_value} for a in d.alerts],
    }


# --- indicators ------------------------------------------------------------------------------


@app.get("/api/indicators", dependencies=[Auth])
def indicators(
    type: str | None = None, q: str = "", sort: str = "sightings", limit: int = Query(100, le=1000), offset: int = 0,
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(Indicator)
    if type:
        stmt = stmt.where(Indicator.type == type)
    if q:
        stmt = stmt.where(Indicator.value.ilike(f"%{q}%") | Indicator.context.ilike(f"%{q}%"))
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    order = Indicator.last_seen.desc() if sort == "recent" else Indicator.sightings.desc()
    items = db.scalars(stmt.order_by(order, Indicator.id).limit(limit).offset(offset)).all()
    return {
        "total": total,
        "items": [
            {"id": i.id, "type": i.type, "value": i.value, "context": i.context, "sightings": i.sightings,
             "first_seen": i.first_seen, "last_seen": i.last_seen}
            for i in items
        ],
    }


@app.get("/api/indicators/{ind_id}", dependencies=[Auth])
def indicator(ind_id: int, db: Session = Depends(get_db)) -> dict:
    i = db.get(Indicator, ind_id)
    if not i:
        raise HTTPException(404)
    return {
        "id": i.id, "type": i.type, "value": i.value, "context": i.context, "sightings": i.sightings,
        "first_seen": i.first_seen, "last_seen": i.last_seen,
        "documents": [{"id": d.id, "title": d.title, "source": d.source.name, "category": d.category} for d in i.documents[:50]],
        "related": [{"id": r.id, "type": r.type, "value": r.value} for r in indicator_neighbors(db, ind_id)[:50]],
        "on_chain": [
            {"checked_at": c.checked_at, "tx_count": c.tx_count, "received_btc": c.received_sats / 1e8,
             "balance_btc": c.balance_sats / 1e8, "pending_tx": c.pending_tx, "last_tx_at": c.last_tx_at,
             "new_tx": c.new_tx, "new_received_btc": c.new_received_sats / 1e8}
            for c in db.scalars(select(WalletCheck).where(WalletCheck.indicator_id == ind_id)
                                .order_by(WalletCheck.checked_at.desc()).limit(20))
        ],
    }


# --- alerts ----------------------------------------------------------------------------------


@app.get("/api/alerts", dependencies=[Auth])
def alerts(status: str | None = None, severity: str | None = None, limit: int = Query(200, le=1000),
           db: Session = Depends(get_db)) -> list[dict]:
    stmt = select(Alert).options(selectinload(Alert.document).selectinload(Document.source))
    if status:
        stmt = stmt.where(Alert.status == status)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    out = []
    for a in db.scalars(stmt.order_by(Alert.created_at.desc()).limit(limit)):
        out.append({
            "id": a.id, "severity": a.severity, "status": a.status, "watch_kind": a.watch_kind,
            "watch_value": a.watch_value, "matched": a.matched, "snippet": a.snippet, "created_at": a.created_at,
            "document_id": a.document_id, "victim_id": a.victim_id,
            "document_title": a.document.title if a.document else None,
            "source": a.document.source.name if a.document else None,
        })
    return out


class AlertUpdate(BaseModel):
    status: str


@app.patch("/api/alerts/{alert_id}", dependencies=[Auth])
def update_alert(alert_id: int, body: AlertUpdate, db: Session = Depends(get_db)) -> dict:
    if body.status not in ("new", "acknowledged", "resolved"):
        raise HTTPException(422, "status must be new | acknowledged | resolved")
    a = db.get(Alert, alert_id)
    if not a:
        raise HTTPException(404)
    a.status = body.status
    db.commit()
    return {"id": a.id, "status": a.status}


# --- ransomware victims ----------------------------------------------------------------------


@app.get("/api/victims", dependencies=[Auth])
def victims(q: str = "", group: str | None = None, country: str | None = None, sector: str | None = None,
            days: int | None = None, limit: int = Query(200, le=2000), db: Session = Depends(get_db)) -> dict:
    stmt = select(Victim)
    if q:
        stmt = stmt.where(Victim.name.ilike(f"%{q}%") | Victim.domain.ilike(f"%{q}%"))
    if group:
        stmt = stmt.where(Victim.group_name == group)
    if country:
        stmt = stmt.where(Victim.country == country)
    if sector:
        stmt = stmt.where(Victim.sector == sector)
    if days:
        stmt = stmt.where(Victim.discovered_at >= _since(days))
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = db.scalars(stmt.order_by(Victim.discovered_at.desc()).limit(limit)).all()
    return {
        "total": total,
        "items": [
            {"id": v.id, "name": v.name, "domain": v.domain, "group": v.group_name, "country": v.country,
             "country_name": country_name(v.country), "sector": v.sector, "description": v.description,
             "discovered_at": v.discovered_at, "document_id": v.document_id}
            for v in rows
        ],
    }


@app.get("/api/victims/stats", dependencies=[Auth])
def victim_stats(days: int | None = Query(None), real_only: bool = False, db: Session = Depends(get_db)) -> dict:
    since = _since(days)

    def scoped(stmt):
        if real_only:
            stmt = stmt.join(Source, Victim.source_id == Source.id).where(_real_sources())
        if since:
            stmt = stmt.where(Victim.discovered_at >= since)
        return stmt

    def grouped(col):
        return db.execute(scoped(select(col, func.count()).group_by(col).order_by(func.count().desc()))).all()

    weekly: Counter = Counter()
    stmt = scoped(select(Victim.discovered_at))
    for (dt,) in db.execute(stmt):
        monday = (dt - timedelta(days=dt.weekday())).date().isoformat()
        weekly[monday] += 1

    groups = grouped(Victim.group_name)
    return {
        "total": sum(c for _, c in groups),
        "groups_total": len(groups),
        "by_group": [{"group": g, "count": c} for g, c in groups[:15]],
        "by_country": [
            {"code": c, "name": country_name(c), "numeric": country_numeric(c), "count": n}
            for c, n in grouped(Victim.country) if c
        ],
        "by_sector": [{"sector": s or "Unknown", "count": c} for s, c in grouped(Victim.sector)],
        "weekly": [{"week": w, "count": weekly[w]} for w in sorted(weekly)],
    }


# --- source coverage -------------------------------------------------------------------------


@app.get("/api/coverage", dependencies=[Auth])
def coverage(days: int = Query(14, ge=1, le=365), db: Session = Depends(get_db)) -> dict:
    """Our own Tor leak-site crawl vs the ransomware.live feed: who sees which victims."""
    since = _since(days)
    ours = {s.id: s for s in db.scalars(
        select(Source).where(Source.kind == "tor", Source.name.like("% leak site"), _real_sources()))}
    theirs = set(db.scalars(select(Source.id).where(Source.name == "ransomware.live")))
    sightings: dict[int, set[int]] = defaultdict(set)
    for vid, sid in db.execute(
        select(VictimSighting.victim_id, VictimSighting.source_id).join(Victim, Victim.id == VictimSighting.victim_id)
        .where(Victim.discovered_at >= since)
    ):
        sightings[vid].add(sid)
    victims = db.execute(select(Victim.id, Victim.group_name).where(Victim.id.in_(list(sightings)))).all() if sightings else []

    crawled = {s.name.removesuffix(" leak site").lower(): s for s in ours.values()}
    per: dict[str, Counter] = defaultdict(Counter)
    for vid, group in victims:
        g = group.lower()
        if g not in crawled:
            continue
        srcs = sightings[vid]
        o, t = bool(srcs & set(ours)), bool(srcs & theirs)
        per[g]["ours"] += o
        per[g]["theirs"] += t
        per[g]["both"] += o and t
        per[g]["only_ours"] += o and not t
        per[g]["only_theirs"] += t and not o

    rows = []
    for g, src in sorted(crawled.items()):
        latest = db.scalar(select(func.length(Document.text)).where(Document.source_id == src.id)
                           .order_by(Document.collected_at.desc()).limit(1))
        c = per.get(g, Counter())
        if src.last_status != "up" and not latest:
            state = "unreachable"
        elif latest is not None and latest < 300:
            state = "javascript-only page"
        elif c["ours"]:
            state = "parsed"
        else:
            state = "no victims parsed"
        rows.append({"group": src.name.removesuffix(" leak site"), "status": src.last_status, "state": state,
                     "last_seen": src.last_seen, **{k: c[k] for k in ("ours", "theirs", "both", "only_ours", "only_theirs")}})
    rows.sort(key=lambda r: (-(r["ours"] + r["theirs"]), r["group"].lower()))
    totals = Counter()
    for r in rows:
        totals.update({k: r[k] for k in ("ours", "theirs", "both", "only_ours", "only_theirs")})
    return {"window_days": days, "groups_crawled": len(rows), "groups_parsed": sum(r["state"] == "parsed" for r in rows),
            "totals": dict(totals), "groups": rows}


# --- live threat map -------------------------------------------------------------------------


@app.get("/api/map", dependencies=[Auth])
def threat_map(hours: int = Query(168, ge=1, le=24 * 365), real_only: bool = False, limit: int = Query(400, le=2000),
               db: Session = Depends(get_db)) -> dict:
    """Geolocated attacks (leak-site victims) for the animated map, newest first, plus panel rankings."""
    now = utcnow()
    since = now - timedelta(hours=hours)

    def scoped(stmt):
        if real_only:
            stmt = stmt.join(Source, Victim.source_id == Source.id).where(_real_sources())
        return stmt

    rows = db.scalars(
        scoped(select(Victim)).where(Victim.discovered_at >= since).order_by(Victim.discovered_at.desc()).limit(limit)
    ).all()
    events = [
        {
            "id": v.id, "victim": v.name, "group": v.group_name, "country": v.country,
            "country_name": country_name(v.country), "numeric": country_numeric(v.country), "sector": v.sector,
            "at": v.discovered_at, "document_id": v.document_id,
        }
        for v in rows
    ]

    def count_since(h: int) -> int:
        return db.scalar(scoped(select(func.count()).select_from(Victim)).where(Victim.discovered_at >= now - timedelta(hours=h)))

    def top(col, n=8):
        stmt = scoped(select(col, func.count()).where(Victim.discovered_at >= since, col.is_not(None)))
        return db.execute(stmt.group_by(col).order_by(func.count().desc()).limit(n)).all()

    return {
        "window_hours": hours,
        "server_time": now,
        "max_id": db.scalar(select(func.max(Victim.id))) or 0,
        "counts": {"last_24h": count_since(24), "last_7d": count_since(168), "window": len(events)},
        "events": events,
        "top_countries": [{"code": c, "name": country_name(c), "count": n} for c, n in top(Victim.country)],
        "top_groups": [{"name": g, "count": n} for g, n in top(Victim.group_name)],
        "top_sectors": [{"name": s, "count": n} for s, n in top(Victim.sector)],
    }


# --- live activity ---------------------------------------------------------------------------

_ACTIVITY_VERB = {
    "ransomware": "Ransomware attack",
    "credential_leak": "Credential leak",
    "access_broker": "Network access for sale",
    "exploit": "Exploit offered",
    "malware": "Malware offered",
    "fraud": "Carding / fraud",
    "hacking_services": "Hacking service",
    "drugs": "Drug listing",
    "other": "Post",
}
_WALLET_TYPES = {"btc_address", "xmr_address", "eth_address"}


@app.get("/api/activity", dependencies=[Auth])
def activity(limit: int = Query(40, le=200), real_only: bool = False, after_id: int = 0,
             db: Session = Depends(get_db)) -> dict:
    """Newest events first: attacks, leaks, illicit listings and posts carrying payment wallets."""
    items = []

    # 1. ransomware attacks: one event per victim (a leak-site page can list dozens)
    vstmt = select(Victim, Source).join(Source, Source.id == Victim.source_id)
    if real_only:
        vstmt = vstmt.where(_real_sources())
    for v, src in db.execute(vstmt.order_by(Victim.discovered_at.desc(), Victim.id.desc()).limit(limit)):
        items.append({
            "key": f"v{v.id}", "id": v.document_id, "document_id": v.document_id, "kind": "ransomware",
            "label": _ACTIVITY_VERB["ransomware"], "title": f"{v.group_name} hit {v.name}",
            "source": src.name, "demo": "[demo]" in src.name, "at": v.discovered_at, "collected_at": v.discovered_at,
            "country": v.country, "country_name": country_name(v.country), "country_numeric": country_numeric(v.country),
            "sector": v.sector, "threat_score": 0, "payment_wallets": [],
        })

    # 2. other illicit activity (forum posts, listings, pastes) - documents not already shown as a victim
    when = func.coalesce(Document.published_at, Document.collected_at)
    dstmt = (
        select(Document)
        .options(selectinload(Document.source), selectinload(Document.indicators))
        .join(Source)
        .where(Document.category.not_in(["other", "ransomware"]))
    )
    if real_only:
        dstmt = dstmt.where(_real_sources())
    for d in db.scalars(dstmt.order_by(when.desc(), Document.id.desc()).limit(limit)):
        items.append({
            "key": f"d{d.id}", "id": d.id, "document_id": d.id, "kind": d.category,
            "label": _ACTIVITY_VERB.get(d.category, d.category), "title": d.title or d.text[:90] or "(untitled)",
            "source": d.source.name, "demo": "[demo]" in d.source.name, "at": d.published_at or d.collected_at,
            "collected_at": d.collected_at, "country": None, "country_name": None, "country_numeric": None,
            "sector": None, "threat_score": d.threat_score,
            "payment_wallets": sorted({i.type for i in d.indicators if i.type in _WALLET_TYPES}),
        })
    # on-chain movements of wallets advertised in dark web posts
    moves = db.execute(
        select(WalletCheck, Indicator).join(Indicator, Indicator.id == WalletCheck.indicator_id)
        .where(WalletCheck.new_tx > 0).order_by(WalletCheck.checked_at.desc()).limit(limit)
    ).all()
    for chk, ind in moves:
        doc = next(iter(ind.documents), None)
        if real_only and doc is not None and "[demo]" in doc.source.name:
            continue
        items.append({
            "key": f"w{chk.id}", "id": -chk.id, "kind": "transaction", "label": "Wallet transaction",
            "title": f"{chk.new_tx} new tx · +{chk.new_received_sats / 1e8:.8f} BTC to {ind.value[:14]}…",
            "source": doc.source.name if doc else "blockchain", "demo": bool(doc and "[demo]" in doc.source.name),
            "at": chk.last_tx_at or chk.checked_at, "collected_at": chk.checked_at, "country": None,
            "country_name": None, "country_numeric": None, "sector": None, "threat_score": 0,
            "payment_wallets": ["btc_address"], "is_new": False, "indicator_id": ind.id,
            "document_id": doc.id if doc else None,
        })
    items.sort(key=lambda i: i["at"], reverse=True)
    items = items[:limit]

    last = db.scalar(select(func.max(Document.collected_at)))
    return {
        "items": items,
        "max_id": db.scalar(select(func.max(Document.id))) or 0,
        "last_collected_at": last,
        "server_time": utcnow(),
        "auto_collect": scheduler.status,
    }


# --- tor & wallets ---------------------------------------------------------------------------

_tor_cache: dict = {"at": None, "value": None}


@app.get("/api/tor", dependencies=[Auth])
def tor_status(refresh: bool = False) -> dict:
    """Is a Tor SOCKS proxy reachable? Cached for 2 minutes (each check goes out through Tor)."""
    from ..collectors.tor_crawler import find_tor
    from ..config import load_yaml

    now = utcnow()
    if refresh or not _tor_cache["at"] or (now - _tor_cache["at"]).total_seconds() > 120:
        _tor_cache.update(at=now, value=find_tor(settings))
    seeds = load_yaml(settings.seeds_file).get("onion_seeds") or []
    return {**_tor_cache["value"], "checked_at": _tor_cache["at"], "seeds_configured": len(seeds)}


@app.get("/api/wallets", dependencies=[Auth])
def wallets(limit: int = Query(100, le=500), db: Session = Depends(get_db)) -> dict:
    latest = (
        select(WalletCheck.indicator_id, func.max(WalletCheck.id).label("cid")).group_by(WalletCheck.indicator_id).subquery()
    )
    rows = db.execute(
        select(Indicator, WalletCheck).join(latest, latest.c.indicator_id == Indicator.id)
        .join(WalletCheck, WalletCheck.id == latest.c.cid)
        .order_by(WalletCheck.tx_count.desc(), WalletCheck.received_sats.desc()).limit(limit)
    ).all()
    tracked = db.scalar(select(func.count()).select_from(Indicator).where(Indicator.type == "btc_address"))
    return {
        "tracked": tracked,
        "checked": len(rows),
        "items": [
            {"id": i.id, "address": i.value, "tx_count": c.tx_count, "received_btc": c.received_sats / 1e8,
             "balance_btc": c.balance_sats / 1e8, "pending_tx": c.pending_tx, "last_tx_at": c.last_tx_at,
             "checked_at": c.checked_at, "posts": i.sightings}
            for i, c in rows
        ],
    }


# --- actors / graph --------------------------------------------------------------------------


@app.get("/api/graph", dependencies=[Auth])
def graph(min_weight: int = 1, limit: int = Query(300, le=1500), db: Session = Depends(get_db)) -> dict:
    return graph_to_cytoscape(build_graph(db, min_weight=min_weight), limit=limit)


@app.get("/api/actors", dependencies=[Auth])
def actors(db: Session = Depends(get_db)) -> list[dict]:
    return actor_clusters(build_graph(db))


# --- watchlist -------------------------------------------------------------------------------


class WatchIn(BaseModel):
    kind: str
    value: str
    severity: str = "high"


@app.get("/api/watchlist", dependencies=[Auth])
def watchlist(db: Session = Depends(get_db)) -> list[dict]:
    counts = dict(db.execute(select(Alert.watch_value, func.count()).group_by(Alert.watch_value)).all())
    return [
        {"id": w.id, "kind": w.kind, "value": w.value, "severity": w.severity, "created_at": w.created_at,
         "alerts": counts.get(w.value, 0)}
        for w in db.scalars(select(WatchlistItem).order_by(WatchlistItem.kind, WatchlistItem.value))
    ]


@app.post("/api/watchlist", dependencies=[Auth], status_code=201)
def add_watch(body: WatchIn, db: Session = Depends(get_db)) -> dict:
    if body.kind not in ("domain", "keyword", "email_domain", "ip_range", "bin"):
        raise HTTPException(422, "kind must be domain | keyword | email_domain | ip_range | bin")
    if body.severity not in ("low", "medium", "high", "critical"):
        raise HTTPException(422, "invalid severity")
    value = body.value.strip()
    if not value:
        raise HTTPException(422, "value required")
    if db.scalar(select(WatchlistItem).where(WatchlistItem.kind == body.kind, WatchlistItem.value == value)):
        raise HTTPException(409, "already on watchlist")
    w = WatchlistItem(kind=body.kind, value=value, severity=body.severity)
    db.add(w)
    db.commit()
    return {"id": w.id, "kind": w.kind, "value": w.value, "severity": w.severity}


@app.delete("/api/watchlist/{item_id}", dependencies=[Auth], status_code=204)
def delete_watch(item_id: int, db: Session = Depends(get_db)) -> Response:
    w = db.get(WatchlistItem, item_id)
    if not w:
        raise HTTPException(404)
    db.delete(w)
    db.commit()
    return Response(status_code=204)


# --- sources ---------------------------------------------------------------------------------


@app.get("/api/sources", dependencies=[Auth])
def sources(db: Session = Depends(get_db)) -> list[dict]:
    doc_counts = dict(db.execute(select(Document.source_id, func.count()).group_by(Document.source_id)).all())
    out = []
    for s in db.scalars(select(Source).order_by(Source.name)):
        checks = db.scalars(
            select(SourceCheck).where(SourceCheck.source_id == s.id).order_by(SourceCheck.checked_at.desc()).limit(30)
        ).all()
        lat = [c.latency_ms for c in checks if c.ok and c.latency_ms]
        out.append({
            "id": s.id, "name": s.name, "kind": s.kind, "url": s.url, "status": s.last_status, "last_seen": s.last_seen,
            "documents": doc_counts.get(s.id, 0),
            "uptime": round(100 * sum(c.ok for c in checks) / len(checks), 1) if checks else None,
            "avg_latency_ms": round(sum(lat) / len(lat)) if lat else None,
            "history": [{"at": c.checked_at, "ok": c.ok} for c in reversed(checks)],
        })
    return sorted(out, key=lambda s: (-s["documents"], s["name"]))


# --- collection jobs -------------------------------------------------------------------------

_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


def _run_job(job_id: str, source: str) -> None:
    try:
        with session_scope() as s:
            result = run_job(source, s)
        status = "done"
    except Exception as exc:
        result, status = {"error": str(exc)[:500]}, "failed"
    with _jobs_lock:
        _jobs[job_id].update(status=status, result=result, finished_at=utcnow())


@app.post("/api/collect/{source}", dependencies=[Auth], status_code=202)
def collect(source: str, tasks: BackgroundTasks) -> dict:
    if source not in COLLECTORS + JOBS:
        raise HTTPException(404, f"unknown job; choose from {COLLECTORS + JOBS}")
    job_id = uuid.uuid4().hex[:12]
    with _jobs_lock:
        _jobs[job_id] = {"id": job_id, "source": source, "status": "running", "started_at": utcnow()}
    tasks.add_task(_run_job, job_id, source)
    return _jobs[job_id]


@app.get("/api/jobs", dependencies=[Auth])
def jobs() -> list[dict]:
    with _jobs_lock:
        return sorted(_jobs.values(), key=lambda j: j["started_at"], reverse=True)


# --- export ----------------------------------------------------------------------------------


def build_export(db: Session, fmt: str, types: list[str] | None = None) -> tuple[str, str]:
    stmt = select(Indicator)
    if types:
        stmt = stmt.where(Indicator.type.in_(types))
    inds = db.scalars(stmt.order_by(Indicator.sightings.desc())).all()
    if fmt == "stix":
        techs: Counter = Counter()
        for (t,) in db.execute(select(Document.attack_techniques)):
            techs.update(t or [])
        bundle = stix.build_bundle(inds, actors=actor_clusters(build_graph(db)), techniques=list(techs))
        return json.dumps(bundle, indent=2), ".json"
    if fmt == "misp":
        return json.dumps(misp.build_event(inds), indent=2), ".json"
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["type", "value", "context", "sightings", "first_seen", "last_seen"])
        for i in inds:
            w.writerow([i.type, i.value, i.context or "", i.sightings, i.first_seen.isoformat(), i.last_seen.isoformat()])
        return buf.getvalue(), ".csv"
    raise HTTPException(422, "format must be stix | misp | csv")


@app.get("/api/export/{fmt}", dependencies=[Auth])
def export(fmt: str, types: str | None = None, db: Session = Depends(get_db)) -> Response:
    content, ext = build_export(db, fmt, types.split(",") if types else None)
    media = "text/csv" if ext == ".csv" else "application/json"
    name = f"onionlens-{fmt}-{utcnow():%Y%m%d}{ext}"
    return Response(content, media_type=media, headers={"Content-Disposition": f'attachment; filename="{name}"'})


# --- frontend --------------------------------------------------------------------------------

_DIST = ROOT / "frontend" / "dist"
if _DIST.exists():
    app.mount("/", StaticFiles(directory=Path(_DIST), html=True), name="frontend")
