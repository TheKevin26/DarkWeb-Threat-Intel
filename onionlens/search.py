"""Full-text search: OpenSearch when configured, SQL LIKE fallback otherwise."""

from __future__ import annotations

import logging
from functools import lru_cache

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import Document

log = logging.getLogger(__name__)
INDEX = "onionlens-documents"


@lru_cache(maxsize=1)
def _client():
    url = get_settings().opensearch_url
    if not url:
        return None
    try:
        from opensearchpy import OpenSearch

        client = OpenSearch(url, timeout=10)
        if not client.indices.exists(INDEX):
            client.indices.create(
                INDEX,
                body={
                    "mappings": {
                        "properties": {
                            "title": {"type": "text"},
                            "text": {"type": "text"},
                            "category": {"type": "keyword"},
                            "source": {"type": "keyword"},
                            "language": {"type": "keyword"},
                            "threat_score": {"type": "float"},
                            "collected_at": {"type": "date"},
                        }
                    }
                },
            )
        return client
    except Exception as exc:  # pragma: no cover - depends on external service
        log.warning("OpenSearch unavailable (%s); using SQL search", exc)
        return None


def index_document(doc: Document, source_name: str) -> None:
    client = _client()
    if client is None:
        return
    try:  # pragma: no cover - external service
        client.index(
            INDEX,
            id=str(doc.id),
            body={
                "title": doc.title, "text": doc.text, "category": doc.category, "source": source_name,
                "language": doc.language, "threat_score": doc.threat_score, "collected_at": doc.collected_at.isoformat(),
            },
        )
    except Exception as exc:  # pragma: no cover
        log.warning("indexing failed: %s", exc)


def search_ids(session: Session, q: str, limit: int = 500) -> list[int] | None:
    """Return matching document ids, best first. ``None`` means 'no query'."""
    q = (q or "").strip()
    if not q:
        return None
    client = _client()
    if client is not None:  # pragma: no cover - external service
        try:
            res = client.search(
                index=INDEX,
                body={"size": limit, "query": {"multi_match": {"query": q, "fields": ["title^2", "text"]}}, "_source": False},
            )
            return [int(h["_id"]) for h in res["hits"]["hits"]]
        except Exception as exc:
            log.warning("OpenSearch query failed (%s); falling back to SQL", exc)
    terms = [t for t in q.split() if t]
    stmt = select(Document.id)
    for t in terms:
        like = f"%{t}%"
        stmt = stmt.where(or_(Document.text.ilike(like), Document.title.ilike(like)))
    return list(session.scalars(stmt.order_by(Document.threat_score.desc()).limit(limit)))
