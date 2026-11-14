"""Import known ransomware payment wallets from the public ransomwhe.re dataset.

ransomwhe.re is a crowd-sourced, open dataset of Bitcoin addresses that received ransom payments,
labelled by ransomware family. Imported addresses become ``btc_address`` indicators so the wallet
tracker watches them for new on-chain movement. The most recently active addresses are preferred.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Indicator, utcnow

log = logging.getLogger(__name__)

EXPORT = "https://api.ransomwhe.re/export"


def _value_hash(addr: str) -> str:
    return hashlib.sha256(f"btc_address:{addr}".encode()).hexdigest()


def import_ransomwhere(session: Session, limit: int = 400, data: list[dict] | None = None) -> dict:
    if data is None:
        resp = httpx.get(EXPORT, timeout=120, headers={"User-Agent": "onionlens/0.1"}).raise_for_status().json()
        data = resp.get("result", resp) if isinstance(resp, dict) else resp

    def last_tx(row: dict) -> int:
        return max((t.get("time") or 0 for t in row.get("transactions") or []), default=0)

    rows = sorted((r for r in data if r.get("blockchain", "bitcoin") == "bitcoin" and r.get("address")),
                  key=last_tx, reverse=True)[:limit]
    added = updated = 0
    for r in rows:
        addr = r["address"]
        family = (r.get("family") or "Unlabeled").strip()
        txs = r.get("transactions") or []
        first = min((t.get("time") or 0 for t in txs), default=0)
        last = last_tx(r)
        to_dt = lambda ts: datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None) if ts else utcnow()  # noqa: E731
        ind = session.scalar(select(Indicator).where(Indicator.type == "btc_address", Indicator.value_hash == _value_hash(addr)))
        if ind is None:
            ind = Indicator(type="btc_address", value=addr, value_hash=_value_hash(addr), context=f"{family} ransom wallet",
                            first_seen=to_dt(first), last_seen=to_dt(last), sightings=1)
            session.add(ind)
            # No baseline from the dataset: its "balance" field is total *received*, not the current balance.
            # The first live blockchain check becomes the baseline; later checks report genuine movement.
            added += 1
        else:
            if not ind.context:
                ind.context = f"{family} ransom wallet"
            updated += 1
    session.commit()
    return {"wallets_added": added, "already_known": updated, "considered": len(rows)}
