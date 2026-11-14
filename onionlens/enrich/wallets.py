"""Bitcoin wallet tracking.

Payment addresses posted in dark web listings are checked against the public blockchain via the
mempool.space REST API (no key needed). Each check stores a snapshot; when a wallet gains new
transactions between checks, that movement becomes an event in the live feed.

Only BTC is tracked: Monero is private by design, and ETH tracking would need another provider.
Only wallet addresses that were already published on the dark web are sent to mempool.space.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Indicator, WalletCheck, utcnow

log = logging.getLogger(__name__)

# Esplora-compatible public APIs, tried in order. A provider that fails twice in a row is skipped for the run.
PROVIDERS = ["https://mempool.space/api", "https://blockstream.info/api"]
API = PROVIDERS[0]
MAX_CONSECUTIVE_FAILURES = 4  # all providers failing this many wallets in a row -> stop and retry next run


def _fetch(client: httpx.Client, address: str, api: str = API) -> dict:
    data = client.get(f"{api}/address/{address}").raise_for_status().json()
    chain, mem = data.get("chain_stats", {}), data.get("mempool_stats", {})
    received = int(chain.get("funded_txo_sum", 0))
    sent = int(chain.get("spent_txo_sum", 0))
    out = {
        "tx_count": int(chain.get("tx_count", 0)),
        "received_sats": received,
        "sent_sats": sent,
        "balance_sats": received - sent,
        "pending_tx": int(mem.get("tx_count", 0)),
        "last_tx_at": None,
    }
    if out["tx_count"] or out["pending_tx"]:
        txs = client.get(f"{api}/address/{address}/txs").raise_for_status().json()
        times = [t.get("status", {}).get("block_time") for t in txs if t.get("status", {}).get("block_time")]
        if times:
            out["last_tx_at"] = datetime.fromtimestamp(max(times), tz=timezone.utc).replace(tzinfo=None)
    return out


def track_wallets(session: Session, limit: int = 25, delay: float = 1.2, client: httpx.Client | None = None) -> dict:
    """Check the least-recently-checked BTC wallets. Returns run statistics."""
    last_check = (
        select(WalletCheck.indicator_id, func.max(WalletCheck.checked_at).label("at"))
        .group_by(WalletCheck.indicator_id)
        .subquery()
    )
    wallets = session.execute(
        select(Indicator)
        .outerjoin(last_check, last_check.c.indicator_id == Indicator.id)
        .where(Indicator.type == "btc_address")
        .order_by(last_check.c.at.is_not(None), last_check.c.at)  # never-checked first
        .limit(limit)
    ).scalars().all()

    stats = {"checked": 0, "active": 0, "movements": 0, "errors": 0, "stopped_early": False}
    own = client is None
    client = client or httpx.Client(timeout=12, headers={"User-Agent": "onionlens/0.1"})
    strikes = dict.fromkeys(PROVIDERS, 0)
    consecutive = 0
    try:
        for ind in wallets:
            snap = None
            for api in [p for p in PROVIDERS if strikes[p] < 2] or PROVIDERS:
                try:
                    snap = _fetch(client, ind.value, api)
                    strikes[api] = 0
                    break
                except Exception as exc:
                    strikes[api] += 1
                    log.debug("wallet %s lookup via %s failed: %s", ind.value, api, exc)
            if snap is None:
                stats["errors"] += 1
                consecutive += 1
                if consecutive >= MAX_CONSECUTIVE_FAILURES:
                    log.warning("blockchain APIs unavailable - stopping wallet checks until the next run")
                    stats["stopped_early"] = True
                    break
                continue
            consecutive = 0
            prev = session.scalar(
                select(WalletCheck).where(WalletCheck.indicator_id == ind.id).order_by(WalletCheck.checked_at.desc()).limit(1)
            )
            new_tx = max(0, snap["tx_count"] - prev.tx_count) if prev else 0
            new_recv = max(0, snap["received_sats"] - prev.received_sats) if prev else 0
            session.add(WalletCheck(indicator_id=ind.id, checked_at=utcnow(), new_tx=new_tx, new_received_sats=new_recv, **snap))
            stats["checked"] += 1
            stats["active"] += snap["tx_count"] > 0
            stats["movements"] += new_tx > 0
            session.commit()  # short transactions: never hold the SQLite write lock across network calls
            if delay:
                time.sleep(delay)
    finally:
        if own:
            client.close()
    return stats
