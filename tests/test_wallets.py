import httpx
from sqlalchemy import select

from onionlens.db import session_scope
from onionlens.enrich.wallets import track_wallets
from onionlens.models import Indicator, WalletCheck


def _client(tx_count: int, received: int) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/txs"):
            return httpx.Response(200, json=[{"status": {"block_time": 1_760_000_000}}])
        return httpx.Response(200, json={
            "chain_stats": {"funded_txo_sum": received, "spent_txo_sum": 0, "tx_count": tx_count},
            "mempool_stats": {"tx_count": 0},
        })

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_wallet_movement_detected(loaded_db):
    with session_scope() as s:
        n = s.scalar(select(Indicator).where(Indicator.type == "btc_address").limit(1))
        assert n is not None
        first = track_wallets(s, limit=500, delay=0, client=_client(2, 50_000))
        assert first["checked"] > 0 and first["movements"] == 0  # first sight is a baseline, not a movement
        second = track_wallets(s, limit=500, delay=0, client=_client(5, 150_000))
        assert second["movements"] == second["checked"]
        last = s.scalar(select(WalletCheck).where(WalletCheck.indicator_id == n.id).order_by(WalletCheck.id.desc()).limit(1))
        assert last.new_tx == 3 and last.new_received_sats == 100_000 and last.last_tx_at is not None

    from fastapi.testclient import TestClient

    from onionlens.api.main import app

    c = TestClient(app)
    feed = c.get("/api/activity", params={"limit": 200}).json()["items"]
    assert any(i["kind"] == "transaction" for i in feed)
    assert c.get("/api/wallets").json()["items"][0]["tx_count"] == 5
    assert c.get(f"/api/indicators/{n.id}").json()["on_chain"][0]["new_tx"] == 3


def test_provider_fallback_and_circuit_breaker(loaded_db):
    def flaky(request: httpx.Request) -> httpx.Response:
        if request.url.host == "mempool.space":
            return httpx.Response(503)
        if request.url.path.endswith("/txs"):
            return httpx.Response(200, json=[])
        return httpx.Response(200, json={"chain_stats": {"tx_count": 0}, "mempool_stats": {}})

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out", request=request)

    with session_scope() as s:
        ok = track_wallets(s, limit=5, delay=0, client=httpx.Client(transport=httpx.MockTransport(flaky)))
        assert ok["checked"] == 5 and ok["errors"] == 0  # fell back to the second provider
        dead = track_wallets(s, limit=50, delay=0, client=httpx.Client(transport=httpx.MockTransport(down)))
        assert dead["stopped_early"] and dead["errors"] == 4 and dead["checked"] == 0
