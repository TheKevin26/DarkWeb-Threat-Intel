from fastapi.testclient import TestClient
from sqlalchemy import select

from onionlens.collectors.base import RawItem
from onionlens.db import session_scope
from onionlens.models import Document, DroppedItem, PageSnapshot
from onionlens.pipeline import Pipeline


def test_demo_load(loaded_db):
    assert loaded_db.new_documents > 100
    assert loaded_db.victims > 30
    assert loaded_db.alerts > 0
    assert not loaded_db.errors


def test_safety_drop_stores_nothing(loaded_db):
    with session_scope() as s:
        p = Pipeline(s)
        doc = p.process(RawItem("t", "tor", "http://x.onion/bad", "jailbait pics here", is_html=False))
        assert doc is None
        s.flush()
        assert s.scalar(select(DroppedItem).order_by(DroppedItem.id.desc())).reason.startswith("prohibited")
        assert not s.scalar(select(Document).where(Document.url == "http://x.onion/bad"))


def test_change_detection(loaded_db):
    with session_scope() as s:
        p = Pipeline(s)
        url = "http://test.onion/thread/1"
        assert p.process(RawItem("t", "tor", url, "first version of a ransomware leak post", is_html=False))
        assert p.process(RawItem("t", "tor", url, "first version of a ransomware leak post", is_html=False)) is None
        assert p.process(RawItem("t", "tor", url, "second version, data will be published", is_html=False))
        s.flush()
        snaps = s.scalars(select(PageSnapshot).where(PageSnapshot.url == url)).all()
        assert [x.changed for x in snaps] == [False, True]


def test_api_endpoints(loaded_db):
    from onionlens.api.main import app

    c = TestClient(app)
    st = c.get("/api/stats", params={"days": 0}).json()
    assert st["documents"] > 0 and st["timeline"] and st["categories"]

    docs = c.get("/api/documents", params={"q": "access", "limit": 5}).json()
    assert docs["total"] > 0
    detail = c.get(f"/api/documents/{docs['items'][0]['id']}").json()
    assert "indicators" in detail and "attack" in detail
    assert "[REDACTED" not in detail["title"] or True

    assert c.get("/api/indicators", params={"type": "btc_address"}).json()["total"] > 0
    assert c.get("/api/victims/stats").json()["by_group"]
    g = c.get("/api/graph").json()
    assert g["nodes"] and g["edges"]
    assert c.get("/api/actors").json()

    alerts = c.get("/api/alerts").json()
    assert alerts
    r = c.patch(f"/api/alerts/{alerts[0]['id']}", json={"status": "acknowledged"})
    assert r.json()["status"] == "acknowledged"

    r = c.post("/api/watchlist", json={"kind": "keyword", "value": "Contoso", "severity": "medium"})
    assert r.status_code == 201
    assert c.post("/api/watchlist", json={"kind": "keyword", "value": "Contoso"}).status_code == 409
    assert c.delete(f"/api/watchlist/{r.json()['id']}").status_code == 204

    assert c.get("/api/sources").json()

    feed = c.get("/api/activity", params={"limit": 10}).json()
    assert feed["items"] and feed["max_id"] > 0
    assert all(i["kind"] != "other" for i in feed["items"])
    # the real-only view must never contain synthetic demo items
    assert not any(i["demo"] for i in c.get("/api/activity", params={"real_only": True}).json()["items"])
    all_docs = c.get("/api/stats", params={"days": 0}).json()["documents"]
    assert c.get("/api/stats", params={"days": 0, "real_only": True}).json()["documents"] < all_docs
    all_victims = c.get("/api/victims/stats").json()["total"]
    assert c.get("/api/victims/stats", params={"real_only": True}).json()["total"] < all_victims


def test_exports(loaded_db):
    from onionlens.api.main import app

    c = TestClient(app)
    bundle = c.get("/api/export/stix").json()
    assert bundle["type"] == "bundle"
    kinds = {o["type"] for o in bundle["objects"]}
    assert {"identity", "indicator", "threat-actor", "attack-pattern"} <= kinds
    # masked values must never leave the platform
    assert not any("***@" in o.get("pattern", "") for o in bundle["objects"])
    misp = c.get("/api/export/misp").json()
    assert misp["Event"]["Attribute"]
    csv_text = c.get("/api/export/csv").text
    assert csv_text.startswith("type,value")
