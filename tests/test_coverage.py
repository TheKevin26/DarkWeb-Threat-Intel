import os
import tempfile
from datetime import timedelta
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from typer.testing import CliRunner

from onionlens.collectors.base import RawItem
from onionlens.db import session_scope
from onionlens.models import Victim, VictimSighting, utcnow
from onionlens.pipeline import Pipeline


def test_cross_source_matching_and_coverage(loaded_db):
    now = utcnow()
    feed_item = lambda name, domain: RawItem(  # noqa: E731
        "ransomware.live", "api", f"ransomware.live://qilin/{name}", f"Ransomware group qilin listed victim {name}",
        is_html=False, victim={"name": name, "group_name": "qilin", "country": "DE", "sector": "Logistics",
                               "domain": domain, "discovered_at": now - timedelta(days=1)})
    with session_scope() as s:
        p = Pipeline(s)
        p.process(feed_item("Northwind Logistics GmbH", "northwind.example.de"))
        p.process(feed_item("Feed Only Corp", None))
        page = RawItem("qilin leak site", "tor", "http://qilinexample.onion/", "<html>" + "x" * 400 + "</html>",
                       victims=[
                           {"name": "NORTHWIND LOGISTICS", "group_name": "qilin", "domain": None, "country": None,
                            "sector": None, "discovered_at": now, "description": None},
                           {"name": "Crawl Only Ltd", "group_name": "qilin", "domain": "crawlonly.example.com",
                            "country": None, "sector": "Retail", "discovered_at": now, "description": None},
                       ])
        p.process(page)
        s.flush()
        nw = s.scalar(select(Victim).where(Victim.name == "Northwind Logistics GmbH"))
        assert s.scalar(select(func.count()).select_from(VictimSighting).where(VictimSighting.victim_id == nw.id)) == 2
        assert s.scalar(select(func.count()).select_from(Victim).where(Victim.group_name == "qilin")) == 3

    from onionlens.api.main import app

    cov = TestClient(app).get("/api/coverage", params={"days": 7}).json()
    row = next(g for g in cov["groups"] if g["group"] == "qilin")
    assert (row["ours"], row["theirs"], row["both"], row["only_ours"], row["only_theirs"]) == (2, 2, 1, 1, 1)
    assert row["state"] == "parsed"


def test_purge_demo_keeps_real_data():
    from onionlens.cli import app as cli
    from onionlens.config import get_settings

    tmp = Path(tempfile.mkdtemp()) / "purge.db"
    old = os.environ["ONIONLENS_DATABASE_URL"]
    runner = CliRunner()
    try:
        assert runner.invoke(cli, ["--db", str(tmp), "collect", "demo", "--limit", "25"]).exit_code == 0
        with session_scope() as s:  # one real victim that must survive
            Pipeline(s).process(RawItem("ransomware.live", "api", "ransomware.live://g/real", "real victim posting",
                                        is_html=False, victim={"name": "Real Victim", "group_name": "g"}))
        r = runner.invoke(cli, ["--db", str(tmp), "purge-demo", "--yes"])
        assert r.exit_code == 0, r.output
        with session_scope() as s:
            names = list(s.scalars(select(Victim.name)))
        assert names == ["Real Victim"]
    finally:
        os.environ["ONIONLENS_DATABASE_URL"] = old
        get_settings.cache_clear()
