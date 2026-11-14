"""Command-line interface: ``onionlens --help``."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import typer
from sqlalchemy import select

from .collectors import COLLECTORS
from .db import init_db, session_scope
from .pipeline import run_collector, sync_watchlist_from_file

app = typer.Typer(add_completion=False, help="OnionLens - dark web threat intelligence platform")


@app.callback()
def _main(
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    db: str = typer.Option(None, "--db", help="use another SQLite file, e.g. data/demo.db for a demo-only instance"),
) -> None:
    if db:
        import os

        from .config import get_settings

        os.environ["ONIONLENS_DATABASE_URL"] = "sqlite:///" + Path(db).resolve().as_posix()
        get_settings.cache_clear()
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@app.command()
def init() -> None:
    """Create database tables and load config/watchlist.yaml."""
    init_db()
    with session_scope() as s:
        n = sync_watchlist_from_file(s)
    typer.echo(f"database ready; {n} watchlist item(s) added")


@app.command()
def collect(
    source: str = typer.Argument(..., help=f"one of: {', '.join(COLLECTORS)}"),
    limit: int = typer.Option(None, help="max items (ransomware) / documents (demo)"),
) -> None:
    """Run a collector through the full analysis pipeline."""
    init_db()
    kwargs = {}
    if limit:
        kwargs = {"documents": limit} if source == "demo" else {"limit": limit}
    with session_scope() as s:
        stats = run_collector(source, s, **kwargs)
    typer.echo(json.dumps(stats.as_dict(), indent=2, default=str))


@app.command()
def demo() -> None:
    """Load the synthetic demo dataset (no Tor required)."""
    collect("demo", None)


@app.command()
def export(fmt: str = typer.Argument("stix", help="stix | misp | csv"), out: Path = typer.Option(Path("export"))) -> None:
    """Export indicators to STIX 2.1, MISP JSON or CSV."""
    from .api.main import build_export

    init_db()
    with session_scope() as s:
        content, ext = build_export(s, fmt)
    path = out.with_suffix(ext)
    path.write_text(content, encoding="utf-8")
    typer.echo(f"wrote {path}")


@app.command()
def stats() -> None:
    """Print corpus statistics."""
    from sqlalchemy import func

    from .models import Alert, Document, Indicator, Source, Victim

    init_db()
    with session_scope() as s:
        for model in (Source, Document, Indicator, Victim, Alert):
            typer.echo(f"{model.__tablename__:12} {s.scalar(select(func.count()).select_from(model))}")


@app.command()
def evaluate(out: Path = typer.Option(Path("eval/RESULTS.md"))) -> None:
    """Measure classifier accuracy on the labelled set (held-out test half) and real leak-site pages."""
    from . import evaluate as ev

    rows = ev.load()
    _, test = ev.split(rows)
    init_db()
    try:
        real = ev.real_leak_pages()
    except Exception:
        real = None
    body = ["# Classifier evaluation", "",
            "Method: 98 hand-labelled posts, split 50/50 (stratified). Classifier changes were guided only by the",
            "*dev* half; the numbers below are on the untouched *test* half.", "",
            "## Held-out test set", "", ev.to_markdown(ev.evaluate(test), real), "",
            "## Full labelled set (dev + test, for reference)", "", ev.to_markdown(ev.evaluate(rows))]
    out.write_text("\n".join(body) + "\n", encoding="utf-8")
    r = ev.evaluate(test)
    typer.echo(f"test accuracy {r['accuracy']:.1%}  macro-F1 {r['macro_f1']:.2f}  (n={r['n']}) -> {out}")
    if real and real["pages"]:
        typer.echo(f"real leak-site pages classified as ransomware: {real['ransomware']}/{real['pages']}")


@app.command("reparse-leaks")
def reparse_leaks() -> None:
    """Re-extract victims from stored leak-site pages (no network) - run after improving the parsers."""
    from .pipeline import backfill_sightings, reparse_leak_pages

    init_db()
    with session_scope() as s:
        backfill_sightings(s)
        typer.echo(json.dumps(reparse_leak_pages(s), indent=2))


@app.command("purge-demo")
def purge_demo(yes: bool = typer.Option(False, "--yes", help="skip the confirmation prompt")) -> None:
    """Delete the synthetic [demo] dataset, keeping all real data. Reload it any time with `onionlens demo`."""
    from sqlalchemy import delete

    from .models import Document, Indicator, PageSnapshot, Source, Victim, WalletCheck, document_indicators

    init_db()
    with session_scope() as s:
        demo_sources = list(s.scalars(select(Source.id).where(Source.name.like("%[demo]%"))))
        if not demo_sources:
            typer.echo("no demo data found")
            return
        doc_ids = list(s.scalars(select(Document.id).where(Document.source_id.in_(demo_sources))))
        urls = list(s.scalars(select(Document.url).where(Document.id.in_(doc_ids))))
        ind_ids = set(s.scalars(select(document_indicators.c.indicator_id).where(document_indicators.c.document_id.in_(doc_ids))))
        if not yes:
            typer.confirm(f"Delete {len(demo_sources)} demo sources and {len(doc_ids)} demo documents?", abort=True)
        s.execute(delete(Victim).where(Victim.source_id.in_(demo_sources)))
        for i in range(0, len(doc_ids), 500):
            s.execute(delete(Document).where(Document.id.in_(doc_ids[i:i + 500])))
        for i in range(0, len(urls), 500):
            s.execute(delete(PageSnapshot).where(PageSnapshot.url.in_(urls[i:i + 500])))
        s.execute(delete(Source).where(Source.id.in_(demo_sources)))
        s.flush()
        # indicators that only ever appeared in demo documents (keeps imported real wallets etc.)
        still_used = set(s.scalars(select(document_indicators.c.indicator_id).where(document_indicators.c.indicator_id.in_(ind_ids))))
        orphans = [i for i in ind_ids if i not in still_used]
        for i in range(0, len(orphans), 500):
            chunk = orphans[i:i + 500]
            s.execute(delete(WalletCheck).where(WalletCheck.indicator_id.in_(chunk)))
            s.execute(delete(Indicator).where(Indicator.id.in_(chunk)))
    typer.echo(f"removed {len(demo_sources)} demo sources, {len(doc_ids)} documents, {len(orphans)} indicators")


@app.command("tor-check")
def tor_check() -> None:
    """Check whether a Tor SOCKS proxy is reachable (9050, then Tor Browser's 9150)."""
    from .collectors.tor_crawler import find_tor

    r = find_tor()
    if r["available"]:
        typer.echo(f"Tor OK via {r['proxy']} (exit IP {r['exit_ip']})")
    else:
        typer.echo(f"Tor NOT reachable. Tried: {', '.join(r['tried'])}")
        typer.echo(r["error"])
        raise typer.Exit(1)


@app.command("tor-start")
def tor_start() -> None:
    """Start a headless Tor client (from Tor Browser or PATH) on 127.0.0.1:9050."""
    from .tor_manager import start_tor

    typer.echo(json.dumps(start_tor(), indent=2))


@app.command()
def ransomwhere(limit: int = 400) -> None:
    """Import known ransomware payment wallets (ransomwhe.re) for blockchain tracking."""
    from .enrich.ransomwhere import import_ransomwhere

    init_db()
    with session_scope() as s:
        typer.echo(json.dumps(import_ransomwhere(s, limit=limit), indent=2))


@app.command()
def wallets(limit: int = 25) -> None:
    """Check BTC wallets seen in dark web posts against the public blockchain (mempool.space)."""
    from .enrich.wallets import track_wallets

    init_db()
    with session_scope() as s:
        typer.echo(json.dumps(track_wallets(s, limit=limit), indent=2))


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8000, reload: bool = False) -> None:
    """Start the API + dashboard."""
    import uvicorn

    init_db()
    uvicorn.run("onionlens.api.main:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    app()
