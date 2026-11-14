"""Run a collector or enrichment job by name."""

from __future__ import annotations

from sqlalchemy.orm import Session

from .pipeline import run_collector


def run_job(name: str, session: Session) -> dict:
    if name == "wallets":
        from .enrich.wallets import track_wallets

        return track_wallets(session, limit=60, delay=1.0)
    if name == "ransomwhere":
        from .enrich.ransomwhere import import_ransomwhere

        return import_ransomwhere(session)
    return run_collector(name, session).as_dict()
