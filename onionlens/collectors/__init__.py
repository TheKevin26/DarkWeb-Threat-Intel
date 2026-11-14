"""Collector registry."""

from __future__ import annotations

from ..config import get_settings, load_yaml
from .ahmia import AhmiaCollector
from .base import Collector, Health, RawItem
from .clearnet import ClearnetCollector
from .demo import DemoCollector
from .leaksites import LeakSiteCollector
from .ransomware_live import RansomwareLiveCollector
from .telegram import TelegramCollector
from .tor_crawler import TorCrawler


def get_collector(name: str, **kwargs) -> Collector:
    if name == "demo":
        return DemoCollector(**kwargs)
    if name == "tor":
        return TorCrawler(**kwargs)
    if name in ("ransomware", "ransomware.live", "ransomware_live"):
        return RansomwareLiveCollector(**kwargs)
    if name == "ahmia":
        if "queries" not in kwargs:
            cfg = load_yaml(get_settings().seeds_file)
            kwargs["queries"] = cfg.get("ahmia_queries") or []
        return AhmiaCollector(**kwargs)
    if name == "leaksites":
        return LeakSiteCollector(**kwargs)
    if name == "telegram":
        return TelegramCollector(**kwargs)
    if name == "clearnet":
        return ClearnetCollector(**kwargs)
    raise ValueError(f"unknown collector {name!r}")


COLLECTORS = ["demo", "ransomware", "leaksites", "tor", "ahmia", "telegram", "clearnet"]
JOBS = ["wallets", "ransomwhere"]  # enrichment jobs (not collectors)

__all__ = ["Collector", "RawItem", "Health", "get_collector", "COLLECTORS", "JOBS"]
