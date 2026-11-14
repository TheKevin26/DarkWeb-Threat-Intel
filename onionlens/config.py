"""Runtime configuration. Every value can be overridden with an ONIONLENS_* environment variable."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ONIONLENS_", env_file=".env", extra="ignore")

    # Storage
    database_url: str = f"sqlite:///{(ROOT / 'data' / 'onionlens.db').as_posix()}"
    raw_dir: Path = ROOT / "data" / "raw"
    opensearch_url: str | None = None
    redis_url: str = "redis://localhost:6379/0"

    # Tor / crawling
    tor_proxy: str = "socks5://127.0.0.1:9050"
    # tried in order when tor_proxy is unreachable (9150 = Tor Browser)
    tor_fallback_proxies: str = "socks5://127.0.0.1:9150"
    tor_check_url: str = "https://check.torproject.org/api/ip"
    crawl_max_pages: int = 50
    crawl_max_depth: int = 2
    crawl_delay_seconds: float = 3.0
    crawl_timeout_seconds: float = 60.0
    crawl_max_bytes: int = 2_000_000
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"

    # Config files
    seeds_file: Path = ROOT / "config" / "seeds.yaml"
    watchlist_file: Path = ROOT / "config" / "watchlist.yaml"

    # Analysis
    classifier: str = "keyword"  # keyword | zeroshot
    ner: str = "auto"  # auto | spacy | regex
    translate: bool = False

    # Telegram (optional)
    telegram_api_id: int | None = None
    telegram_api_hash: str | None = None

    # Background collection inside the API process: "collector:seconds,collector:seconds". Empty disables.
    auto_collect: str = "ransomware:1800,wallets:3600,leaksites:21600,ransomwhere:86400"
    # start the bundled/installed tor client automatically when the server starts
    tor_autostart: bool = True

    # API
    api_key: str | None = None  # if set, required in the X-API-Key header
    cors_origins: str = "http://localhost:5173"


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.raw_dir.mkdir(parents=True, exist_ok=True)
    if s.database_url.startswith("sqlite:///"):
        Path(s.database_url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    return s


def load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}
