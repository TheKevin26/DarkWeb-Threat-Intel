"""Public Telegram channel collector (Telethon). Reads only public channels listed in seeds.yaml.

Requires ``pip install onionlens[telegram]`` and ONIONLENS_TELEGRAM_API_ID / _API_HASH from
https://my.telegram.org. The first run asks for a phone login and stores a local session file.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator

from ..config import ROOT, get_settings, load_yaml
from .base import Collector, Event, Health, RawItem

log = logging.getLogger(__name__)


class TelegramCollector(Collector):
    name = "telegram"

    def __init__(self, channels: list[str] | None = None, limit: int = 100):
        s = get_settings()
        self.settings = s
        self.channels = channels if channels is not None else (load_yaml(s.seeds_file).get("telegram_channels") or [])
        self.limit = limit

    def collect(self) -> Iterator[Event]:
        s = self.settings
        if not (s.telegram_api_id and s.telegram_api_hash):
            log.warning("Telegram API credentials not configured - skipping")
            return
        try:
            from telethon.sync import TelegramClient
        except ImportError:
            log.warning("telethon not installed (pip install onionlens[telegram]) - skipping")
            return
        session = str(ROOT / "data" / "telegram")
        with TelegramClient(session, s.telegram_api_id, s.telegram_api_hash) as client:
            for ch in self.channels:
                name = f"telegram:{ch}"
                url = f"https://t.me/{ch}"
                try:
                    entity = client.get_entity(ch)
                    msgs = client.get_messages(entity, limit=self.limit)
                except Exception as exc:
                    yield Health(name, "telegram", url, ok=False, error=str(exc)[:300])
                    continue
                yield Health(name, "telegram", url, ok=True)
                for m in msgs:
                    if not m.message:
                        continue
                    yield RawItem(
                        source_name=name,
                        source_kind="telegram",
                        source_url=url,
                        url=f"{url}/{m.id}",
                        content=m.message,
                        is_html=False,
                        author=ch,
                        published_at=m.date.replace(tzinfo=None) if m.date else None,
                    )
