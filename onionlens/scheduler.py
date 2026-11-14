"""Lightweight in-process collection scheduler.

Keeps the dashboard fed without Docker/Celery: a daemon thread runs each configured collector on its
own interval (``ONIONLENS_AUTO_COLLECT="ransomware:1800,tor:21600"``). The first run happens shortly
after startup. In the Docker stack Celery beat does this job instead and auto_collect can be cleared.
"""

from __future__ import annotations

import logging
import threading
import time

from .config import get_settings
from .db import session_scope
from .models import utcnow
from .jobs import run_job

log = logging.getLogger(__name__)

status: dict[str, dict] = {}  # collector -> {last_run, next_run, last_result}
_stop = threading.Event()
_thread: threading.Thread | None = None


def parse_schedule(spec: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        name, _, secs = part.partition(":")
        out[name.strip()] = max(60, int(secs or 1800))
    return out


def _loop(schedule: dict[str, int]) -> None:
    next_run = {name: time.monotonic() + 5 for name in schedule}
    for name in schedule:
        status[name] = {"interval_seconds": schedule[name], "last_run": None, "last_result": None, "running": False}
    while not _stop.is_set():
        now = time.monotonic()
        for name, interval in schedule.items():
            if now < next_run[name]:
                continue
            status[name]["running"] = True
            try:
                with session_scope() as s:
                    result = run_job(name, s)
                log.info("auto-collect %s: %s", name, {k: v for k, v in result.items() if k != "errors"})
            except Exception as exc:  # never let the scheduler die
                log.warning("auto-collect %s failed: %s", name, exc)
                result = {"error": str(exc)[:300]}
            status[name].update(running=False, last_run=utcnow(), last_result=result)
            next_run[name] = time.monotonic() + interval
        _stop.wait(5)


def start() -> None:
    global _thread
    schedule = parse_schedule(get_settings().auto_collect)
    if not schedule or (_thread and _thread.is_alive()):
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, args=(schedule,), name="onionlens-scheduler", daemon=True)
    _thread.start()
    log.info("auto-collect enabled: %s", schedule)


def stop() -> None:
    _stop.set()
