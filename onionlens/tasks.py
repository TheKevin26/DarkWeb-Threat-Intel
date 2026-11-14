"""Celery tasks and the periodic collection schedule (``pip install onionlens[queue]``).

worker:  celery -A onionlens.tasks worker -l info
beat:    celery -A onionlens.tasks beat -l info
"""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from .config import get_settings
from .db import init_db, session_scope
from .pipeline import run_collector

settings = get_settings()
celery_app = Celery("onionlens", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.update(task_acks_late=True, worker_prefetch_multiplier=1, task_time_limit=60 * 60)

celery_app.conf.beat_schedule = {
    "ransomware-hourly": {"task": "onionlens.tasks.collect", "schedule": crontab(minute=5), "args": ("ransomware",)},
    "tor-every-6h": {"task": "onionlens.tasks.collect", "schedule": crontab(minute=20, hour="*/6"), "args": ("tor",)},
    "ahmia-daily": {"task": "onionlens.tasks.collect", "schedule": crontab(minute=40, hour=3), "args": ("ahmia",)},
    "telegram-hourly": {"task": "onionlens.tasks.collect", "schedule": crontab(minute=30), "args": ("telegram",)},
    "clearnet-every-2h": {"task": "onionlens.tasks.collect", "schedule": crontab(minute=50, hour="*/2"), "args": ("clearnet",)},
}


@celery_app.task(name="onionlens.tasks.collect")
def collect(source: str) -> dict:
    init_db()
    with session_scope() as s:
        return run_collector(source, s).as_dict()


app = celery_app
