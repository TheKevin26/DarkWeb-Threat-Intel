"""MISP event export (importable via MISP's "Populate from... > JSON" or the REST API)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from ..models import Indicator

_TYPES = {
    "ipv4": ("ip-dst", "Network activity"),
    "domain": ("domain", "Network activity"),
    "onion": ("domain", "Network activity"),
    "md5": ("md5", "Payload delivery"),
    "sha1": ("sha1", "Payload delivery"),
    "sha256": ("sha256", "Payload delivery"),
    "btc_address": ("btc", "Financial fraud"),
    "xmr_address": ("xmr", "Financial fraud"),
    "cve": ("vulnerability", "External analysis"),
    "jabber": ("jabber-id", "Social network"),
    "telegram": ("text", "Social network"),
    "handle": ("text", "Attribution"),
    "pgp_fingerprint": ("text", "Attribution"),
}


def build_event(indicators: list[Indicator], info: str = "OnionLens dark web indicators") -> dict:
    attrs = []
    for ind in indicators:
        if ind.type not in _TYPES:
            continue
        mtype, cat = _TYPES[ind.type]
        attrs.append(
            {
                "uuid": str(uuid.uuid5(uuid.NAMESPACE_URL, f"onionlens:{ind.type}:{ind.value}")),
                "type": mtype,
                "category": cat,
                "value": ind.value,
                "to_ids": ind.type in {"ipv4", "domain", "md5", "sha1", "sha256"},
                "comment": f"{ind.type}; sightings={ind.sightings}",
                "first_seen": ind.first_seen.replace(tzinfo=timezone.utc).isoformat(),
                "last_seen": ind.last_seen.replace(tzinfo=timezone.utc).isoformat(),
            }
        )
    return {
        "Event": {
            "uuid": str(uuid.uuid4()),
            "info": info,
            "date": datetime.now(timezone.utc).date().isoformat(),
            "threat_level_id": "2",
            "analysis": "1",
            "distribution": "0",
            "Tag": [{"name": "tlp:amber"}, {"name": "osint:source-type=\"dark-web\""}],
            "Attribute": attrs,
        }
    }
