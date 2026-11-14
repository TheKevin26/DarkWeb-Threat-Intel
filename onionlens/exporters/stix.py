"""STIX 2.1 bundle export (hand-built JSON, no external dependency).

Only indicators whose raw value is safe to share are exported: masked values (emails, credentials,
cards) stay inside the platform.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from ..models import Indicator
from .attack import describe

NAMESPACE = uuid.UUID("8f1c9a52-2a43-4d6e-9e43-7b0a1c0e6f11")
TLP_AMBER = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"  # TLP:AMBER (STIX 2.1 v1 marking)

_PATTERNS = {
    "ipv4": "[ipv4-addr:value = '{v}']",
    "domain": "[domain-name:value = '{v}']",
    "onion": "[domain-name:value = '{v}']",
    "md5": "[file:hashes.MD5 = '{v}']",
    "sha1": "[file:hashes.'SHA-1' = '{v}']",
    "sha256": "[file:hashes.'SHA-256' = '{v}']",
    "btc_address": "[x-cryptocurrency-wallet:address = '{v}' AND x-cryptocurrency-wallet:currency = 'BTC']",
    "xmr_address": "[x-cryptocurrency-wallet:address = '{v}' AND x-cryptocurrency-wallet:currency = 'XMR']",
    "eth_address": "[x-cryptocurrency-wallet:address = '{v}' AND x-cryptocurrency-wallet:currency = 'ETH']",
}


def _ts(dt: datetime | None = None) -> str:
    dt = dt or datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _id(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NAMESPACE, kind + ':' + key)}"


def build_bundle(indicators: list[Indicator], actors: list[dict] | None = None, techniques: list[str] | None = None) -> dict:
    now = _ts()
    identity_id = _id("identity", "onionlens")
    objects: list[dict] = [
        {
            "type": "identity", "spec_version": "2.1", "id": identity_id, "created": now, "modified": now,
            "name": "OnionLens", "identity_class": "system",
        }
    ]
    for ind in indicators:
        if ind.type == "cve":
            objects.append(
                {
                    "type": "vulnerability", "spec_version": "2.1", "id": _id("vulnerability", ind.value),
                    "created": _ts(ind.first_seen), "modified": _ts(ind.last_seen), "name": ind.value,
                    "created_by_ref": identity_id,
                    "external_references": [{"source_name": "cve", "external_id": ind.value}],
                    "object_marking_refs": [TLP_AMBER],
                }
            )
            continue
        tpl = _PATTERNS.get(ind.type)
        if not tpl:
            continue
        value = ind.value.replace("'", "\\'")
        objects.append(
            {
                "type": "indicator", "spec_version": "2.1", "id": _id("indicator", f"{ind.type}:{ind.value}"),
                "created": _ts(ind.first_seen), "modified": _ts(ind.last_seen),
                "name": f"{ind.type}: {ind.value}", "pattern": tpl.format(v=value), "pattern_type": "stix",
                "valid_from": _ts(ind.first_seen), "indicator_types": ["malicious-activity"],
                "created_by_ref": identity_id, "labels": [ind.type, "dark-web"],
                "description": f"Observed {ind.sightings} time(s) in dark web sources.",
                "object_marking_refs": [TLP_AMBER],
            }
        )

    for tid in techniques or []:
        d = describe(tid)
        objects.append(
            {
                "type": "attack-pattern", "spec_version": "2.1", "id": _id("attack-pattern", tid),
                "created": now, "modified": now, "name": d["name"],
                "external_references": [{"source_name": "mitre-attack", "external_id": tid, "url": d["url"]}],
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": d["tactic"]}],
            }
        )

    for actor in actors or []:
        ta_id = _id("threat-actor", actor["name"])
        objects.append(
            {
                "type": "threat-actor", "spec_version": "2.1", "id": ta_id, "created": now, "modified": now,
                "name": actor["name"], "aliases": actor.get("aliases", []), "threat_actor_types": ["criminal"],
                "created_by_ref": identity_id,
                "description": f"Persona cluster linked across {len(actor.get('sources', []))} source(s) via "
                f"{actor.get('strong_links', 0)} strong identifier(s).",
                "object_marking_refs": [TLP_AMBER],
            }
        )
        for kind, values in actor.get("identifiers", {}).items():
            if kind not in _PATTERNS:
                continue
            for v in values:
                ind_id = _id("indicator", f"{kind}:{v}")
                objects.append(
                    {
                        "type": "relationship", "spec_version": "2.1", "id": _id("relationship", f"{ind_id}>{ta_id}"),
                        "created": now, "modified": now, "relationship_type": "indicates",
                        "source_ref": ind_id, "target_ref": ta_id,
                    }
                )

    known = {o["id"] for o in objects}
    objects = [o for o in objects if o["type"] != "relationship" or o["source_ref"] in known]
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
