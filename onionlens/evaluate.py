"""Classifier evaluation: accuracy, per-class precision/recall/F1 and a confusion matrix.

Two numbers are reported:
1. The labelled evaluation set (eval/labeled_posts.jsonl) - realistic, varied posts covering every category
   plus hard negatives (news, ads, chit-chat). The classifier is never tuned on this file.
2. Real leak-site pages collected over Tor - every one should be classified as ransomware.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .config import ROOT
from .processing.classifier import LABELS, classify

EVAL_FILE = ROOT / "eval" / "labeled_posts.jsonl"


def load(path: Path = EVAL_FILE) -> list[dict]:
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def split(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    """Deterministic stratified 50/50 split: (dev, test). Only dev errors may guide classifier changes."""
    dev, test, seen = [], [], Counter()
    for r in rows:
        (dev if seen[r["label"]] % 2 == 0 else test).append(r)
        seen[r["label"]] += 1
    return dev, test


def evaluate(rows: list[dict], engine: str = "keyword") -> dict:
    labels = sorted({r["label"] for r in rows})
    pairs = [(r["label"], classify(r["text"], engine).category) for r in rows]
    confusion = Counter(pairs)
    per = {}
    for c in labels:
        tp = confusion[(c, c)]
        fp = sum(v for (g, p), v in confusion.items() if p == c and g != c)
        fn = sum(v for (g, p), v in confusion.items() if g == c and p != c)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        per[c] = {"precision": prec, "recall": rec, "f1": f1, "support": tp + fn}
    acc = sum(g == p for g, p in pairs) / len(pairs)
    errors = [{"text": r["text"], "gold": g, "pred": p} for r, (g, p) in zip(rows, pairs) if g != p]
    return {
        "n": len(rows), "accuracy": acc, "macro_f1": sum(v["f1"] for v in per.values()) / len(per),
        "per_class": per, "labels": labels, "confusion": {f"{g}|{p}": v for (g, p), v in confusion.items()},
        "errors": errors,
    }


def real_leak_pages() -> dict:
    """Share of real Tor-collected leak-site pages classified as ransomware."""
    from sqlalchemy import select

    from .db import session_scope
    from .models import Document, Source

    with session_scope() as s:
        docs = s.execute(
            select(Document.title, Document.text).join(Source)
            .where(Source.kind == "tor", Source.name.like("% leak site"), ~Source.name.like("%[demo]%"))
        ).all()
    usable = [(t, x) for t, x in docs if len(x or "") >= 300]  # skip JavaScript-only shells
    hits = sum(classify(f"{t or ''}\n{x}").category == "ransomware" for t, x in usable)
    return {"pages": len(usable), "ransomware": hits, "rate": hits / len(usable) if usable else None}


def to_markdown(r: dict, real: dict | None = None) -> str:
    out = [f"**Labelled set:** {r['n']} posts · **accuracy {r['accuracy']:.0%}** · macro-F1 {r['macro_f1']:.2f}", ""]
    out += ["| Category | Precision | Recall | F1 | Posts |", "|---|---:|---:|---:|---:|"]
    for c in r["labels"]:
        v = r["per_class"][c]
        out.append(f"| {LABELS.get(c, c)} | {v['precision']:.2f} | {v['recall']:.2f} | {v['f1']:.2f} | {v['support']} |")
    out += ["", "Confusion matrix (rows = true label, columns = predicted):", ""]
    short = {c: c.split("_")[0][:7] for c in r["labels"]}
    out.append("| true \\ pred | " + " | ".join(short[c] for c in r["labels"]) + " |")
    out.append("|---|" + "---:|" * len(r["labels"]))
    for g in r["labels"]:
        out.append(f"| {short[g]} | " + " | ".join(str(r["confusion"].get(f"{g}|{p}", 0) or "·") for p in r["labels"]) + " |")
    if real and real["pages"]:
        out += ["", f"**Real leak-site pages (collected over Tor), text-only classifier:** {real['ransomware']}/{real['pages']} "
                f"recognised as ransomware ({real['rate']:.0%}). Leak-site front pages are mostly lists of company names "
                "with little extortion vocabulary, so the pipeline labels pages from known leak sites by *source* instead "
                "of relying on the text classifier for them."]
    return "\n".join(out)
