"""Actor linking.

Builds a co-occurrence graph of identity-bearing indicators (handles, wallets, PGP keys, jabber, tox,
telegram). Two indicators are connected when they appear in the same document; the edge weight is
the number of shared documents. Connected components become *actor clusters*: e.g. a vendor handle
on forum A, a PGP fingerprint on market B and a BTC wallet on paste C that all resolve to one operator.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from itertools import combinations

import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..models import Document, Indicator
from .ioc import LINKING_TYPES

# Identifiers strong enough on their own to merge two personas.
STRONG_TYPES = {"pgp_fingerprint", "btc_address", "xmr_address", "eth_address", "jabber", "tox_id"}


def build_graph(session: Session, min_weight: int = 1, max_hub_docs: int = 200) -> nx.Graph:
    docs = session.scalars(
        select(Document).options(selectinload(Document.indicators), selectinload(Document.source))
    ).all()
    g = nx.Graph()
    for doc in docs:
        inds = [i for i in doc.indicators if i.type in LINKING_TYPES and i.sightings <= max_hub_docs]
        for ind in inds:
            node = f"i{ind.id}"
            if node not in g:
                g.add_node(node, label=ind.value, type=ind.type, docs=set(), sources=set(), categories=Counter())
            g.nodes[node]["docs"].add(doc.id)
            g.nodes[node]["sources"].add(doc.source.name)
            g.nodes[node]["categories"][doc.category] += 1
        for a, b in combinations(sorted({f"i{i.id}" for i in inds}), 2):
            if g.has_edge(a, b):
                g[a][b]["weight"] += 1
            else:
                g.add_edge(a, b, weight=1)
    if min_weight > 1:
        g.remove_edges_from([(a, b) for a, b, w in g.edges(data="weight") if w < min_weight])
        g.remove_nodes_from([n for n in list(g.nodes) if g.degree(n) == 0])
    return g


def actor_clusters(g: nx.Graph) -> list[dict]:
    clusters = []
    for idx, comp in enumerate(sorted(nx.connected_components(g), key=len, reverse=True)):
        if len(comp) < 2:
            continue
        nodes = [g.nodes[n] for n in comp]
        by_type: dict[str, list[str]] = defaultdict(list)
        docs: set[int] = set()
        sources: set[str] = set()
        cats: Counter = Counter()
        for n in nodes:
            by_type[n["type"]].append(n["label"])
            docs |= n["docs"]
            sources |= n["sources"]
            cats.update(n["categories"])
        handles = sorted(by_type.get("handle", []), key=lambda h: -len(g.nodes[_find(g, comp, h)]["docs"]))
        name = handles[0] if handles else next(iter(by_type.values()))[0]
        clusters.append(
            {
                "id": idx,
                "name": name,
                "aliases": handles[1:],
                "identifiers": dict(by_type),
                "document_count": len(docs),
                "document_ids": sorted(docs)[:100],
                "sources": sorted(sources),
                "cross_site": len(sources) > 1,
                "top_categories": [c for c, _ in cats.most_common(3)],
                "strong_links": sum(len(v) for k, v in by_type.items() if k in STRONG_TYPES),
            }
        )
    return clusters


def _find(g: nx.Graph, comp: set, label: str) -> str:
    for n in comp:
        if g.nodes[n]["label"] == label:
            return n
    raise KeyError(label)


def graph_to_cytoscape(g: nx.Graph, limit: int = 400) -> dict:
    """Serialize the top-N nodes (by degree) for Cytoscape.js."""
    comp_of = {}
    for idx, comp in enumerate(sorted(nx.connected_components(g), key=len, reverse=True)):
        for n in comp:
            comp_of[n] = idx
    top = sorted(g.nodes, key=lambda n: (g.degree(n), len(g.nodes[n]["docs"])), reverse=True)[:limit]
    keep = set(top)
    nodes = [
        {
            "data": {
                "id": n,
                "label": g.nodes[n]["label"],
                "type": g.nodes[n]["type"],
                "docs": len(g.nodes[n]["docs"]),
                "doc_ids": sorted(g.nodes[n]["docs"])[:50],
                "sources": sorted(g.nodes[n]["sources"]),
                "cluster": comp_of[n],
                "degree": g.degree(n),
            }
        }
        for n in top
    ]
    edges = [
        {"data": {"id": f"{a}-{b}", "source": a, "target": b, "weight": w}}
        for a, b, w in g.edges(data="weight")
        if a in keep and b in keep
    ]
    return {"nodes": nodes, "edges": edges}


def indicator_neighbors(session: Session, indicator_id: int) -> list[Indicator]:
    """Indicators that co-occur with the given one (pivoting)."""
    ind = session.get(Indicator, indicator_id)
    if not ind:
        return []
    out: dict[int, Indicator] = {}
    for doc in ind.documents:
        for other in doc.indicators:
            if other.id != ind.id:
                out[other.id] = other
    return list(out.values())
