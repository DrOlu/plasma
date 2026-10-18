"""Relationship layer over normalized Plasma events.

The declaration lives in graph_edges.json; this module traverses the same
records. Edges are built per call from the events themselves, so the graph
cannot drift from the data. Only two probes are exposed (menu budget):
overview and neighbors.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

ROW_CAP = 25


def _declaration() -> dict:
    path = Path(__file__).resolve().parent / "graph_edges.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"nodes": {}, "edges": []}


def _entities(row: dict) -> list[tuple[str, str]]:
    out = []
    if row.get("host"):
        out.append(("host", row["host"]))
    if row.get("process"):
        out.append(("process", row["process"]))
    if row.get("parent"):
        out.append(("process", row["parent"]))
    if row.get("user"):
        out.append(("user", row["user"]))
    if row.get("dest_ip"):
        out.append(("ip", row["dest_ip"]))
    if row.get("dns_query"):
        out.append(("dns", row["dns_query"]))
    if row.get("file_path"):
        out.append(("file", row["file_path"]))
    if row.get("registry_path"):
        out.append(("registry", row["registry_path"]))
    if row.get("technique"):
        out.append(("technique", row["technique"]))
    return out


def overview(rows: list[dict]) -> dict:
    decl = _declaration()
    counts: dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        for kind, value in _entities(row):
            counts[kind][value] += 1
    nodes = {
        kind: {"count": len(c), "top": dict(c.most_common(10))}
        for kind, c in sorted(counts.items())
    }
    edge_types = Counter()
    for row in rows:
        if row.get("process") and row.get("host"):
            edge_types["runs_on"] += 1
        if row.get("process") and row.get("parent"):
            edge_types["spawned_by"] += 1
        if row.get("dest_ip"):
            edge_types["connects_to"] += 1
        if row.get("dns_query"):
            edge_types["resolves"] += 1
        if row.get("file_path"):
            edge_types["writes_file"] += 1
        if row.get("registry_path"):
            edge_types["writes_registry"] += 1
        if row.get("technique"):
            edge_types["exhibits"] += 1
    return {
        "events": len(rows),
        "nodes": nodes,
        "edges": dict(edge_types.most_common()),
        "declared": {
            "nodes": list(decl.get("nodes", {})),
            "edges": [e.get("type") for e in decl.get("edges", [])],
        },
        "disjoint": decl.get("disjoint", []),
    }


def neighbors(rows: list[dict], node: str) -> dict:
    needle = node.lower()
    hit_rows = []
    for row in rows:
        if any(needle in str(v).lower() for _, v in _entities(row)):
            hit_rows.append(row)
    if not hit_rows:
        return {"node": node, "found": False, "neighbors": {}}
    adjacent: dict[str, Counter] = defaultdict(Counter)
    for row in hit_rows:
        for kind, value in _entities(row):
            if needle not in value.lower():
                adjacent[kind][value] += 1
    by_type = {
        kind: dict(c.most_common(ROW_CAP))
        for kind, c in sorted(adjacent.items())
    }
    return {
        "node": node,
        "found": True,
        "events": len(hit_rows),
        "neighbors": by_type,
        "by_technique": dict(Counter(
            r.get("technique") or "none" for r in hit_rows
        ).most_common()),
        "sample_events": [
            {k: r.get(k) for k in (
                "ts", "host", "kind", "process", "parent", "user",
                "dest_ip", "dns_query", "file_path", "registry_path",
                "technique", "description",
            ) if r.get(k) is not None}
            for r in hit_rows[:10]
        ],
    }
