"""Bounded local summaries for agent context.

An agent should not have to ingest thousands of JSONL rows to understand a
host. This module reduces a bounded tail into a compact digest: process
first/last seen, parent→child counts, rare command lines, per-user and
per-host counts, score bands and event sources.

The output is deliberately small and lossy. It is a map, not the territory;
every count says what it was computed from and what it dropped.
"""

from __future__ import annotations

from collections import Counter

from .query import _load_rows, _row_time, parse_time

DEFAULT_LIMIT = 20
MAX_LIMIT = 100


def _basename(value) -> str:
    return str(value or "").replace("\\", "/").rsplit("/", 1)[-1]


def _band(score) -> str:
    try:
        value = float(score or 0)
    except (TypeError, ValueError):
        value = 0.0
    if value >= 0.9:
        return "critical"
    if value >= 0.7:
        return "high"
    if value >= 0.4:
        return "medium"
    return "low"


def _norm_cmdline(text) -> str:
    return " ".join(str(text or "").split())[:300]


def summarize(events_path, since=None, max_rows: int = 5000,
              limit: int = DEFAULT_LIMIT, rare_max: int = 2) -> dict:
    """Return a bounded digest of the event tail."""
    rows = _load_rows(events_path, max_rows=max_rows)
    since_dt = parse_time(since) if since else None
    if since_dt:
        rows = [row for row in rows
                if (_row_time(row) or since_dt) >= since_dt]
    limit = max(1, min(int(limit), MAX_LIMIT))

    processes = {}
    parent_child = Counter()
    users = Counter()
    hosts = Counter()
    sources = Counter()
    kinds = Counter()
    bands = Counter()
    cmd_counts = Counter()
    cmd_process = {}

    for row in rows:
        process = _basename(row.get("process")) or None
        parent = _basename(row.get("parent")) or None
        stamp = _row_time(row)
        if process:
            entry = processes.setdefault(process, {
                "process": process, "count": 0, "first_seen": None,
                "last_seen": None, "users": set(), "parents": set(),
            })
            entry["count"] += 1
            if stamp:
                if entry["first_seen"] is None or stamp < entry["first_seen"]:
                    entry["first_seen"] = stamp
                if entry["last_seen"] is None or stamp > entry["last_seen"]:
                    entry["last_seen"] = stamp
            if row.get("user"):
                entry["users"].add(str(row["user"]))
            if parent:
                entry["parents"].add(parent)
        if parent and process:
            parent_child[(parent, process)] += 1
        if row.get("user"):
            users[str(row["user"])] += 1
        if row.get("host"):
            hosts[str(row["host"])] += 1
        if row.get("source"):
            sources[str(row["source"])] += 1
        if row.get("kind"):
            kinds[str(row["kind"])] += 1
        bands[_band(row.get("score"))] += 1
        cmd = _norm_cmdline(row.get("cmdline"))
        if cmd:
            cmd_counts[cmd] += 1
            cmd_process.setdefault(cmd, process)

    top_processes = []
    for entry in sorted(processes.values(),
                        key=lambda e: e["count"], reverse=True)[:limit]:
        top_processes.append({
            **entry,
            "first_seen": entry["first_seen"].isoformat()
            if entry["first_seen"] else None,
            "last_seen": entry["last_seen"].isoformat()
            if entry["last_seen"] else None,
            "users": sorted(entry["users"])[:10],
            "parents": sorted(entry["parents"])[:10],
        })
    rare = [
        {"cmdline": cmd, "process": cmd_process.get(cmd), "count": count}
        for cmd, count in sorted(cmd_counts.items(),
                                 key=lambda item: (item[1], item[0]))
        if count <= max(1, int(rare_max))
    ][:limit]
    return {
        "ok": True,
        "checked": len(rows),
        "max_rows": max_rows,
        "since": since_dt.isoformat().replace("+00:00", "Z") if since_dt else None,
        "counts": {
            "processes": len(processes),
            "users": len(users),
            "hosts": len(hosts),
            "command_lines": len(cmd_counts),
        },
        "score_bands": [{"band": key, "count": bands[key]}
                        for key in ("critical", "high", "medium", "low")
                        if bands[key]],
        "sources": [{"value": key, "count": value}
                    for key, value in sources.most_common(limit)],
        "kinds": [{"value": key, "count": value}
                  for key, value in kinds.most_common(limit)],
        "top_processes": top_processes,
        "parent_child": [
            {"parent": parent, "process": process, "count": count}
            for (parent, process), count in parent_child.most_common(limit)
        ],
        "top_users": [{"user": key, "count": value}
                      for key, value in users.most_common(limit)],
        "hosts": [{"host": key, "count": value}
                  for key, value in hosts.most_common(limit)],
        "rare_command_lines": rare,
        "truncated": len(processes) > limit or len(parent_child) > limit
        or len(cmd_counts) > limit,
    }
