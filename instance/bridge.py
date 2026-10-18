"""Plasma frozen-instance bridge.

The engine selects a probe from needle_menu.json; this file executes it
against the endpoint's local normalized event store. Contract:

* every record passes through models.PlasmaEvent before it reaches a probe;
* results are digests (<= ROW_CAP rows) plus counts — never a raw dump;
* errors are data ({"error": ...}), never exceptions across the boundary;
* the event path comes from PLASMA_EVENTS, then the instance directory,
  then the packaged samples, then C:\\ProgramData\\Plasma\\data\\events.jsonl.
* read-only: this bridge performs no writes, no response actions.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

# A frozen bundle is immutable: never write bytecode caches into it.
sys.dont_write_bytecode = True

from models import PlasmaEvent

ROW_CAP = 25
EVENTS_ENV = "PLASMA_EVENTS"
VALIDATION = {"parsed": 0, "failed": 0, "errors": []}

DIGEST_FIELDS = (
    "ts", "host", "source", "kind", "event_id", "severity", "user",
    "process", "pid", "parent", "cmdline", "dest_ip", "dest_port",
    "dns_query", "file_path", "file_hash", "registry_path", "technique",
    "alert_id", "score", "action", "description",
)


def _candidates():
    here = Path(__file__).resolve().parent
    return [
        here / "events.jsonl",
        here.parent / "samples" / "plasma_events.jsonl",
        Path(r"C:\ProgramData\Plasma\data\events.jsonl"),
        Path("/var/lib/plasma/events.jsonl"),
    ]


def source_path() -> str:
    env = os.environ.get(EVENTS_ENV)
    if env:
        return env
    for candidate in _candidates():
        if candidate.exists():
            return str(candidate)
    return str(_candidates()[0])


def _load():
    """Parse and validate every event. Unreadable source is data, not a raise."""
    path = source_path()
    if not Path(path).exists():
        return None, {"error": f"event store not found: {path}"}
    rows = []
    VALIDATION["parsed"] = VALIDATION["failed"] = 0
    VALIDATION["errors"] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError as exc:
                    VALIDATION["failed"] += 1
                    VALIDATION["errors"].append(f"json: {exc}"[:200])
                    continue
                try:
                    row = PlasmaEvent(**raw).model_dump(mode="json")
                    rows.append(row)
                    VALIDATION["parsed"] += 1
                except Exception as exc:  # noqa: BLE001 - errors are data
                    VALIDATION["failed"] += 1
                    if len(VALIDATION["errors"]) < 5:
                        VALIDATION["errors"].append(str(exc)[:200])
    except OSError as exc:
        return None, {"error": f"event store unreadable: {exc}"[:200]}
    return rows, None


def coverage() -> dict:
    rows, err = _load()
    if err:
        return err
    total = VALIDATION["parsed"] + VALIDATION["failed"]
    pct = round(100.0 * VALIDATION["parsed"] / total, 2) if total else 0.0
    return {
        "total": total,
        "parsed": VALIDATION["parsed"],
        "failed": VALIDATION["failed"],
        "coverage_pct": pct,
        "errors": VALIDATION["errors"],
    }


def _digest(row: dict) -> dict:
    return {k: row.get(k) for k in DIGEST_FIELDS if row.get(k) is not None}


def _sort_desc(rows):
    return sorted(rows, key=lambda r: str(r.get("ts") or ""), reverse=True)


def _cap(rows):
    return [_digest(r) for r in rows[:ROW_CAP]]


def _match(value, needle):
    return needle.lower() in str(value or "").lower()


def _filter(rows, **criteria):
    out = []
    for row in rows:
        ok = True
        for field, needle in criteria.items():
            if needle in (None, "", 0):
                continue
            if not _match(row.get(field), str(needle)):
                ok = False
                break
        if ok:
            out.append(row)
    return out


# --------------------------------------------------------------------------
# Probes (read-only)
# --------------------------------------------------------------------------

def plasma_overview() -> dict:
    rows, err = _load()
    if err:
        return err
    kinds = Counter(r["kind"] for r in rows)
    severities = Counter(r["severity"] for r in rows)
    hosts = Counter(r["host"] for r in rows)
    sources = Counter(r["source"] for r in rows)
    alerts = [r for r in rows if r["kind"] == "alert"]
    return {
        "events": len(rows),
        "alerts": len(alerts),
        "killed": sum(1 for r in alerts if r.get("action") == "killed"),
        "by_kind": dict(kinds.most_common()),
        "by_severity": dict(severities.most_common()),
        "by_host": dict(hosts.most_common(ROW_CAP)),
        "by_source": dict(sources.most_common()),
        "techniques": dict(Counter(
            r["technique"] for r in rows if r.get("technique")
        ).most_common(ROW_CAP)),
        "coverage_pct": coverage()["coverage_pct"],
    }


def plasma_recent(limit: int = 10, host: str = "") -> dict:
    rows, err = _load()
    if err:
        return err
    try:
        limit = max(1, min(int(limit), ROW_CAP))
    except (TypeError, ValueError):
        limit = 10
    if host:
        rows = [r for r in rows if _match(r["host"], host)]
    ordered = _sort_desc(rows)
    return {"returned": min(limit, len(ordered)), "events": _cap(ordered[:limit])}


def plasma_alerts(severity: str = "", technique: str = "") -> dict:
    rows, err = _load()
    if err:
        return err
    alerts = [r for r in rows if r["kind"] == "alert"]
    if severity:
        alerts = [r for r in alerts if r["severity"] == severity]
    if technique:
        alerts = [r for r in alerts if _match(r.get("technique"), technique)]
    ordered = _sort_desc(alerts)
    return {
        "count": len(alerts),
        "by_technique": dict(Counter(
            r.get("technique") or "unknown" for r in alerts
        ).most_common(ROW_CAP)),
        "by_severity": dict(Counter(r["severity"] for r in alerts).most_common()),
        "by_action": dict(Counter(
            r.get("action") or "unknown" for r in alerts
        ).most_common()),
        "alerts": _cap(ordered),
    }


def plasma_processes(host: str = "", process: str = "", user: str = "") -> dict:
    rows, err = _load()
    if err:
        return err
    procs = [r for r in rows if r["kind"] in ("process", "image_load")]
    if host:
        procs = [r for r in procs if _match(r["host"], host)]
    if process:
        procs = [r for r in procs if _match(r.get("process"), process)]
    if user:
        procs = [r for r in procs if _match(r.get("user"), user)]
    ordered = _sort_desc(procs)
    return {
        "count": len(procs),
        "by_process": dict(Counter(
            r.get("process") or "unknown" for r in procs
        ).most_common(ROW_CAP)),
        "by_technique": dict(Counter(
            r.get("technique") or "none" for r in procs
        ).most_common(ROW_CAP)),
        "events": _cap(ordered),
    }


def plasma_network(dest_ip: str = "", dest_port: int = 0) -> dict:
    rows, err = _load()
    if err:
        return err
    net = [r for r in rows if r["kind"] == "network"]
    if dest_ip:
        net = [r for r in net if _match(r.get("dest_ip"), dest_ip)]
    if dest_port:
        net = [r for r in net if int(r.get("dest_port") or 0) == int(dest_port)]
    ordered = _sort_desc(net)
    return {
        "count": len(net),
        "by_destination": dict(Counter(
            f"{r.get('dest_ip')}:{r.get('dest_port')}" for r in net
        ).most_common(ROW_CAP)),
        "by_process": dict(Counter(
            r.get("process") or "unknown" for r in net
        ).most_common(ROW_CAP)),
        "connections": _cap(ordered),
    }


def plasma_dns(query: str = "") -> dict:
    rows, err = _load()
    if err:
        return err
    dns = [r for r in rows if r["kind"] == "dns"]
    if query:
        dns = [r for r in dns if _match(r.get("dns_query"), query)]
    ordered = _sort_desc(dns)
    return {
        "count": len(dns),
        "by_query": dict(Counter(
            r.get("dns_query") or "unknown" for r in dns
        ).most_common(ROW_CAP)),
        "lookups": _cap(ordered),
    }


def plasma_persistence() -> dict:
    rows, err = _load()
    if err:
        return err
    markers = ("T154", "T1053", "T1547", "T1546")
    hits = [
        r for r in rows
        if r["kind"] == "registry"
        or r["kind"] == "file" and r.get("technique")
        or (r.get("technique") or "").startswith(markers)
    ]
    ordered = _sort_desc(hits)
    return {
        "count": len(hits),
        "by_technique": dict(Counter(
            r.get("technique") or "unclassified" for r in hits
        ).most_common(ROW_CAP)),
        "by_artifact": dict(Counter(
            "registry" if r.get("registry_path") else "file" for r in hits
        ).most_common()),
        "events": _cap(ordered),
    }


def plasma_search(text: str = "") -> dict:
    rows, err = _load()
    if err:
        return err
    fields = (
        "cmdline", "description", "file_path", "file_hash", "registry_path",
        "dns_query", "user", "process", "image", "technique", "alert_id",
    )
    if not text:
        return {"error": "text is required"}
    hits = [r for r in rows if any(_match(r.get(f), text) for f in fields)]
    ordered = _sort_desc(hits)
    return {"count": len(hits), "query": text, "events": _cap(ordered)}


def plasma_graph_overview() -> dict:
    import graph_bridge
    rows, err = _load()
    if err:
        return err
    return graph_bridge.overview(rows)


def plasma_graph_neighbors(node: str = "") -> dict:
    import graph_bridge
    rows, err = _load()
    if err:
        return err
    if not node:
        return {"error": "node is required"}
    return graph_bridge.neighbors(rows, node)


PROBES = {
    "plasma_overview": plasma_overview,
    "plasma_recent": plasma_recent,
    "plasma_alerts": plasma_alerts,
    "plasma_processes": plasma_processes,
    "plasma_network": plasma_network,
    "plasma_dns": plasma_dns,
    "plasma_persistence": plasma_persistence,
    "plasma_search": plasma_search,
    "plasma_graph_overview": plasma_graph_overview,
    "plasma_graph_neighbors": plasma_graph_neighbors,
}


def run_tool(name: str, args: dict | None = None) -> dict:
    fn = PROBES.get(name)
    if fn is None:
        return {"error": f"unknown probe: {name}"}
    args = args or {}
    try:
        return fn(**args)
    except TypeError as exc:
        return {"error": f"bad arguments for {name}: {exc}"[:300]}
    except Exception as exc:  # noqa: BLE001 - errors are data
        return {"error": f"{type(exc).__name__}: {exc}"[:300]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Execute one Plasma probe.")
    ap.add_argument("--tool")
    ap.add_argument("--args", default="{}")
    ap.add_argument("--events")
    ap.add_argument("--coverage", action="store_true")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args(argv)
    if a.events:
        os.environ[EVENTS_ENV] = a.events
    if a.list:
        print(json.dumps({"probes": sorted(PROBES)}, indent=2))
        return 0
    if a.coverage:
        print(json.dumps(coverage(), indent=2))
        return 0
    if not a.tool:
        ap.error("--tool is required (or --coverage / --list)")
    try:
        args = json.loads(a.args)
    except json.JSONDecodeError as exc:
        print(json.dumps({"error": f"bad --args JSON: {exc}"}))
        return 2
    print(json.dumps(run_tool(a.tool, args), indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
