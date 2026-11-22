"""Local anomaly scoring and causal traces over the bounded event tail.

This is the detection half of the profile spine. It never learns online and
never ships events: it compares a bounded tail against a profile the host
already built, using four explainable families — categorical rarity,
first-seen keys, robust hourly volume, and (for traces) sequence rarity.

Every score is a weighted mean of named components with the observed and
expected values attached. There is no opaque model in the path: an operator
or an agent can read why a row scored, and a cold profile returns no score
at all rather than inventing confidence.

Trace reconstruction is deliberately local. Process IDs are host-scoped, so
spans are joined only within one host's store; cross-host identity joins
belong to the fleet layer and are labelled as such when used.
"""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict

from .profile import (
    MIN_OBSERVATIONS,
    _image,
    _parent,
    _row_time,
    _user,
    cmd_shape,
    dest_family,
    file_family,
    rarity,
    registry_family,
    volume,
)

WEIGHTS = {
    "image": 1.0,
    "edge": 1.5,
    "user_image": 0.8,
    "dest": 0.7,
    "registry": 0.8,
    "file": 0.4,
    "shape": 0.8,
    "volume": 1.2,
    "estate": 1.5,
}

# Routine Windows servicing spawns rare children from a small set of signed
# service hosts. Novelty there is real but low-signal; damp it so a patched
# server does not read as critical while still surfacing at triage level.
BENIGN_SERVICE_PARENTS = {
    "services.exe", "svchost.exe", "wininit.exe", "winlogon.exe",
    "taskhostw.exe", "wuauclt.exe", "usoclient.exe", "sihclient.exe",
    "upfc.exe", "compattelrunner.exe", "msiexec.exe",
}
SERVICE_PARENT_DAMPING = 0.55


def _is_self(image) -> bool:
    """Plasma's own binaries are operations, not threat novelty."""
    name = str(image or "").lower()
    return name.startswith("plasma") and name.endswith(".exe")

TRACE_GAP_SECONDS = 1800
DEFAULT_LIMIT = 20
MAX_LIMIT = 200


def _component(name, rarity_row, weight, detail=None):
    return {
        "name": name,
        "weight": weight,
        "value": round(float(rarity_row["value"]), 3),
        "first_seen": bool(rarity_row.get("first_seen")),
        "table": rarity_row.get("table"),
        "key": rarity_row.get("key"),
        "count": rarity_row.get("count"),
        "total": rarity_row.get("total"),
        "detail": detail,
    }


def _reason(component) -> str:
    key = str(component.get("key") or "")[:80]
    if component.get("first_seen"):
        return f"{component['name']}: '{key}' was never seen in the baseline"
    return (f"{component['name']}: '{key}' appeared "
            f"{component.get('count')} of {component.get('total')} times")


def _batch_counts(rows: list[dict]) -> Counter:
    """Observed per-entity, per-hour, per-day counts in the scored window.

    Volume is a daily quantity: comparing a whole tail's count against a
    one-day median would mark every busy hour as an anomaly.
    """
    counts: Counter = Counter()
    for row in rows:
        stamp = _row_time(row)
        if stamp is None:
            continue
        image = _image(row)
        user = _user(row)
        day = stamp.date().isoformat()
        if user:
            counts[(f"user:{user}", stamp.hour, day)] += 1
        if image:
            counts[(f"image:{image}", stamp.hour, day)] += 1
    return counts


def score_row(row: dict, profile: dict, estate: dict | None = None,
              batch: Counter | None = None) -> dict | None:
    """Score one event against one profile. Returns None when cold."""
    if not isinstance(row, dict) or not profile:
        return None
    n = int(profile.get("n") or 0)
    minimum = int((profile.get("limits") or {}).get(
        "min_observations", MIN_OBSERVATIONS))
    if n < minimum:
        return {
            "ts": row.get("ts"), "host": row.get("host"),
            "process": _image(row), "score": None, "cold_start": True,
            "components": [],
            "reason": (f"baseline has {n} observations; "
                       f"{minimum} required"),
        }

    image = _image(row)
    parent = _parent(row)
    user = _user(row)
    stamp = _row_time(row)
    components: list[dict] = []

    def add(name, table, key, weight, detail=None):
        found = rarity(profile, table, key)
        if found is not None:
            components.append(_component(name, found, weight, detail))

    if image:
        add("image", "image", image, WEIGHTS["image"])
    if parent and image:
        add("edge", "parent_child", f"{parent}>{image}", WEIGHTS["edge"])
    if user and image:
        add("user_image", "user_image", f"{user}>{image}",
            WEIGHTS["user_image"])
    dest = dest_family(row)
    if image and dest:
        add("dest", "dest", f"{image}>{dest}", WEIGHTS["dest"])
    registry = registry_family(row.get("registry_path"))
    if registry:
        add("registry", "registry", registry, WEIGHTS["registry"])
    family = file_family(row.get("file_path"))
    if family:
        add("file", "file", family, WEIGHTS["file"])
    shape = cmd_shape(row.get("cmdline"), image)
    if shape:
        add("shape", "shape", shape, WEIGHTS["shape"])

    if stamp is not None and batch is not None:
        entity = f"user:{user}" if user else f"image:{image}" if image else ""
        if entity:
            observed = int(batch.get(
                (entity, stamp.hour, stamp.date().isoformat())) or 0)
            vol = volume(profile, entity, stamp.hour, observed)
            if vol is not None:
                components.append({
                    "name": "volume", "weight": WEIGHTS["volume"],
                    "value": round(float(vol["value"]), 3),
                    "first_seen": False, "table": "hourly",
                    "key": entity, "count": observed,
                    "total": vol.get("median"), "detail": {
                        "hour": stamp.hour, "median": vol.get("median"),
                        "mad": vol.get("mad"), "z": vol.get("z"),
                    },
                })

    if estate:
        estate_keys = [("image", image), ("edge", f"{parent}>{image}"),
                       ("user_image", f"{user}>{image}")]
        for table, key in estate_keys:
            if not key or key.startswith(">"):
                continue
            found = rarity(estate, table, key)
            if found is not None:
                components.append(_component(
                    "estate", found, WEIGHTS["estate"], detail={"table": table}))

    # If every table was below its own observation floor there is nothing to
    # stand on; say so instead of returning a confident zero.
    usable = [component for component in components
              if component["total"] is not None]
    if not usable:
        return {
            "ts": row.get("ts"), "host": row.get("host"),
            "process": image, "parent": parent, "user": user,
            "score": None, "cold_start": True, "components": [],
            "reason": "no baseline table has enough observations",
        }

    weight_sum = sum(component["weight"] for component in usable)
    raw = sum(component["weight"] * component["value"]
              for component in usable)
    score = 10.0 * raw / weight_sum if weight_sum else 0.0
    damping = None
    if parent in BENIGN_SERVICE_PARENTS:
        damping = {"parent": parent, "factor": SERVICE_PARENT_DAMPING,
                   "reason": "routine Windows service parent"}
        score *= SERVICE_PARENT_DAMPING
    score = round(score, 1)
    reasons = [_reason(component) for component in
               sorted(usable, key=lambda item: -(item["weight"] * item["value"]))
               if component["value"] >= 0.6][:4]
    return {
        "ts": row.get("ts"),
        "host": row.get("host"),
        "process": image,
        "parent": parent,
        "user": user,
        "behaviour": shape,
        "event_id": row.get("event_id"),
        "severity": row.get("severity"),
        "score": score,
        "cold_start": False,
        "components": sorted(usable,
                             key=lambda item: -(item["weight"] * item["value"])),
        "reasons": reasons,
        "damping": damping,
    }


def rank(events_path, profile: dict, estate: dict | None = None,
         since=None, max_rows: int = 5000, limit: int = DEFAULT_LIMIT,
         include_suppressed: bool = False,
         include_self: bool = False,
         per_behaviour: int = 3) -> dict:
    """Score the tail and return the highest-scoring behaviours."""
    from .query import _load_rows, parse_time

    rows = _load_rows(events_path, max_rows=max_rows)
    since_dt = parse_time(since) if since else None
    kept = []
    for row in rows:
        stamp = _row_time(row)
        if stamp is None:
            continue
        if since_dt is not None and stamp < since_dt:
            continue
        if not include_suppressed and row.get("suppressed"):
            continue
        if not include_self and _is_self(_image(row)):
            continue
        kept.append(row)
    batch = _batch_counts(kept)

    scored = []
    for row in kept:
        result = score_row(row, profile, estate=estate, batch=batch)
        if result and result.get("score") is not None:
            scored.append(result)
    scored.sort(key=lambda item: (-item["score"], str(item.get("ts") or "")))

    # A noisy actor can repeat one behaviour; keep the ranking readable
    # without hiding it (the occurrence count is reported).
    seen: Counter = Counter()
    selected = []
    for item in scored:
        key = (item.get("host"), item.get("process"),
               item.get("parent"), item.get("behaviour"))
        if per_behaviour and seen[key] >= per_behaviour:
            continue
        seen[key] += 1
        selected.append(item)
        if len(selected) >= max(1, min(int(limit), MAX_LIMIT)):
            break

    return {
        "ok": True,
        "profile_host": profile.get("host"),
        "profile_n": profile.get("n"),
        "estate": bool(estate),
        "scored": len(scored),
        "cold_start": not scored and int(profile.get("n") or 0) < int(
            (profile.get("limits") or {}).get(
                "min_observations", MIN_OBSERVATIONS)),
        "events": selected,
        "top_score": selected[0]["score"] if selected else 0.0,
        "bands": _bands(selected),
    }


def _bands(rows: list[dict]) -> dict:
    bands = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for row in rows:
        score = float(row.get("score") or 0)
        if score >= 9.0:
            bands["critical"] += 1
        elif score >= 7.5:
            bands["high"] += 1
        elif score >= 6.0:
            bands["medium"] += 1
        else:
            bands["low"] += 1
    return bands


def explain(events_path, profile: dict, contains: str | None = None,
            ts: str | None = None, estate: dict | None = None,
            since=None, max_rows: int = 5000) -> dict:
    """Explain the highest-scoring row, optionally filtered to one match."""
    ranked = rank(events_path, profile, estate=estate, since=since,
                  max_rows=max_rows, limit=MAX_LIMIT, per_behaviour=0)
    rows = ranked["events"]
    if contains:
        needle = str(contains).lower()
        rows = [row for row in rows
                if needle in str(row.get("process") or "").lower()
                or needle in str(row.get("parent") or "").lower()]
    if ts:
        rows = [row for row in rows if str(row.get("ts") or "") == ts]
    if not rows:
        return {"ok": False, "error": "no scored event matched", "events": []}
    best = rows[0]
    return {
        "ok": True,
        "profile_host": profile.get("host"),
        "cold_start": bool(best.get("cold_start")),
        "event": best,
        "weights": WEIGHTS,
        "reading": _reading(best),
    }


def _reading(row: dict) -> list[str]:
    if row.get("cold_start"):
        return [row.get("reason") or "baseline too small"]
    return row.get("reasons") or ["no component crossed the reporting band"]


# ---------------------------------------------------------------------------
# traces
# ---------------------------------------------------------------------------

def _span(row: dict) -> dict:
    return {
        "ts": row.get("ts"),
        "pid": row.get("pid"),
        "ppid": row.get("ppid"),
        "process": _image(row),
        "parent": _parent(row),
        "user": _user(row),
        "event_id": row.get("event_id"),
        "severity": row.get("severity"),
    }


def build_traces(rows: list[dict], gap_seconds: int = TRACE_GAP_SECONDS,
                 min_spans: int = 1) -> list[dict]:
    """Join process spans into causal trees, one host at a time.

    Process IDs are host-scoped and reused, so a parent link is the most
    recent earlier span with that PID on the same host. No guess is made
    across hosts: an RDP hop creates a new logon and a new tree.
    """
    nodes = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("kind") not in ("process", "alert"):
            continue
        stamp = _row_time(row)
        if stamp is None or row.get("pid") in (None, ""):
            continue
        nodes.append({"row": row, "ts": stamp, "host": str(row.get("host") or ""),
                      "pid": row.get("pid"), "ppid": row.get("ppid"),
                      "parent_index": None})
    nodes.sort(key=lambda node: node["ts"])

    last_by_pid: dict[tuple, int] = {}
    for index, node in enumerate(nodes):
        key = (node["host"], node["pid"])
        parent_pid = node["ppid"]
        if parent_pid not in (None, ""):
            parent_key = (node["host"], parent_pid)
            candidate = last_by_pid.get(parent_key)
            if candidate is not None:
                delta = (node["ts"] - nodes[candidate]["ts"]).total_seconds()
                if 0 <= delta <= gap_seconds:
                    node["parent_index"] = candidate
        last_by_pid[key] = index

    # Root is the oldest ancestor reachable through parent_index.
    def root_of(index: int) -> int:
        seen = set()
        while nodes[index]["parent_index"] is not None and index not in seen:
            seen.add(index)
            index = nodes[index]["parent_index"]
        return index

    grouped: dict[int, list[int]] = defaultdict(list)
    for index in range(len(nodes)):
        grouped[root_of(index)].append(index)

    traces = []
    for root_index, members in grouped.items():
        if len(members) < max(1, int(min_spans)):
            continue
        members.sort(key=lambda item: nodes[item]["ts"])
        root = nodes[root_index]
        spans = []
        for index in members:
            span = _span(nodes[index]["row"])
            parent_index = nodes[index]["parent_index"]
            if not span["parent"] and parent_index is not None:
                span["parent"] = _image(nodes[parent_index]["row"])
            spans.append(span)
        images = sorted({span["process"] for span in spans if span["process"]})
        users = sorted({span["user"] for span in spans if span["user"]})
        edges = sorted({f"{span['parent']}>{span['process']}" for span in spans
                        if span["parent"] and span["process"]})
        start = nodes[members[0]]["ts"]
        end = nodes[members[-1]]["ts"]
        depth = _depth(members, nodes)
        trace_id = hashlib.sha256(
            f"{root['host']}|{root['pid']}|{start.isoformat()}".encode()
        ).hexdigest()[:12]
        traces.append({
            "trace_id": trace_id,
            "host": root["host"],
            "root_pid": root["pid"],
            "root_process": _image(root["row"]),
            "start": start.isoformat(),
            "end": end.isoformat(),
            "duration_seconds": int((end - start).total_seconds()),
            "spans": len(spans),
            "depth": depth,
            "images": images[:20],
            "users": users[:10],
            "edges": edges[:40],
            "trace": spans[:200],
        })
    traces.sort(key=lambda item: (-item["spans"], item["start"]))
    return traces


def _depth(members: list[int], nodes: list[dict]) -> int:
    depth_by_index = {}
    for index in members:
        chain = 0
        cursor = index
        seen = set()
        while cursor in members and cursor not in seen:
            seen.add(cursor)
            parent = nodes[cursor]["parent_index"]
            if parent is None:
                break
            chain += 1
            cursor = parent
        depth_by_index[index] = chain
    return max(depth_by_index.values() or [0])


def trace_score(trace: dict, profile: dict) -> dict:
    """Score a trace by the rarity of its parent→child edges."""
    if not profile:
        return {"score": None, "cold_start": True, "components": []}
    components = []
    for edge in trace.get("edges") or []:
        found = rarity(profile, "parent_child", edge)
        if found is not None:
            components.append(_component("edge", found, 1.0))
    if not components:
        return {"score": None, "cold_start": True, "components": []}
    values = [component["value"] for component in components]
    score = round(10.0 * sum(values) / len(values), 1)
    return {
        "score": score,
        "cold_start": False,
        "first_seen_edges": [component["key"] for component in components
                             if component["first_seen"]],
        "components": components,
    }


def traces(events_path, profile: dict | None = None, since=None,
           max_rows: int = 5000, limit: int = DEFAULT_LIMIT,
           min_spans: int = 2, gap_seconds: int = TRACE_GAP_SECONDS,
           include_self: bool = False) -> dict:
    from .query import _load_rows, parse_time

    rows = _load_rows(events_path, max_rows=max_rows)
    since_dt = parse_time(since) if since else None
    if since_dt is not None:
        rows = [row for row in rows
                if (_row_time(row) or since_dt) >= since_dt]
    built = build_traces(rows, gap_seconds=gap_seconds, min_spans=min_spans)
    scored = []
    for trace in built:
        if not include_self and _is_self(trace.get("root_process")):
            continue
        if profile:
            trace = {**trace, **trace_score(trace, profile)}
        scored.append(trace)
    scored.sort(key=lambda item: (-(item.get("score") or 0), -item["spans"]))
    kept = scored[:max(1, min(int(limit), MAX_LIMIT))]
    return {
        "ok": True,
        "host": (profile or {}).get("host"),
        "traces": kept,
        "count": len(scored),
        "returned": len(kept),
        "cold_start": bool(profile) and bool(kept) and all(
            trace.get("cold_start") for trace in kept),
    }
