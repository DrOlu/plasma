"""Typed local queries and process lineage over the Plasma event store.

Plasma is deliberately lake-less: the store is a bounded JSONL tail, not a
database. An agent still needs to ask precise questions without inventing a
shell pipeline. This module provides a small, closed query language:

    plasma query --process powershell.exe --since 1h --min-score 0.7
    plasma query --user CORP\\olu --count-by process
    plasma tree --pid 4832 --depth 3

Every filter is a named field with a fixed meaning. Unknown fields are
refused rather than ignored, so a typo cannot silently widen a search. The
reader is bounded in rows and bytes, matching every other Plasma probe.
"""

from __future__ import annotations

import fnmatch
import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_MAX_ROWS = 5000
DEFAULT_MAX_BYTES = 8 << 20
DEFAULT_LIMIT = 100
MAX_LIMIT = 1000
MAX_TREE_DEPTH = 10
MAX_TREE_NODES = 500

EXACT_FIELDS = (
    "host", "user", "kind", "source", "action", "severity", "technique",
    "process", "parent", "image", "file_path", "dns_query", "dest_ip",
    "alert_id",
)
STRING_FIELDS = EXACT_FIELDS + ("cmdline", "description", "target")
NUMERIC_FIELDS = ("pid", "event_id", "score")
COUNT_FIELDS = (
    "host", "user", "kind", "source", "severity", "technique", "process",
    "parent", "event_id", "action", "dest_ip",
)
FILTERS = frozenset(EXACT_FIELDS + ("pid", "event_id", "min_score",
                                    "max_score", "contains", "regex",
                                    "since", "until"))
SPEC_KEYS = FILTERS | {"limit", "count_by", "order", "max_rows"}

_CONTAINS_FIELDS = ("description", "cmdline", "image", "file_path",
                    "dns_query", "alert_id", "process", "parent")


class QueryError(ValueError):
    """A query used an unknown field or an invalid value."""


def _basename(value) -> str:
    return str(value or "").replace("\\", "/").rsplit("/", 1)[-1]


def _load_rows(path, max_rows: int = DEFAULT_MAX_ROWS,
               max_bytes: int = DEFAULT_MAX_BYTES) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    try:
        size = path.stat().st_size
        start = max(0, size - max(1, int(max_bytes)))
        with path.open("rb") as fh:
            fh.seek(start)
            blob = fh.read()
        if start:
            cut = blob.find(b"\n")
            blob = blob[cut + 1:] if cut >= 0 else b""
        rows = []
        for line in blob.splitlines()[-max(1, int(max_rows)):]:
            if not line.strip():
                continue
            try:
                row = json.loads(line.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
        return rows
    except OSError:
        return []


_DURATION = re.compile(r"^(\d{1,6})\s*([smhdw])$", re.IGNORECASE)


def parse_time(value, now=None):
    """Parse an ISO timestamp or a relative duration ending at ``now``."""
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        stamp = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        # An integer is minutes-ago. That is the least surprising unit for
        # an operator typing --since-minutes, and it is bounded by parse_time
        # callers through the normal filters.
        stamp = (now or datetime.now(timezone.utc)) - timedelta(
            minutes=float(value))
    else:
        text = str(value).strip()
        match = _DURATION.match(text)
        if match:
            amount = int(match.group(1))
            unit = match.group(2).lower()
            delta = {
                "s": timedelta(seconds=amount),
                "m": timedelta(minutes=amount),
                "h": timedelta(hours=amount),
                "d": timedelta(days=amount),
                "w": timedelta(weeks=amount),
            }[unit]
            stamp = (now or datetime.now(timezone.utc)) - delta
        else:
            try:
                stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError as exc:
                raise QueryError(
                    f"invalid time {value!r}; use an ISO timestamp or a "
                    "duration such as 15m, 1h or 2d") from exc
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc)


def _row_time(row):
    try:
        stamp = datetime.fromisoformat(str(row.get("ts", "")).replace(
            "Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc)


def _norm(value) -> str:
    return str(value or "").strip().lower()


def _match_text(actual, wanted) -> bool:
    actual = _norm(actual)
    wanted = _norm(wanted)
    if "*" in wanted or "?" in wanted:
        return fnmatch.fnmatchcase(actual, wanted)
    return actual == wanted


def _validate(spec: dict) -> dict:
    if not isinstance(spec, dict):
        raise QueryError("query must be a JSON object")
    unknown = sorted(set(spec) - SPEC_KEYS)
    if unknown:
        raise QueryError("unknown query field(s): " + ", ".join(unknown))
    clean = dict(spec)
    if "limit" in clean:
        try:
            clean["limit"] = max(1, min(int(clean["limit"]), MAX_LIMIT))
        except (TypeError, ValueError) as exc:
            raise QueryError("limit must be an integer") from exc
    if "max_rows" in clean:
        try:
            clean["max_rows"] = max(1, min(int(clean["max_rows"]),
                                           DEFAULT_MAX_ROWS))
        except (TypeError, ValueError) as exc:
            raise QueryError("max_rows must be an integer") from exc
    for key in ("pid", "event_id"):
        if key in clean:
            try:
                clean[key] = int(clean[key])
            except (TypeError, ValueError) as exc:
                raise QueryError(f"{key} must be an integer") from exc
    for key in ("min_score", "max_score"):
        if key in clean:
            try:
                clean[key] = float(clean[key])
            except (TypeError, ValueError) as exc:
                raise QueryError(f"{key} must be a number") from exc
            if not 0 <= clean[key] <= 1:
                raise QueryError(f"{key} must be between 0 and 1")
    if "count_by" in clean and clean["count_by"] not in COUNT_FIELDS:
        raise QueryError("count_by must be one of: " + ", ".join(COUNT_FIELDS))
    order = str(clean.get("order") or "desc").lower()
    if order not in ("asc", "desc"):
        raise QueryError("order must be asc or desc")
    clean["order"] = order
    for key in ("since", "until"):
        if key in clean:
            clean[key] = parse_time(clean[key])
    if clean.get("since") and clean.get("until") \
            and clean["since"] > clean["until"]:
        raise QueryError("since must be earlier than until")
    if "regex" in clean:
        try:
            re.compile(str(clean["regex"]))
        except re.error as exc:
            raise QueryError(f"invalid regex: {exc}") from exc
    return clean


def _matches(row: dict, spec: dict) -> bool:
    for key in EXACT_FIELDS:
        if key not in spec:
            continue
        actual = row.get(key)
        if key in ("process", "parent", "image"):
            actual = _basename(actual)
        if not _match_text(actual, spec[key]):
            return False
    for key in ("pid", "event_id"):
        if key in spec:
            try:
                if int(row.get(key)) != spec[key]:
                    return False
            except (TypeError, ValueError):
                return False
    score = row.get("score")
    if "min_score" in spec and (
            not isinstance(score, (int, float)) or float(score) < spec["min_score"]):
        return False
    if "max_score" in spec and (
            not isinstance(score, (int, float)) or float(score) > spec["max_score"]):
        return False
    stamp = _row_time(row)
    if spec.get("since") and (stamp is None or stamp < spec["since"]):
        return False
    if spec.get("until") and (stamp is None or stamp > spec["until"]):
        return False
    if "contains" in spec:
        needle = _norm(spec["contains"])
        haystack = " ".join(
            str(row.get(key) or "") for key in _CONTAINS_FIELDS).lower()
        if needle not in haystack:
            return False
    if "regex" in spec:
        pattern = re.compile(str(spec["regex"]))
        haystack = " ".join(
            str(row.get(key) or "") for key in _CONTAINS_FIELDS)
        if not pattern.search(haystack):
            return False
    return True


def _sort_rows(rows: list[dict], order: str) -> list[dict]:
    def key(row):
        stamp = _row_time(row)
        return stamp.timestamp() if stamp else 0.0
    return sorted(rows, key=key, reverse=(order == "desc"))


def query(events_path, spec: dict | None = None,
          max_rows: int = DEFAULT_MAX_ROWS) -> dict:
    """Run one closed-schema query over the bounded event tail."""
    clean = _validate(spec or {})
    rows = _load_rows(events_path,
                      max_rows=int(clean.pop("max_rows", max_rows)))
    matched = [row for row in rows if _matches(row, clean)]
    ordered = _sort_rows(matched, clean["order"])
    limit = int(clean.get("limit", DEFAULT_LIMIT))
    result = {
        "ok": True,
        "checked": len(rows),
        "matched": len(matched),
        "returned": len(ordered[:limit]),
        "truncated": len(matched) > limit,
        "query": _public_spec(clean),
        "events": ordered[:limit],
    }
    if clean.get("count_by"):
        field = clean["count_by"]
        counts = Counter(
            _basename(row.get(field)) if field in ("process", "parent")
            else str(row.get(field) or "unknown") for row in matched)
        result["count_by"] = field
        result["counts"] = [
            {"value": value, "count": count}
            for value, count in counts.most_common(50)
        ]
    return result


def _public_spec(spec: dict) -> dict:
    out = {}
    for key, value in spec.items():
        if key in ("since", "until") and isinstance(value, datetime):
            out[key] = value.isoformat().replace("+00:00", "Z")
        else:
            out[key] = value
    return out


def _node(row: dict) -> dict:
    return {
        "ts": row.get("ts"),
        "pid": row.get("pid"),
        "ppid": row.get("ppid"),
        "process": _basename(row.get("process")),
        "parent": _basename(row.get("parent")),
        "user": row.get("user"),
        "image": row.get("image"),
        "cmdline": row.get("cmdline"),
        "event_id": row.get("event_id"),
        "score": row.get("score"),
    }


def tree(events_path, pid=None, process_name=None, depth: int = 3,
         max_rows: int = DEFAULT_MAX_ROWS,
         max_nodes: int = MAX_TREE_NODES) -> dict:
    """Return a parent/child process tree from PID lineage in the tail.

    The tree is built only from explicit ``ppid`` edges. A missing parent
    link is reported as an orphan root rather than guessed from a process
    name: a wrong lineage edge is worse than none in an investigation.
    """
    depth = max(1, min(int(depth), MAX_TREE_DEPTH))
    rows = _load_rows(events_path, max_rows=max_rows, max_bytes=DEFAULT_MAX_BYTES)
    proc_rows = [r for r in rows if r.get("pid") is not None
                 and (_norm(r.get("kind")) in ("process", "alert", "")
                      or r.get("ppid") is not None)]
    proc_rows.sort(key=lambda r: (_row_time(r) or datetime.min.replace(
        tzinfo=timezone.utc)))
    if not proc_rows:
        return {"ok": True, "roots": [], "nodes": [], "edges": [],
                "checked": len(rows), "note": "no process rows in the tail"}

    by_pid = {}
    for row in proc_rows:
        try:
            by_pid[int(row["pid"])] = row
        except (TypeError, ValueError):
            continue
    children = {}
    for child_pid, row in by_pid.items():
        try:
            ppid = int(row["ppid"]) if row.get("ppid") is not None else None
        except (TypeError, ValueError):
            ppid = None
        if ppid is not None:
            children.setdefault(ppid, []).append(child_pid)

    root_pids = []
    if pid is not None:
        try:
            root_pids = [int(pid)]
        except (TypeError, ValueError):
            raise QueryError("pid must be an integer")
    elif process_name:
        wanted = _norm(_basename(process_name))
        matches = [p for p, row in by_pid.items()
                   if fnmatch.fnmatchcase(_norm(_basename(row.get("process"))),
                                          wanted)]
        root_pids = matches[-1:]
    else:
        # Roots are rows with no parent edge or with a parent outside the tail.
        def _orphan(row):
            try:
                ppid = int(row["ppid"])
            except (KeyError, TypeError, ValueError):
                return True
            return ppid not in by_pid

        root_pids = [p for p, row in by_pid.items() if _orphan(row)][-5:]

    nodes, edges = [], []
    seen = set()
    truncated = False

    def visit(current: int, level: int):
        nonlocal truncated
        if current in seen or len(nodes) >= max_nodes:
            truncated = truncated or len(nodes) >= max_nodes
            return
        seen.add(current)
        row = by_pid.get(current)
        if row is None:
            return
        nodes.append({**_node(row), "level": level})
        if level >= depth:
            return
        for child in children.get(current, []):
            if len(nodes) >= max_nodes:
                truncated = True
                return
            edges.append({"from": current, "to": child})
            visit(child, level + 1)

    for root in root_pids:
        visit(root, 0)

    return {
        "ok": True,
        "checked": len(rows),
        "root": nodes[0] if nodes else None,
        "roots": root_pids,
        "nodes": nodes,
        "edges": edges,
        "truncated": truncated,
        "max_depth": depth,
    }
