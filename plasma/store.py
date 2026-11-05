"""Plasma store hygiene: rotation and compaction for the events diary.

The events store is an append-only JSONL file. Without hygiene it grows
forever; with rotation it stays a bounded tail with archived elders, and
with compaction it sheds exact duplicates (identity dedupes on write, but
hand-appended or multi-sensor rows can still repeat).

Rotation keeps NUMBERED elders next to the live file:
    events.jsonl            (live, freshly created)
    events.jsonl.1          (most recent rotated)
    events.jsonl.2          ...
Rotation never touches the content of the live file beyond renaming it —
the format contract stays "a plain file".
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

DEFAULT_MAX_MB = 50
DEFAULT_KEEP = 3


def rotate(events_path, max_mb: float = DEFAULT_MAX_MB,
           keep: int = DEFAULT_KEEP) -> dict:
    """Rotate the store when it exceeds max_mb. Returns what happened."""
    path = Path(events_path)
    if not path.exists():
        return {"rotated": False, "reason": f"no store at {path}"}
    size = path.stat().st_size
    limit = int(max_mb * 1024 * 1024)
    if size < limit:
        return {"rotated": False, "reason": f"{size} bytes < {limit} limit",
                "size_bytes": size}
    # shift elders: .(keep-1) -> deleted, .k -> .(k+1)
    removed = None
    oldest = path.with_name(path.name + f".{keep}")
    if oldest.exists():
        removed = str(oldest)
        oldest.unlink()
    for k in range(keep - 1, 0, -1):
        src = path.with_name(path.name + f".{k}")
        if src.exists():
            src.rename(path.with_name(path.name + f".{k + 1}"))
    path.rename(path.with_name(path.name + ".1"))
    path.touch()
    return {"rotated": True, "size_bytes": size, "limit_bytes": limit,
            "kept": keep, "removed_elder": removed,
            "live_file": str(path)}


def compact(events_path, out_path=None) -> dict:
    """Drop exact-duplicate lines (full-row JSON equality), keep order.

    Writes to a temp file and os.replace()s — a crash mid-compact leaves
    the original untouched. Returns counts, never raises on bad lines
    (torn lines are preserved as-is rather than silently dropped).
    """
    src = Path(events_path)
    if not src.exists():
        return {"error": f"no store at {src}"}
    dst = Path(out_path) if out_path else src.with_suffix(src.suffix + ".compact")
    seen: set[str] = set()
    kept_lines = 0
    dropped = 0
    torn = 0
    with src.open(encoding="utf-8", errors="replace") as fh, \
            dst.open("w", encoding="utf-8") as out:
        for line in fh:
            stripped = line.strip()
            if not stripped:
                continue
            if not stripped.startswith("{"):
                torn += 1
                out.write(line)
                kept_lines += 1
                continue
            try:
                canonical = json.dumps(json.loads(stripped),
                                       sort_keys=True, ensure_ascii=False)
            except json.JSONDecodeError:
                torn += 1
                out.write(line)
                kept_lines += 1
                continue
            if canonical in seen:
                dropped += 1
                continue
            seen.add(canonical)
            out.write(stripped + "\n")
            kept_lines += 1
    before = src.stat().st_size
    if out_path is None:
        os.replace(dst, src)
    result = {"kept": kept_lines, "dropped_duplicates": dropped,
              "torn_or_noise_preserved": torn}
    if out_path is None:
        result["size_bytes"] = {"before": before, "after": src.stat().st_size}
    else:
        result["written"] = str(dst)
    return result


def stats(events_path) -> dict:
    path = Path(events_path)
    if not path.exists():
        return {"error": f"no store at {path}"}
    rows = 0
    kinds: dict[str, int] = {}
    first_ts = last_ts = None
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped.startswith("{"):
                continue
            try:
                row = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            rows += 1
            kinds[str(row.get("kind"))] = kinds.get(str(row.get("kind")), 0) + 1
            ts = row.get("ts")
            if ts:
                first_ts = first_ts or ts
                last_ts = ts
    return {"rows": rows, "size_bytes": path.stat().st_size,
            "kinds": kinds, "first_ts": first_ts, "last_ts": last_ts,
            "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
