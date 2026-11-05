"""Plasma chain: deterministic story-level detection over the events store.

Single findings say "this happened". Chains say "this happened, then this,
then this — that is a story". A chain is an ordered sequence of step
matchers over normalized PlasmaEvent rows; every adjacent pair must fall
within the chain's gap window. No ML, no scores learned from data — a
written suspicion story, exactly like a gene rule but across time.

Chains scan the LAST `max_rows` rows of the events store (oldest→newest),
so findings are always about recent history.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .fleet import _parse_ts

DEFAULT_WINDOW = 1800        # max seconds between adjacent chain steps
DEFAULT_MAX_ROWS = 5000      # scan tail size, bounded like every probe

# step matcher fields:
#   any of: kind, process (regex on basename-ish field), user (regex),
#           event_id, description (regex), dest_ip present?
# each built-in chain: name, score, gap_seconds, steps in time order

BUILTIN_CHAINS = [
    {
        "name": "phish_spawn_chain",
        "score": 9,
        "gap_seconds": 900,
        "detail": "office app spawned a script host, then an encoded/obfuscated "
                  "command or egress followed",
        "steps": [
            {"kind": "process", "process": r"(?i)(winword|excel|powerpnt|outlook)\.exe$"},
            {"kind": "process", "process": r"(?i)(powershell|wscript|cscript|mshta)\.exe$"},
            {"any_of": [
                {"description": r"(?i)(-enc|-ec|encodedcommand|frombase64|downloadstring|webclient)"},
                {"kind": "network"},
            ]},
        ],
    },
    {
        "name": "brute_force_success",
        "score": 8,
        "gap_seconds": 3600,
        "min_failures": 5,
        "detail": "repeated failed logons against one user, then a success",
        "steps": [
            {"kind": "auth", "event_id": 4625, "user": r".+", "min_count": 5},
            {"kind": "auth", "event_id": 4624, "user": r".+"},
        ],
    },
    {
        "name": "persistence_after_privilege",
        "score": 9,
        "gap_seconds": 3600,
        "detail": "account/admin change followed by a persistence-shaped alert",
        "steps": [
            {"description": r"(?i)(net1? .*(user|localgroup).*(/add| add)|add-localgroupmember|new-localuser)"},
            {"description": r"(?i)(sched|schtasks|new-service|register-scheduledtask|run ?key|eventfilter|bindversion)"},
        ],
    },
]


def _match_step(step: dict, row: dict) -> bool:
    """One step matcher against one event row."""
    if "any_of" in step:
        return any(_match_step(s, row) for s in step["any_of"])
    kind = step.get("kind")
    if kind and str(row.get("kind", "")).lower() != kind.lower():
        return False
    eid = step.get("event_id")
    if eid is not None:
        try:
            if int(row.get("event_id") or 0) != int(eid):
                return False
        except (TypeError, ValueError):
            return False
    for field in ("process", "user", "description"):
        if field in step:
            value = str(row.get(field) or "")
            try:
                if not re.search(step[field], value):
                    return False
            except re.error:
                return False
    return True


def _ts(row: dict):
    return _parse_ts(row.get("ts"))


def _count_back(events, i, step, gap):
    """Matches of `step` within `gap` seconds ending at events[i] (inclusive)."""
    t = _ts(events[i])
    count = 0
    k = i
    while k >= 0:
        tk = _ts(events[k])
        if tk is None or (t - tk).total_seconds() > gap:
            break
        if _match_step(step, events[k]):
            count += 1
        k -= 1
    return count


def _match_from(steps, events, start, gap, t_prev=None):
    """Ordered forward match of steps against events[start:], full
    backtracking on step candidates. Returns indices or None. Each adjacent
    pair must sit within `gap` seconds."""
    if not steps:
        return []
    step = steps[0]
    for i in range(start, len(events)):
        row = events[i]
        if not _match_step(step, row):
            continue
        t = _ts(row)
        if t_prev is not None and (t - t_prev).total_seconds() > gap:
            break          # sorted input: every later candidate is later still
        if step.get("min_count") and _count_back(events, i, step, gap) < step["min_count"]:
            continue
        rest = _match_from(steps[1:], events, i + 1, gap, t_prev=t)
        if rest is not None:
            return [i] + rest
    return None


def scan(rows: list[dict], chains: list[dict] | None = None,
         gap_seconds: int = DEFAULT_WINDOW) -> list[dict]:
    """Find chain matches in time-ordered rows. Returns findings."""
    chains = chains or BUILTIN_CHAINS
    events = [r for r in rows if _ts(r) is not None]
    events.sort(key=_ts)
    findings: list[dict] = []
    for chain in chains:
        gap = int(chain.get("gap_seconds", gap_seconds))
        idxs = _match_from(chain["steps"], events, 0, gap)
        if idxs:
            matched = [events[i] for i in idxs]
            t0, t1 = _ts(matched[0]), _ts(matched[-1])
            span_min = int((t1 - t0).total_seconds() / 60)
            users = sorted({str(m.get("user")) for m in matched if m.get("user")})
            findings.append({
                "type": f"chain_{chain['name']}",
                "score": chain["score"],
                "gap_seconds": gap,
                "span_minutes": span_min,
                "users": users,
                "steps": len(matched),
                "detail": (chain["detail"] + f" — {len(matched)} events over "
                           f"{span_min} min" +
                           (f", users: {', '.join(users)}" if users else "")),
                "events": [
                    {"ts": m.get("ts"), "kind": m.get("kind"),
                     "user": m.get("user"), "process": m.get("process"),
                     "description": str(m.get("description") or "")[:160]}
                    for m in matched][:8],
            })
    return findings


def scan_store(events_path, chains: list[dict] | None = None,
               max_rows: int = DEFAULT_MAX_ROWS,
               gap_seconds: int = DEFAULT_WINDOW) -> dict:
    """Scan the tail of an events store. Endpoint- and desk-safe."""
    path = Path(events_path)
    if not path.exists():
        return {"error": f"events store not found: {path}", "findings": []}
    rows = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    findings = scan(rows[-max_rows:], chains=chains, gap_seconds=gap_seconds)
    return {"scanned_rows": min(len(rows), max_rows),
            "chains": [c["name"] for c in (chains or BUILTIN_CHAINS)],
            "findings": findings,
            "top_score": max((f["score"] for f in findings), default=0)}
