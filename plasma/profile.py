"""Plasma behavioural profiles: compact, local, lake-less baselines.

A profile is what a host knows about its own normal: which images run, which
parent→child edges exist, which identities touch which images, which registry
and file families change, and how much each entity does at each hour of the
day. It stores counts and robust statistics — never the event stream, never
a full command line, never a file path.

That is the point. A profile is tens of kilobytes, so an estate of a
thousand hosts is megabytes at the desk, not a log lake. Profiles merge and
diff deterministically, carry an integrity hash, and can be pulled from a
host without shipping its diary.

The schema is intentionally small and closed; unknown fields are ignored so
an older reader can still open a newer profile's core.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import socket
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .query import _load_rows, parse_time
from .redact import redact_text

PROFILE_SCHEMA = 1
DEFAULT_MAX_ROWS = 20000
DEFAULT_MAX_BYTES = 16 << 20
TOP_K = 2000
SHAPE_TOP_K = 500
MAX_SHAPE_CHARS = 160
MAX_ENTITY_BUCKETS = 200
RARITY_COUNT_CAP = 50
MIN_OBSERVATIONS = 50
MIN_BUCKET_DAYS = 3

TABLES = ("image", "parent_child", "user_image", "dest", "registry",
          "file", "shape")

_B64 = re.compile(r"(?i)\b[A-Za-z0-9+/]{16,}={0,2}\b")
_URL = re.compile(r"(?i)\b(?:https?|ftp)://[^\s\"']+")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_GUID = re.compile(
    r"(?i)\{[0-9a-f-]{36}\}|\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}\b")
_HEX = re.compile(r"(?i)\b[0-9a-f]{16,}\b")
_PATH = re.compile(r"(?i)(?:[a-z]:\\|\\\\)[^\s\"']+")
_QUOTED = re.compile(r"\"[^\"]*\"|'[^']*'")
_NUM = re.compile(r"\b\d+\b")
_SPACE = re.compile(r"\s+")
_CRED = re.compile(r"(?i)\b(password|passwd|pwd)([=:\s]+)\S+")
_NET_USER = re.compile(r"(?i)\b(net1?)(\.exe)?\s+user\s+(\S+)\s+([^\s/-]\S*)")

_FILE_MARKERS = (
    "documents", "desktop", "downloads", "pictures", "videos",
    "appdata\\local\\temp", "windows\\temp", "users\\public",
    "programdata", "windows\\system32", "program files", "finance",
    "payroll", "hr", "legal", "backup", "shared",
)
_REG_PREFIX = re.compile(
    r"^(\\registry\\)?(hklm|hkcu|hkcr|hku|hkey_local_machine|"
    r"hkey_current_user|hkey_classes_root)(\\[^\\]+)?")

def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _basename(value) -> str:
    if value is None:
        return ""
    return str(value).replace("\\", "/").rsplit("/", 1)[-1].strip().lower()


def _clip(value, limit: int) -> str:
    text = str(value or "")
    return text[:limit]


def _row_time(row: dict):
    text = str(row.get("ts") or "").strip()
    if not text:
        return None
    try:
        stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc)


def _image(row: dict) -> str:
    return _basename(row.get("process") or row.get("image"))


def _parent(row: dict) -> str:
    return _basename(row.get("parent"))


def _user(row: dict) -> str:
    value = str(row.get("user") or "").strip().lower()
    # Machine accounts are noise for behaviour profiles.
    if not value or value.endswith("$"):
        return ""
    return value


def dest_family(row: dict) -> str:
    """Port if known, else a /24-shaped IP family. Never a raw address."""
    port = row.get("dest_port")
    if port:
        try:
            return f"p:{int(port)}"
        except (TypeError, ValueError):
            pass
    ip = str(row.get("dest_ip") or "").strip()
    if ip.count(".") == 3:
        head = ".".join(ip.split(".")[:3])
        return f"ip:{head}.0/24"
    if ip:
        return "ip:other"
    return ""


def registry_family(path) -> str:
    text = str(path or "").replace("/", "\\").strip().lower()
    if not text:
        return ""
    text = _REG_PREFIX.sub("", text)
    parts = [part for part in text.split("\\") if part]
    if not parts:
        return "other"
    return "\\".join(parts[-3:])


def file_family(path) -> str:
    text = str(path or "").replace("/", "\\").strip().lower()
    if not text:
        return ""
    ext = ""
    name = text.rsplit("\\", 1)[-1]
    if "." in name:
        ext = "." + name.rsplit(".", 1)[-1]
    for marker in _FILE_MARKERS:
        if marker in text:
            return f"{marker}{ext}"
    if text.startswith("c:\\windows"):
        return f"windows{ext}"
    return f"other{ext}"


def cmd_shape(cmdline, image=None) -> str:
    """A behaviour label for a command line, not the command line itself.

    Paths, URLs, addresses, GUIDs, long hex blobs, quoted strings and numbers
    collapse to placeholders. The result is stable across runs, safe to keep
    in a profile, and still distinguishes ``powershell -enc <b64>`` from
    ``powershell -file <path>``.
    """
    text = redact_text(str(cmdline or ""))
    if not text.strip():
        return ""
    # Credentials must never survive as a shape. `net user bob <pw>` is the
    # one Windows idiom no generic redactor catches reliably.
    text = _CRED.sub(r"\1\2<cred>", text)
    text = _NET_USER.sub(r"\1\2 user \3 <cred>", text)
    text = _QUOTED.sub("<s>", text)
    text = _URL.sub("<url>", text)
    text = _IP.sub("<ip>", text)
    text = _GUID.sub("<guid>", text)
    text = _B64.sub("<b64>", text)
    text = _HEX.sub("<hex>", text)
    text = _PATH.sub("<path>", text)
    text = _NUM.sub("<n>", text)
    tokens = [token for token in _SPACE.split(text.strip()) if token]
    if not tokens:
        return ""
    head = _basename(tokens[0]) or ""
    if head in ("", "<s>"):
        # A quoted full path collapsed to <s>; keep the process identity by
        # falling back to the image name so shapes separate binaries.
        head = _basename(image) or tokens[0] or "<cmd>"
    shaped = " ".join([head] + tokens[1:11])
    return shaped[:MAX_SHAPE_CHARS]


def _bump(table: Counter, key: str, limit: int = TOP_K) -> None:
    if not key:
        return
    if key in table or len(table) < limit:
        table[key] += 1


def _final_table(counter: Counter, limit: int = TOP_K) -> dict:
    ordered = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    kept = ordered[:limit]
    return {"counts": dict(kept), "total": sum(count for _, count in kept)}


def _median_mad(values: list[int]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    median = (float(ordered[mid]) if len(ordered) % 2
              else (ordered[mid - 1] + ordered[mid]) / 2.0)
    deviations = sorted(abs(value - median) for value in values)
    mad = (float(deviations[mid]) if len(deviations) % 2
           else (deviations[mid - 1] + deviations[mid]) / 2.0)
    return median, mad


def _integrity(body: dict) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _sign(profile: dict) -> dict:
    body = {key: value for key, value in profile.items()
            if key != "integrity"}
    profile["integrity"] = {"sha256": _integrity(body)}
    return profile


def verify(profile: dict) -> dict:
    """Recompute the profile hash without trusting the stored value."""
    if not isinstance(profile, dict):
        return {"ok": False, "reason": "profile is not an object"}
    stored = (profile.get("integrity") or {}).get("sha256")
    if not stored:
        return {"ok": False, "reason": "profile has no integrity hash"}
    expected = _integrity({key: value for key, value in profile.items()
                           if key != "integrity"})
    return {"ok": stored == expected, "expected": expected,
            "stored": stored, "reason": None if stored == expected
            else "integrity hash mismatch"}


def _host(rows, host=None) -> str:
    if host:
        return str(host)
    for row in rows:
        if row.get("host"):
            return str(row["host"])
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def build(events_path, host: str | None = None, role: str = "unknown",
          max_rows: int = DEFAULT_MAX_ROWS, since=None,
          max_bytes: int = DEFAULT_MAX_BYTES) -> dict:
    """Build one host profile from a bounded tail of its event store."""
    rows = _load_rows(events_path, max_rows=max(1, int(max_rows)),
                      max_bytes=max(1 << 20, int(max_bytes)))
    since_dt = parse_time(since) if since else None
    if since_dt is not None:
        rows = [row for row in rows
                if (_row_time(row) or since_dt) >= since_dt]
    rows = [row for row in rows if _row_time(row) is not None]

    tables = {name: Counter() for name in TABLES}
    shape_table = tables["shape"]
    hourly: dict[str, dict[int, Counter]] = defaultdict(
        lambda: defaultdict(Counter))
    entity_totals: Counter = Counter()
    last_seen: dict[str, object] = {}
    dates: set = set()

    for row in rows:
        stamp = _row_time(row)
        hour, day = stamp.hour, stamp.date().isoformat()
        dates.add(day)
        image = _image(row)
        parent = _parent(row)
        user = _user(row)

        if image:
            _bump(tables["image"], image)
            entity_totals[f"image:{image}"] += 1
            hourly[f"image:{image}"][hour][day] += 1
            last_seen[f"image:{image}"] = stamp
        if parent and image:
            _bump(tables["parent_child"], f"{parent}>{image}")
        if user and image:
            _bump(tables["user_image"], f"{user}>{image}")
        if user:
            entity_totals[f"user:{user}"] += 1
        dest = dest_family(row)
        if dest and image:
            _bump(tables["dest"], f"{image}>{dest}")
        registry = registry_family(row.get("registry_path"))
        if registry:
            _bump(tables["registry"], registry)
        family = file_family(row.get("file_path"))
        if family:
            _bump(tables["file"], family)
        shape = cmd_shape(row.get("cmdline"), image)
        if shape:
            _bump(shape_table, shape, SHAPE_TOP_K)
        if user:
            hourly[f"user:{user}"][hour][day] += 1
            last_seen[f"user:{user}"] = stamp

    days = sorted(dates)
    buckets: dict[str, dict[str, dict]] = {}
    ranked_entities = [name for name, _ in
                       sorted(hourly.items(), key=lambda item: (-entity_totals.get(item[0], 0), item[0]))[:MAX_ENTITY_BUCKETS]]
    # Lifetime top-K alone excludes exactly the rare, low-and-slow entities
    # volume exists to watch. Add anything active near the fresh end of the
    # tail so the volume family can see it too (bounded, rate-neutral).
    chosen = set(ranked_entities)
    if rows:
        stamps = [stamp for stamp in (_row_time(row) for row in rows)
                  if stamp is not None]
        if stamps:
            cutoff = min(stamps) + 0.8 * (max(stamps) - min(stamps))
            for entity, hourly_stamps in last_seen.items():
                if len(chosen) >= MAX_ENTITY_BUCKETS + 100:
                    break
                if entity not in chosen and hourly_stamps >= cutoff:
                    ranked_entities.append(entity)
                    chosen.add(entity)
    for entity in ranked_entities:
        buckets[entity] = {}
        for hour in range(24):
            samples = hourly[entity].get(hour) or Counter()
            values = [samples.get(day, 0) for day in days]
            if not values:
                continue
            median, mad = _median_mad(values)
            buckets[entity][str(hour)] = {
                "median": round(median, 3),
                "mad": round(mad, 3),
                "days": len(days),
            }

    profile = {
        "schema": PROFILE_SCHEMA,
        "product": "Plasma",
        "kind": "host-profile",
        "host": _host(rows, host),
        "role": str(role or "unknown"),
        "built_at": _now(),
        "window": {
            "rows": len(rows),
            "since": since_dt.isoformat() if since_dt else None,
            "until": rows[-1].get("ts") if rows else None,
            "days": days[-31:],
        },
        "n": len(rows),
        "tables": {name: _final_table(table,
                                      SHAPE_TOP_K if name == "shape" else TOP_K)
                   for name, table in tables.items()},
        "hourly": buckets,
        "limits": {
            "min_observations": MIN_OBSERVATIONS,
            "min_bucket_days": MIN_BUCKET_DAYS,
            "top_k": TOP_K,
            "shape_top_k": SHAPE_TOP_K,
        },
    }
    return _sign(profile)


def save(path, profile: dict) -> dict:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    signed = _sign({key: value for key, value in profile.items()
                    if key != "integrity"})
    target.write_text(json.dumps(signed, indent=1, sort_keys=True,
                                 ensure_ascii=False) + "\n", encoding="utf-8")
    return {"ok": True, "profile": str(target),
            "bytes": target.stat().st_size, "host": signed.get("host")}


def load(path) -> dict:
    profile = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(profile, dict):
        raise TypeError("profile must be a JSON object")
    return profile


def _table_total(profile: dict, table: str) -> int:
    entry = (profile.get("tables") or {}).get(table) or {}
    try:
        return int(entry.get("total") or 0)
    except (TypeError, ValueError):
        return 0


def rarity(profile, table: str, key: str) -> dict | None:
    """How rare is ``key`` in this baseline? 0 common → 1 unseen.

    Returns None when the baseline is too small to judge, so a cold profile
    can never manufacture confidence.
    """
    if not profile or not key:
        return None
    minimum = int((profile.get("limits") or {}).get(
        "min_observations", MIN_OBSERVATIONS))
    # Confidence comes from the profile as a whole. A thin table (registry
    # paths only exist when a rule fires) still carries a real first-seen
    # signal; refusing to score it would hide exactly the rare event.
    if int(profile.get("n") or 0) < minimum:
        return None
    entry = (profile.get("tables") or {}).get(table) or {}
    counts = entry.get("counts") or {}
    total = _table_total(profile, table)
    if total <= 0:
        return None
    count = int(counts.get(key) or 0)
    if count == 0:
        return {"table": table, "key": key, "count": 0, "total": total,
                "value": 1.0, "first_seen": True}
    # The count is capped inside the math, not in the table: counts stay
    # honest for merge and diff, while a single burst (or deliberate
    # poisoning — 500 runs to look "common") cannot push a key past
    # RARITY_COUNT_CAP towards the familiar end of the scale.
    if int(count) >= int(total):
        return {"table": table, "key": key, "count": count, "total": total,
                "value": 0.0, "first_seen": False}
    capped = min(int(count), RARITY_COUNT_CAP)
    value = 1.0 - (math.log2(capped + 1) / math.log2(total + 1))
    return {"table": table, "key": key, "count": count, "total": total,
            "value": max(0.0, min(1.0, value)), "first_seen": False}


def volume(profile, entity: str, hour: int, observed: int) -> dict | None:
    """Robust z of an entity's hourly volume against the host baseline."""
    stats = ((profile.get("hourly") or {}).get(entity) or {}).get(str(hour))
    if not stats:
        return None
    days = int(stats.get("days") or 0)
    minimum = int((profile.get("limits") or {}).get(
        "min_bucket_days", MIN_BUCKET_DAYS))
    if days < minimum:
        return None
    median = float(stats.get("median") or 0)
    mad = float(stats.get("mad") or 0)
    if mad <= 0:
        # Constant baseline: only a clear step counts, and an hour that has
        # never seen the entity has no baseline to step over — bursts at
        # quiet hours are the rarity families' job, not volume's.
        if median <= 0 or observed < median * 3 + 5:
            return None
        return {"entity": entity, "hour": hour, "observed": observed,
                "median": median, "mad": mad, "z": None, "value": 1.0}
    z = 0.6745 * (observed - median) / mad
    # Spikes only: a volume DROP is quiet, not novel — abs(z) here scored
    # silence at full novelty (up to 10.0 on a lone benign logon).
    value = max(0.0, min(z, 6.0)) / 6.0
    return {"entity": entity, "hour": hour, "observed": observed,
            "median": median, "mad": mad, "z": round(z, 2),
            "value": round(value, 3)}


def merge(profiles: list[dict], name: str = "estate") -> dict:
    """Merge host profiles into one estate profile for cross-host rarity.

    Counts add exactly. Hourly robust statistics cannot be merged without
    the raw days, so the merged profile is deliberately marked as a
    rarity-only baseline.
    """
    if not profiles:
        raise ValueError("no profiles to merge")
    # One host can appear twice (two pulls, two windows); adding both would
    # double its counts. Keep the newest profile per host.
    newest: dict[str, dict] = {}
    for profile in profiles:
        host = str(profile.get("host") or "unknown")
        kept = newest.get(host)
        if kept is None or str(profile.get("built_at") or "") >= str(
                kept.get("built_at") or ""):
            newest[host] = profile
    profiles = list(newest.values())
    tables = {table: Counter() for table in TABLES}
    hosts, roles = [], []
    total = 0
    since = None
    until = None
    for profile in profiles:
        hosts.append(str(profile.get("host") or "unknown"))
        roles.append(str(profile.get("role") or "unknown"))
        total += int(profile.get("n") or 0)
        window = profile.get("window") or {}
        if window.get("since") and (since is None or window["since"] < since):
            since = window["since"]
        if window.get("until") and (until is None or window["until"] > until):
            until = window["until"]
        for table in TABLES:
            entry = (profile.get("tables") or {}).get(table) or {}
            for key, count in (entry.get("counts") or {}).items():
                tables[table][key] += int(count or 0)
    merged = {
        "schema": PROFILE_SCHEMA,
        "product": "Plasma",
        "kind": "estate-profile",
        "name": name,
        "host": name,
        "role": "estate",
        "built_at": _now(),
        "window": {"since": since, "until": until,
                   "days": sorted({day for profile in profiles
                                   for day in (profile.get("window") or {}).get("days", [])}),
                   "rows": total},
        "n": total,
        "hosts": sorted(hosts),
        "roles": sorted(set(roles)),
        "tables": {table: _final_table(counter)
                   for table, counter in tables.items()},
        "hourly": {},
        "limits": {"min_observations": MIN_OBSERVATIONS,
                   "min_bucket_days": MIN_BUCKET_DAYS,
                   "top_k": TOP_K, "shape_top_k": SHAPE_TOP_K},
        "merged": True,
    }
    return _sign(merged)


def diff(old: dict, new: dict, limit: int = 50) -> dict:
    """Compare two profiles: what appeared, vanished or changed volume."""
    result = {"ok": True, "old_host": old.get("host"),
              "new_host": new.get("host"), "tables": {}}
    score = 0.0
    for table in TABLES:
        before = ((old.get("tables") or {}).get(table) or {}).get("counts") or {}
        after = ((new.get("tables") or {}).get(table) or {}).get("counts") or {}
        added = sorted((key for key in after if key not in before),
                       key=lambda key: (-int(after[key]), key))
        removed = sorted((key for key in before if key not in after),
                         key=lambda key: (-int(before[key]), key))
        changed = sorted(
            ((key, int(before[key]), int(after[key]))
             for key in set(before) & set(after)
             if int(before[key]) != int(after[key])),
            key=lambda item: (-abs(item[2] - item[1]), item[0]))
        result["tables"][table] = {
            "added": [{"key": key, "count": int(after[key])}
                      for key in added[:limit]],
            "removed": [{"key": key, "count": int(before[key])}
                        for key in removed[:limit]],
            "changed": [{"key": key, "old": old_count, "new": new_count}
                        for key, old_count, new_count in changed[:limit]],
            "added_count": len(added), "removed_count": len(removed),
            "changed_count": len(changed),
        }
    # A new edge is the strongest single drift signal; images next.
    score += min(6.0, 1.5 * result["tables"]["parent_child"]["added_count"])
    score += min(3.0, 0.75 * result["tables"]["image"]["added_count"])
    score += min(1.0, 0.5 * result["tables"]["registry"]["added_count"])
    result["score"] = round(min(10.0, score), 1)
    return result


def summary(profile: dict) -> dict:
    """A compact, human/agent-readable view of one profile."""
    tables = profile.get("tables") or {}
    return {
        "ok": True,
        "host": profile.get("host"),
        "role": profile.get("role"),
        "kind": profile.get("kind"),
        "built_at": profile.get("built_at"),
        "n": profile.get("n"),
        "window": profile.get("window"),
        "hosts": profile.get("hosts"),
        "tables": {name: {"keys": len((tables.get(name) or {}).get("counts") or {}),
                          "total": _table_total(profile, name)}
                   for name in TABLES},
        "top_images": sorted(((tables.get("image") or {}).get("counts") or {}).items(),
                             key=lambda item: -item[1])[:10],
        "top_edges": sorted(((tables.get("parent_child") or {}).get("counts") or {}).items(),
                            key=lambda item: -item[1])[:10],
        "integrity": verify(profile),
        "bytes_estimate": len(json.dumps(profile, separators=(",", ":"))),
    }
