"""Plasma FIM: critical-file integrity, not just ransomware decoys.

Canaries answer "did something destroy a decoy?" — impact. File integrity
monitoring answers the compliance question: "did a critical file change?"
This module records (path, sha256, size) for a configurable set of paths and
diffs it on demand or during `watch`.

    baseline -> write root/fim.json
    verify   -> added / modified / removed findings
    status   -> manifest summary

Paths are expanded as globs, so a directory rule can be expressed as
``C:\\Windows\\System32\\drivers\\etc\\*``. The default set stays small and
high-value; operators add their own with `--path`.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from . import agentstate

MANIFEST_NAME = "fim.json"
MAX_ENTRIES = 5000
MAX_FILE_BYTES = 32 * 1024 * 1024

DEFAULT_PATHS = [
    r"C:\Windows\System32\drivers\etc\hosts",
    r"C:\Windows\System32\drivers\etc\services",
    r"C:\Windows\System32\drivers\etc\networks",
    r"C:\ProgramData\Plasma\config.json",
    r"C:\Program Files\Whids\config.toml",
]

SCORES = {"modified": 8, "removed": 8, "added": 6}


def manifest_path(root) -> Path:
    return Path(root) / MANIFEST_NAME


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _expand(paths) -> tuple[list[Path], int]:
    """Expand globs into a bounded, de-duplicated file list."""
    seen: dict[str, Path] = {}
    skipped = 0
    for pattern in paths:
        p = Path(pattern)
        candidates = [p] if p.is_file() else p.parent.glob(p.name)
        for cand in candidates:
            if not cand.is_file():
                continue
            try:
                size = cand.stat().st_size
            except OSError:
                skipped += 1
                continue
            if size > MAX_FILE_BYTES:
                skipped += 1
                continue
            key = str(cand.resolve())
            if key not in seen:
                seen[key] = cand
            if len(seen) >= MAX_ENTRIES:
                return list(seen.values()), skipped
    return list(seen.values()), skipped


def baseline(root, paths=None) -> dict:
    root = Path(root)
    patterns = list(paths or DEFAULT_PATHS)
    files, skipped = _expand(patterns)
    entries = []
    for path in files:
        try:
            entries.append({"path": str(path.resolve()),
                            "sha256": _sha256(path),
                            "size": path.stat().st_size})
        except OSError:
            skipped += 1
    manifest = {
        "baseline_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "paths": patterns,
        "entries": entries,
    }
    agentstate.write_json(manifest_path(root), manifest)
    return {"baselined": len(entries), "skipped": skipped,
            "manifest": str(manifest_path(root)),
            "paths": patterns}


def _load(root):
    mpath = manifest_path(root)
    if not mpath.exists():
        return None, {"error": "no FIM baseline — run: plasma fim baseline",
                      "checked": 0, "findings": [], "top_score": 0}
    try:
        return json.loads(mpath.read_text(encoding="utf-8-sig")), None
    except (OSError, json.JSONDecodeError) as exc:
        return None, {"error": f"FIM manifest unreadable: {exc}",
                      "checked": 0, "findings": [], "top_score": 0}


def verify(root) -> dict:
    manifest, error = _load(root)
    if error:
        return error
    findings = []
    checked = 0
    recorded = set()
    for entry in manifest.get("entries", []):
        checked += 1
        path = Path(entry.get("path", ""))
        key = str(path)
        recorded.add(key)
        if not path.exists():
            findings.append({"type": "fim_removed", "path": key,
                             "score": SCORES["removed"],
                             "detail": "critical file removed"})
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                findings.append({"type": "fim_oversize", "path": key,
                                 "score": SCORES["modified"],
                                 "detail": "critical file exceeds the size bound"})
                continue
            digest = _sha256(path)
        except OSError:
            findings.append({"type": "fim_unreadable", "path": key,
                             "score": SCORES["modified"],
                             "detail": "critical file unreadable"})
            continue
        if digest != entry.get("sha256"):
            findings.append({"type": "fim_modified", "path": key,
                             "score": SCORES["modified"],
                             "detail": "critical file hash changed"})

    # New files matching a recorded glob are additions, not replacements.
    current, _ = _expand(manifest.get("paths", []))
    for path in current:
        key = str(path.resolve())
        if key not in recorded:
            findings.append({"type": "fim_added", "path": key,
                             "score": SCORES["added"],
                             "detail": "new file matched a monitored path"})
    return {
        "checked": checked,
        "findings": findings,
        "added": sum(1 for f in findings if f["type"] == "fim_added"),
        "modified": sum(1 for f in findings if f["type"] == "fim_modified"),
        "removed": sum(1 for f in findings if f["type"] == "fim_removed"),
        "top_score": max((f["score"] for f in findings), default=0),
        "verdict": "integrity changed" if findings else "integrity intact",
    }


def status(root) -> dict:
    manifest, error = _load(root)
    if error:
        return {"baselined": False, **error}
    return {"baselined": True,
            "manifest": str(manifest_path(root)),
            "baseline_at": manifest.get("baseline_at"),
            "entries": len(manifest.get("entries", [])),
            "paths": manifest.get("paths", [])}
