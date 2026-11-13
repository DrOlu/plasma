"""Deployment rings: canary, broad, rollback.

Agents can plan an update, but membership in a ring is a local, human-set
fact. A host outside the requested ring refuses the update. Rollback uses
the previous canonical binary that the updater already keeps beside the
current one.
"""

from __future__ import annotations

import os
from pathlib import Path

from . import agentstate

RINGS_FILE = "rings.json"
DEFAULT_RINGS = ("canary", "broad")


def path(root=None) -> Path:
    return agentstate.base(root) / RINGS_FILE


def _load(root) -> dict:
    data = agentstate.read_json(path(root), {}) or {}
    rings = data.get("rings")
    if not isinstance(rings, dict):
        rings = {name: [] for name in DEFAULT_RINGS}
    for name in DEFAULT_RINGS:
        rings.setdefault(name, [])
    current = data.get("current") or "broad"
    if current not in rings:
        current = "broad"
    return {"version": 1, "current": current, "rings": rings}


def _save(root, data: dict) -> dict:
    agentstate.write_json(path(root), data)
    return data


def status(root=None) -> dict:
    data = _load(root)
    return {"current": data["current"],
            "rings": {k: sorted(set(v)) for k, v in data["rings"].items()}}


def assign(root, host: str, ring: str = "canary") -> dict:
    data = _load(root)
    if ring not in data["rings"]:
        raise ValueError(f"unknown ring {ring!r}")
    for name, hosts in data["rings"].items():
        data["rings"][name] = [h for h in hosts if h != host]
    data["rings"][ring].append(host)
    data["rings"][ring] = sorted(set(data["rings"][ring]))
    _save(root, data)
    return status(root)


def remove_host(root, host: str) -> dict:
    data = _load(root)
    for name in data["rings"]:
        data["rings"][name] = [h for h in data["rings"][name] if h != host]
    _save(root, data)
    return status(root)


def promote(root, ring: str) -> dict:
    data = _load(root)
    if ring not in data["rings"]:
        raise ValueError(f"unknown ring {ring!r}")
    data["current"] = ring
    _save(root, data)
    return status(root)


def allows(root, host: str, ring: str | None = None) -> bool:
    data = _load(root)
    target = ring or data["current"]
    if target not in data["rings"]:
        return False
    return host in data["rings"][target] or "*" in data["rings"][target]


def rollback(bin_exe) -> dict:
    """Swap the canonical bin copy back to the previous release."""
    bin_exe = Path(bin_exe)
    previous = bin_exe.with_name(bin_exe.name + ".old")
    if not previous.exists():
        return {"ok": False, "error": "no previous binary beside the current one",
                "expected": str(previous)}
    if bin_exe.exists():
        current = bin_exe.with_name(bin_exe.name + ".failed")
        os.replace(bin_exe, current)
    os.replace(previous, bin_exe)
    return {"ok": True, "bin": str(bin_exe), "restored_from": str(previous)}