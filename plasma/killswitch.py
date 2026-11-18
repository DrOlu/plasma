"""Global and per-host kill switch for agent actions.

Reads stay available; every mutating tool is blocked while the switch is
engaged. The state is a small JSON file so a human or a supervising agent
can flip it without touching the harness.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import agentstate

SWITCH_FILE = "killswitch.json"


def path(root=None) -> Path:
    return agentstate.base(root) / SWITCH_FILE


def status(root=None) -> dict:
    state_path = path(root)
    if state_path.exists():
        try:
            data = json.loads(state_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            # Fail closed: an unreadable switch must not silently disable
            # containment.
            return {"global": True, "hosts": {},
                    "reason": "killswitch state unreadable — failing closed",
                    "at": None, "error": "unreadable"}
    else:
        data = {}
    if not isinstance(data, dict):
        return {"global": True, "hosts": {},
                "reason": "killswitch state is not an object — failing closed",
                "at": None, "error": "invalid"}
    hosts = data.get("hosts")
    if hosts is None:
        hosts = {}
    if not isinstance(hosts, dict):
        return {"global": True, "hosts": {},
                "reason": "killswitch hosts state is not an object — failing closed",
                "at": None, "error": "invalid"}
    return {
        "global": bool(data.get("global", False)),
        "hosts": dict(hosts),
        "reason": data.get("reason", ""),
        "at": data.get("at"),
    }


def _save(root, data: dict) -> dict:
    data = dict(data)
    data["at"] = agentstate.now_iso()
    agentstate.write_json(path(root), data)
    return status(root)


def set_global(root, enabled: bool, reason: str = "", actor: str = "cli") -> dict:
    with agentstate.lock(path(root).with_suffix(".lock"), stale=300):
        return _set_global(root, enabled, reason, actor)


def _set_global(root, enabled: bool, reason: str = "", actor: str = "cli") -> dict:
    data = agentstate.read_json(path(root), {}) or {}
    if not isinstance(data, dict):
        data = {}
    data["global"] = bool(enabled)
    data["reason"] = reason
    data["actor"] = actor
    return _save(root, data)


def set_host(root, host: str, enabled: bool, reason: str = "",
             actor: str = "cli") -> dict:
    with agentstate.lock(path(root).with_suffix(".lock"), stale=300):
        return _set_host(root, host, enabled, reason, actor)


def _set_host(root, host: str, enabled: bool, reason: str = "",
              actor: str = "cli") -> dict:
    data = agentstate.read_json(path(root), {}) or {}
    if not isinstance(data, dict):
        data = {}
    hosts = dict(data.get("hosts") or {}) if isinstance(data.get("hosts"), dict) else {}
    if enabled:
        hosts[host] = {"reason": reason, "actor": actor,
                       "at": agentstate.now_iso()}
    else:
        hosts.pop(host, None)
    data["hosts"] = hosts
    data["reason"] = reason or data.get("reason", "")
    return _save(root, data)


def blocked(root=None, host: str | None = None, risk: str = "medium") -> bool:
    if risk == "read":
        return False
    state = status(root)
    if state["global"]:
        return True
    if host:
        # Windows hostnames are case-insensitive; the switch is stored as
        # entered by the operator, the caller may use either case.
        wanted = str(host).strip().lower()
        if any(str(h).strip().lower() == wanted for h in state["hosts"]):
            return True
    return False