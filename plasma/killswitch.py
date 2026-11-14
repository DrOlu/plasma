"""Global and per-host kill switch for agent actions.

Reads stay available; every mutating tool is blocked while the switch is
engaged. The state is a small JSON file so a human or a supervising agent
can flip it without touching the harness.
"""

from __future__ import annotations

from pathlib import Path

from . import agentstate

SWITCH_FILE = "killswitch.json"


def path(root=None) -> Path:
    return agentstate.base(root) / SWITCH_FILE


def status(root=None) -> dict:
    data = agentstate.read_json(path(root), {}) or {}
    return {
        "global": bool(data.get("global", False)),
        "hosts": dict(data.get("hosts") or {}),
        "reason": data.get("reason", ""),
        "at": data.get("at"),
    }


def _save(root, data: dict) -> dict:
    data = dict(data)
    data["at"] = agentstate.now_iso()
    agentstate.write_json(path(root), data)
    return status(root)


def set_global(root, enabled: bool, reason: str = "", actor: str = "cli") -> dict:
    data = agentstate.read_json(path(root), {}) or {}
    data["global"] = bool(enabled)
    data["reason"] = reason
    data["actor"] = actor
    return _save(root, data)


def set_host(root, host: str, enabled: bool, reason: str = "",
             actor: str = "cli") -> dict:
    data = agentstate.read_json(path(root), {}) or {}
    hosts = dict(data.get("hosts") or {})
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