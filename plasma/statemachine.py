"""Small, explicit state machines for workflows that used to be implicit.

Each machine names its states and allowed transitions. Transitions are
validated and persisted atomically under ``<root>/state/<name>.json`` with
a short history, so a crash leaves a recoverable record instead of a
half-remembered phase.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from . import agentstate


class StateError(ValueError):
    pass


@dataclass(frozen=True)
class Machine:
    name: str
    states: tuple[str, ...]
    transitions: dict[str, tuple[str, ...]]
    initial: str
    terminal: tuple[str, ...] = ()

    def allows(self, current: str, target: str) -> bool:
        return current in self.states and target in self.transitions.get(current, ())

    def next_states(self, current: str) -> tuple[str, ...]:
        return self.transitions.get(current, ())


def state_path(root, name: str) -> Path:
    return agentstate.base(root) / "state" / f"{name}.json"


def load(root, machine: Machine) -> dict:
    data = agentstate.read_json(state_path(root, machine.name), {}) or {}
    if data.get("state") not in machine.states:
        data = {"state": machine.initial, "history": []}
    data.setdefault("history", [])
    return data


def save(root, machine: Machine, data: dict) -> dict:
    agentstate.write_json(state_path(root, machine.name), data)
    return data


def transition(root, machine: Machine, target: str, detail=None) -> dict:
    data = load(root, machine)
    current = data["state"]
    if target == current:
        return data
    if not machine.allows(current, target):
        raise StateError(
            f"{machine.name}: illegal transition {current!r} -> {target!r}")
    data["state"] = target
    data["history"].append({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "from": current,
        "to": target,
        "detail": detail,
    })
    data["history"] = data["history"][-50:]
    return save(root, machine, data)


def reset(root, machine: Machine, detail=None) -> dict:
    data = load(root, machine)
    data["history"].append({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "from": data["state"], "to": machine.initial, "detail": detail,
    })
    data["state"] = machine.initial
    data["history"] = data["history"][-50:]
    return save(root, machine, data)


UPDATE_MACHINE = Machine(
    name="update",
    states=("idle", "staged", "verified", "installing", "installed", "rotated", "failed"),
    initial="idle",
    terminal=("rotated",),
    transitions={
        "idle": ("staged", "failed"),
        "staged": ("verified", "failed"),
        "verified": ("installing", "failed"),
        "installing": ("installed", "failed"),
        "installed": ("rotated", "failed"),
        "rotated": ("idle", "staged", "failed"),
        "failed": ("idle", "staged"),
    },
)