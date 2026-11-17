"""Measured protection posture.

Plasma ships armed, but narrowly: automatic containment is limited to
``snapshot`` + ``kill_process`` at score 9+, with a per-run cap and a
cooldown. Every other response action — host isolation, disabling users,
removing admins, stopping services, blocking IPs — stays behind human
approval. Inline prevention remains audit-first and opt-in.

This module is the single place that defines that posture, migrates the
old "off by default" block, and exposes ``plasma protect``.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import actuate, agentstate, enforce, killswitch

# The measured default is the enforcement engine's default. Keeping one
# source of truth prevents the installer, the runtime and the docs from
# drifting apart.
MEASURED_ENFORCEMENT: dict = dict(enforce.DEFAULT_POLICY)

# The pre-1.17 default. An upgrade replaces exactly this block; a custom
# operator block is preserved.
LEGACY_ENFORCEMENT: dict = {
    "enabled": False,
    "mode": "dry-run",
    "min_score": 9,
    "allowed_actions": ["kill_process"],
    "require_approval": ["isolate_host"],
    "cooldown_minutes": 30,
    "max_actions_per_run": 2,
    "watch_task": "disabled",
    "watch_every_minutes": 0,
}

# The keys that identify the pre-1.17 default. An old config does not have
# the watch_task keys, so migration must not require them.
LEGACY_KEYS = ("enabled", "mode", "min_score", "allowed_actions",
               "require_approval", "cooldown_minutes", "max_actions_per_run")

DEFAULT_PREVENTION: dict = {
    "applocker": {"mode": "audit"},
    "egress": {"applied": False},
}


def config_path(root=None) -> Path:
    return agentstate.base(root) / "config.json"


def load_config(root=None) -> dict:
    try:
        data = json.loads(config_path(root).read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def save_config(root, config: dict) -> dict:
    path = config_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with agentstate.lock(path.with_suffix(".lock"), stale=300):
        path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return config


def migrate_enforcement(previous) -> dict:
    """Return the effective enforcement block for an install/upgrade.

    * missing or empty -> measured default
    * exactly the old default -> measured default
    * anything else -> the operator's block, with measured defaults filled in
    """
    if not isinstance(previous, dict) or not previous:
        return dict(MEASURED_ENFORCEMENT)
    if all(previous.get(k) == LEGACY_ENFORCEMENT[k] for k in LEGACY_KEYS):
        return dict(MEASURED_ENFORCEMENT)
    merged = dict(MEASURED_ENFORCEMENT)
    merged.update(previous)
    for key in ("allowed_actions", "require_approval", "deny_techniques",
                "allow_techniques"):
        value = merged.get(key)
        merged[key] = list(value) if isinstance(value, (list, tuple)) else []
    return merged


def protected() -> dict:
    """The components the response layer refuses to touch."""
    return {
        "services": sorted(actuate.PROTECTED_SERVICES),
        "processes": sorted(actuate.PROTECTED_PROCESSES),
        "accounts": sorted(actuate.PROTECTED_ACCOUNTS),
        "paths": list(actuate.PROTECTED_PATH_PREFIXES),
    }


def status(root=None) -> dict:
    config = load_config(root)
    policy = enforce.load_policy(root)
    prevention = config.get("prevention")
    if not isinstance(prevention, dict):
        prevention = dict(DEFAULT_PREVENTION)
    ks = killswitch.status(root)
    return {
        "ok": True,
        "root": str(agentstate.base(root)),
        "armed": bool(policy.get("enabled") and policy.get("mode") == "enforce"),
        "detection": {"enabled": True, "mode": "always-on"},
        "containment": policy,
        "prevention": prevention,
        "killswitch": ks,
        "protected": protected(),
    }


def arm(root=None, apply_prevention: bool = False,
        reason: str | None = None) -> dict:
    """Write the measured containment policy. Optionally apply AppLocker audit."""
    config = load_config(root)
    config["enforcement"] = dict(MEASURED_ENFORCEMENT)
    prevention = config.get("prevention")
    if not isinstance(prevention, dict):
        prevention = dict(DEFAULT_PREVENTION)
    prevention.setdefault("applocker", {"mode": "audit"})
    prevention.setdefault("egress", {"applied": False})
    config["prevention"] = prevention
    save_config(root, config)

    result = {
        "ok": True,
        "armed": True,
        "policy": dict(MEASURED_ENFORCEMENT),
        "prevention": prevention,
        "note": ("automatic containment is limited to snapshot + kill_process "
                 "at score 9+; every other action requires approval"),
    }
    if apply_prevention:
        if not reason or not str(reason).strip():
            return {"ok": False, "error": "--apply-prevention requires --reason",
                    "armed": True, "policy": dict(MEASURED_ENFORCEMENT)}
        from . import prevent
        dry = prevent.applocker(root, mode="audit", apply=False)
        if "error" in dry:
            return {"ok": False, "error": dry["error"], "armed": True,
                    "policy": dict(MEASURED_ENFORCEMENT)}
        applied = prevent.applocker(root, mode="audit", apply=True,
                                    plan=dry["id"], reason=reason)
        result["prevention_plan"] = dry.get("id")
        result["prevention_result"] = applied
        if "error" in applied:
            result["ok"] = False
            result["error"] = applied["error"]
    return result


def disarm(root=None, reason: str | None = None) -> dict:
    """Turn automatic containment off; keep the allowlist for a later arm."""
    config = load_config(root)
    block = config.get("enforcement")
    if not isinstance(block, dict):
        block = dict(MEASURED_ENFORCEMENT)
    block["enabled"] = False
    block["mode"] = "dry-run"
    config["enforcement"] = block
    save_config(root, config)
    return {
        "ok": True,
        "armed": False,
        "policy": block,
        "reason": reason,
        "note": "automatic containment is off; reads and dry-runs remain",
    }
