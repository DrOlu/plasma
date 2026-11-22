"""Plan-gated responder actions contributed by plugins.

A responder declares named actions as argv arrays. Plasma still owns the
plan: `act` without `--apply` renders the exact argv and returns a plan id;
applying requires that id and a reason, the kill switch is checked, and every
run is journaled with its rollback argv. There is no shell and no arbitrary
command: only the action's declared argv runs.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import killswitch, plugin_api, plugins

JOURNAL = "plugin-actions-journal.jsonl"
PLANS = "plugin-action-plans"
PLAN_TTL_SECONDS = 24 * 3600
TIMEOUT = 30
MAX_OUTPUT = 4000


def _journal_path(root) -> Path:
    return Path(root) / JOURNAL


def _plans_dir(root) -> Path:
    return Path(root) / PLANS


def _now() -> str:
    return plugin_api.now_iso()


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _python() -> str:
    return os.environ.get("PLASMA_PLUGIN_PYTHON") or (
        sys.executable if not getattr(sys, "frozen", False) else "python")


def load_actions(plugin_dir) -> list[dict]:
    manifest = plugin_api.load_manifest(plugin_dir)
    if manifest.get("kind") != "responder":
        raise plugin_api.PluginError(
            f"{manifest.get('name')} is a {manifest.get('kind')}, not a responder")
    name = manifest["name"]
    rel = manifest.get("actions") or "actions.json"
    path = Path(plugin_dir) / rel
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise plugin_api.PluginError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise plugin_api.PluginError(f"invalid actions.json: {exc}") from exc
    rows = payload.get("actions") if isinstance(payload, dict) else payload
    if not isinstance(rows, list) or not rows:
        raise plugin_api.PluginError("actions must be a non-empty list")
    actions = []
    for row in rows:
        if not isinstance(row, dict):
            raise plugin_api.PluginError("action must be an object")
        action = dict(row)
        action["plugin"] = name
        action["name"] = f"{name}.{action.get('name', '').split('.')[-1]}"
        for field in ("preview", "apply", "verify", "rollback"):
            value = action.get(field)
            if value is not None and (not isinstance(value, list) or not all(
                    isinstance(part, str) for part in value)):
                raise plugin_api.PluginError(
                    f"{action['name']}: {field} must be a list of strings")
        if not action.get("apply") or not action.get("preview"):
            raise plugin_api.PluginError(
                f"{action['name']}: preview and apply argv are required")
        actions.append(action)
    return actions


def list_actions(root) -> dict:
    rows = []
    for entry in plugins.list_plugins(root)["plugins"]:
        if entry.get("kind") != "responder" or not entry.get("present"):
            continue
        try:
            for action in load_actions(plugins.plugin_path(root, entry["name"])):
                rows.append({
                    "name": action["name"],
                    "plugin": action["plugin"],
                    "description": action.get("description", ""),
                    "args_schema": action.get("args_schema") or {},
                    "reversible": bool(action.get("reversible")),
                })
        except plugin_api.PluginError as exc:
            rows.append({"plugin": entry["name"], "error": str(exc)[:300]})
    return {"ok": True, "actions": rows}


def _find(root, name: str) -> tuple[dict, dict, Path]:
    for entry in plugins.list_plugins(root)["plugins"]:
        if entry.get("kind") != "responder" or not entry.get("present"):
            continue
        plugin_dir = plugins.plugin_path(root, entry["name"])
        try:
            actions = load_actions(plugin_dir)
        except plugin_api.PluginError:
            continue
        for action in actions:
            if action["name"] == name:
                manifest = plugin_api.load_manifest(plugin_dir)
                return action, manifest, plugin_dir
    raise plugin_api.PluginError(f"unknown plugin action {name!r}")


def _validate_args(action: dict, args: dict) -> None:
    schema = action.get("args_schema") or {}
    if not isinstance(args, dict):
        raise plugin_api.PluginError("args must be a JSON object")
    properties = schema.get("properties") or {}
    required = schema.get("required") or []
    unknown = sorted(set(args) - set(properties))
    if unknown:
        raise plugin_api.PluginError(f"unknown arguments: {', '.join(unknown)}")
    missing = [key for key in required if key not in args]
    if missing:
        raise plugin_api.PluginError(f"missing arguments: {', '.join(missing)}")
    for key, value in args.items():
        expected = (properties.get(key) or {}).get("type")
        if expected == "string" and not isinstance(value, str):
            raise plugin_api.PluginError(f"{key} must be a string")
        if expected == "integer" and (not isinstance(value, int)
                                      or isinstance(value, bool)):
            raise plugin_api.PluginError(f"{key} must be an integer")
        if isinstance(value, str) and len(value) > 1024:
            raise plugin_api.PluginError(f"{key} is too long")


def _allowed_roots(manifest: dict, root) -> list[str]:
    permissions = manifest.get("permissions") or {}
    values = permissions.get("filesystem") or []
    roots = []
    for value in values:
        expanded = str(value).replace("${root}", str(root))
        roots.append(os.path.abspath(expanded))
    return roots


def _check_paths(args: dict, manifest: dict, root) -> None:
    roots = _allowed_roots(manifest, root)
    if not roots:
        return
    for key, value in args.items():
        if not isinstance(value, str):
            continue
        if not any(sep in value for sep in ("/", "\\")):
            continue
        candidate = os.path.abspath(value)
        if not any(candidate == allowed or candidate.startswith(
                allowed + os.sep) for allowed in roots):
            raise plugin_api.PluginError(
                f"{key} is outside the plugin's permitted roots")


def _render(argv: list[str], args: dict) -> list[str]:
    rendered = []
    for part in argv:
        value = part
        for key, item in args.items():
            value = value.replace("{{" + key + "}}", str(item))
        if "{{" in value or "}}" in value:
            raise plugin_api.PluginError(f"unresolved placeholder in {part!r}")
        rendered.append(value)
    if rendered and rendered[0] in ("python", "python3"):
        rendered[0] = _python()
    return rendered


def preview(root, name: str, args: dict | None = None) -> dict:
    action, manifest, plugin_dir = _find(root, name)
    args = args or {}
    _validate_args(action, args)
    _check_paths(args, manifest, root)
    payload = {
        "action": name,
        "plugin": action["plugin"],
        "args": args,
        "preview": _render(action["preview"], args),
        "apply": _render(action["apply"], args),
        "verify": _render(action.get("verify") or [], args),
        "rollback": _render(action.get("rollback") or [], args),
        "reversible": bool(action.get("reversible")),
    }
    plan_id = _digest(payload)[:16]
    plan = {
        "plan_id": plan_id, "created_at": _now(), "root": str(root),
        "plugin_dir": str(plugin_dir), **payload,
    }
    target = _plans_dir(root) / f"{plan_id}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(plan, indent=1, sort_keys=True) + "\n",
                      encoding="utf-8")
    return {"ok": True, "dry_run": True, "plan_id": plan_id,
            "plan": str(target), "action": name, "args": args,
            "preview": payload["preview"], "reversible": payload["reversible"]}


def _run(argv: list[str], cwd: Path) -> dict:
    try:
        proc = subprocess.run(argv, cwd=str(cwd), capture_output=True,
                              text=True, timeout=TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "error": str(exc)[:300], "argv": argv}
    return {"ok": proc.returncode == 0, "exit_code": proc.returncode,
            "stdout": (proc.stdout or "")[:MAX_OUTPUT],
            "stderr": (proc.stderr or "")[:MAX_OUTPUT], "argv": argv}


def _journal(root, entry: dict) -> dict:
    entry = {"id": entry.get("id") or _digest(
        {**entry, "ts": _now()})[:12], "ts": _now(), **entry}
    path = _journal_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, separators=(",", ":"), default=str) + "\n")
    return entry


def apply(root, name: str, args: dict | None, plan_id: str,
          reason: str) -> dict:
    if not reason.strip():
        raise plugin_api.PluginError("--reason is required with --apply")
    if killswitch.blocked(root, host=socket.gethostname(), risk="high"):
        raise plugin_api.PluginError("kill switch is engaged")
    target = _plans_dir(root) / f"{plan_id}.json"
    if not target.exists():
        raise plugin_api.PluginError(f"unknown plan id {plan_id!r}")
    plan = json.loads(target.read_text(encoding="utf-8-sig"))
    args = args or {}
    if plan.get("action") != name or plan.get("args") != args:
        raise plugin_api.PluginError("plan does not match this action/args")
    try:
        created = datetime.fromisoformat(
            str(plan["created_at"]).replace("Z", "+00:00"))
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - created).total_seconds()
    except (KeyError, ValueError):
        age = PLAN_TTL_SECONDS + 1
    if age < 0 or age > PLAN_TTL_SECONDS:
        raise plugin_api.PluginError("plan has expired; preview again")
    entry_state = plugins.get(root, plan.get("plugin"))
    if not entry_state.get("enabled"):
        raise plugin_api.PluginError("plugin is disabled; enable it first")
    plugin_dir = Path(plan["plugin_dir"])
    applied = _run(plan["apply"], plugin_dir)
    verified = _run(plan["verify"], plugin_dir) if plan.get("verify") else None
    entry = _journal(root, {
        "kind": "apply", "action": name, "args": args, "reason": reason,
        "plugin": plan.get("plugin"), "plugin_dir": str(plugin_dir),
        "plan_id": plan_id,
        "argv": plan["apply"], "result": applied,
        "verify": verified,
        "undo_argv": plan.get("rollback") or [],
        "reversible": bool(plan.get("reversible")),
    })
    return {"ok": bool(applied.get("ok")) and (
        verified is None or bool(verified.get("ok"))),
        "journal_id": entry["id"], "action": name,
        "apply": applied, "verify": verified,
        "reversible": bool(plan.get("reversible"))}


def _load_journal(root) -> list[dict]:
    path = _journal_path(root)
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def undo(root, journal_id: str, reason: str) -> dict:
    if not reason.strip():
        raise plugin_api.PluginError("--reason is required with --undo")
    if killswitch.blocked(root, host=socket.gethostname(), risk="high"):
        raise plugin_api.PluginError("kill switch is engaged")
    rows = _load_journal(root)
    entry = next((row for row in rows
                  if row.get("id") == journal_id and row.get("kind") == "apply"),
                 None)
    if entry is None:
        raise plugin_api.PluginError(f"no applied action {journal_id!r}")
    argv = entry.get("undo_argv") or []
    if not argv:
        raise plugin_api.PluginError("this action is not reversible")
    result = _run(argv, Path(entry.get("plugin_dir") or root))
    journal = _journal(root, {
        "kind": "undo", "action": entry.get("action"),
        "undo_of": journal_id, "reason": reason, "argv": argv,
        "result": result,
    })
    return {"ok": bool(result.get("ok")), "journal_id": journal["id"],
            "undo_of": journal_id, "result": result}
