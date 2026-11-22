"""Plugin registry and lifecycle.

Installing a plugin is an explicit, verified copy into
``<root>/plugins/<name>``. The registry records the manifest summary, the
payload digest, whether the plugin was signed, and whether it is enabled.
Nothing is auto-enabled: an operator enables a plugin after reviewing what
it is allowed to do.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from . import agentstate, plugin_api

REGISTRY = "registry.json"
SCHEMA = 1
_IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", ".git",
                                 ".pytest_cache")


def plugins_dir(root) -> Path:
    return Path(root) / "plugins"


def registry_path(root) -> Path:
    return plugins_dir(root) / REGISTRY


def _load_registry(root) -> dict:
    path = registry_path(root)
    if not path.exists():
        return {"version": SCHEMA, "plugins": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return {"version": SCHEMA, "plugins": {}}
    if not isinstance(data, dict) or not isinstance(data.get("plugins"), dict):
        return {"version": SCHEMA, "plugins": {}}
    data.setdefault("version", SCHEMA)
    return data


def _save_registry(root, data: dict) -> None:
    path = registry_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    agentstate.write_json(path, data)


def plugin_path(root, name: str) -> Path:
    return plugins_dir(root) / name


def install(root, source, allow_unsigned: bool = False, trust_key=None,
            force: bool = False, enable: bool = False) -> dict:
    source_path = Path(source).resolve()
    manifest = plugin_api.load_manifest(source_path)
    name = manifest["name"]
    target = plugin_path(root, name)
    if target.exists() and not force:
        raise plugin_api.PluginError(
            f"plugin {name!r} is already installed (use --force)")
    verification = plugin_api.verify_signature(source_path, trust_key=trust_key)
    if not verification.get("ok") and not allow_unsigned:
        raise plugin_api.PluginError(
            f"refusing unsigned/untrusted plugin: {verification.get('reason')}")
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source_path, target, ignore=_IGNORE)
    digest = plugin_api.payload_digest(target)
    registry = _load_registry(root)
    registry["plugins"][name] = {
        "name": name,
        "version": manifest["version"],
        "kind": manifest["kind"],
        "runtime": manifest.get("runtime", "native"),
        "path": f"plugins/{name}",
        "enabled": bool(enable),
        "installed_at": plugin_api.now_iso(),
        "digest": digest,
        "signed": bool(verification.get("signed")),
        "fingerprint": verification.get("fingerprint"),
        "status": "installed",
        "last_run": None,
    }
    _save_registry(root, registry)
    return {
        "ok": True, "name": name, "version": manifest["version"],
        "kind": manifest["kind"], "path": str(target),
        "enabled": bool(enable), "signed": bool(verification.get("signed")),
        "fingerprint": verification.get("fingerprint"),
        "digest": digest,
    }


def uninstall(root, name: str) -> dict:
    registry = _load_registry(root)
    if name not in registry["plugins"]:
        raise plugin_api.PluginError(f"plugin {name!r} is not installed")
    target = plugin_path(root, name)
    if target.exists():
        shutil.rmtree(target)
    entry = registry["plugins"].pop(name)
    _save_registry(root, registry)
    return {"ok": True, "name": name, "removed": entry.get("path")}


def set_enabled(root, name: str, enabled: bool) -> dict:
    registry = _load_registry(root)
    entry = registry["plugins"].get(name)
    if entry is None:
        raise plugin_api.PluginError(f"plugin {name!r} is not installed")
    entry["enabled"] = bool(enabled)
    entry["status"] = "enabled" if enabled else "disabled"
    _save_registry(root, registry)
    return {"ok": True, "name": name, "enabled": bool(enabled),
            "status": entry["status"]}


def get(root, name: str) -> dict:
    entry = _load_registry(root)["plugins"].get(name)
    if entry is None:
        raise plugin_api.PluginError(f"plugin {name!r} is not installed")
    return entry


def load_installed(root, name: str) -> tuple[dict, dict, Path]:
    entry = get(root, name)
    path = plugin_path(root, name)
    manifest = plugin_api.load_manifest(path)
    return entry, manifest, path


def list_plugins(root) -> dict:
    registry = _load_registry(root)
    rows = []
    for name, entry in sorted(registry["plugins"].items()):
        row = dict(entry)
        path = plugin_path(root, name)
        row["present"] = path.exists()
        if row["present"]:
            try:
                manifest = plugin_api.load_manifest(path)
                row["description"] = manifest.get("description", "")
                row["capabilities"] = manifest.get("capabilities", [])
            except plugin_api.PluginError as exc:
                row["status"] = "broken"
                row["error"] = str(exc)[:300]
        rows.append(row)
    return {"ok": True, "plugins": rows,
            "enabled": [row["name"] for row in rows if row.get("enabled")]}


def verify(root, name: str, trust_key=None) -> dict:
    entry = get(root, name)
    path = plugin_path(root, name)
    verdict = plugin_api.verify_signature(path, trust_key=trust_key)
    digest = plugin_api.payload_digest(path)
    integrity = digest == entry.get("digest")
    result = {"name": name, "installed_digest": entry.get("digest"),
              "current_digest": digest, "integrity": integrity, **verdict}
    result["ok"] = bool(result.get("ok") and integrity)
    if not integrity:
        result["reason"] = "installed payload changed since installation"
    return result


def health(root, name: str) -> dict:
    entry, manifest, path = load_installed(root, name)
    block = manifest.get("health") or {}
    command = block.get("command") if isinstance(block, dict) else None
    if isinstance(command, list) and command:
        argv = [str(part) for part in command]
        try:
            proc = subprocess.run(
                argv, cwd=str(path), capture_output=True, text=True,
                timeout=15, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return {"ok": False, "name": name, "status": "unhealthy",
                    "error": str(exc)[:300]}
        return {
            "ok": proc.returncode == 0, "name": name,
            "status": "healthy" if proc.returncode == 0 else "unhealthy",
            "exit_code": proc.returncode,
            "stdout": (proc.stdout or "")[:500],
            "stderr": (proc.stderr or "")[:500],
        }
    return {"ok": entry.get("enabled", False) is not False, "name": name,
            "status": entry.get("status", "unknown"),
            "enabled": entry.get("enabled", False),
            "last_run": entry.get("last_run"),
            "note": "manifest declares no health command"}


def update_run(root, name: str, status: str, detail: dict | None = None) -> None:
    registry = _load_registry(root)
    entry = registry["plugins"].get(name)
    if entry is None:
        return
    entry["last_run"] = plugin_api.now_iso()
    entry["status"] = status
    if detail is not None:
        entry["last_result"] = detail
    _save_registry(root, registry)


# ---------------------------------------------------------------------------
# scaffold
# ---------------------------------------------------------------------------

_SENSOR_TEMPLATE = '''#!/usr/bin/env python3
"""Sample Plasma sensor: emit bounded NDJSON events on stdout."""
import json
import os
import sys
import time


def main() -> int:
    limit = int(os.environ.get("PLASMA_PLUGIN_MAX_EVENTS", "10"))
    for index in range(limit):
        sys.stdout.write(json.dumps({
            "v": 1, "type": "event", "plugin": "NAME", "seq": index,
            "event": {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "kind": "process", "process": "sample-sensor.exe",
                "parent": "explorer.exe", "user": "CORP\\\\sample",
                "pid": 4000 + index, "score": 0.1,
                "description": "sample plugin event"
            }
        }) + "\\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''

_DETECTOR_TEMPLATE = '''#!/usr/bin/env python3
"""Sample Plasma detector: read events, print NDJSON findings."""
import argparse
import json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", required=True)
    parser.add_argument("--since", default=None)
    parser.add_argument("--max-rows", type=int, default=1000)
    args = parser.parse_args()
    watched = {"mimikatz.exe", "psexec.exe"}
    with open(args.events, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle.readlines()[-args.max_rows:]:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if str(row.get("process") or "").lower() in watched:
                print(json.dumps({
                    "v": 1, "type": "finding", "plugin": "NAME",
                    "finding": {
                        "description": "sample detector: watched process "
                                       + str(row.get("process")),
                        "score": 0.8, "technique": "T1059",
                        "evidence": [str(row.get("ts")),
                                     str(row.get("process"))]
                    }
                }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''

_RESPONDER_TEMPLATE = '''#!/usr/bin/env python3
"""Sample Plasma responder: create, verify and remove one file."""
import os
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: action.py preview|apply|verify|rollback <path>")
        return 2
    mode, path = sys.argv[1], sys.argv[2]
    if mode == "preview":
        print("would create", path)
        return 0
    if mode == "apply":
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("created by sample responder\\n")
        return 0
    if mode == "verify":
        return 0 if os.path.isfile(path) else 1
    if mode == "rollback":
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
'''


def scaffold(out, name: str, kind: str = "sensor") -> dict:
    if not plugin_api.NAME.match(name):
        raise plugin_api.PluginError("name must be lowercase letters/digits/._-")
    if kind not in plugin_api.KINDS:
        raise plugin_api.PluginError(f"kind must be one of {sorted(plugin_api.KINDS)}")
    target = Path(out) / name
    if target.exists():
        raise plugin_api.PluginError(f"target already exists: {target}")
    target.mkdir(parents=True)
    entry = "sensor.py" if kind == "sensor" else (
        "detector.py" if kind == "detector" else "action.py")
    template = {
        "sensor": _SENSOR_TEMPLATE,
        "detector": _DETECTOR_TEMPLATE,
        "responder": _RESPONDER_TEMPLATE,
    }.get(kind, _SENSOR_TEMPLATE)
    (target / entry).write_text(template.replace("NAME", name), encoding="utf-8")
    manifest = {
        "api_version": plugin_api.API_VERSION,
        "name": name,
        "version": "0.1.0",
        "kind": kind,
        "description": f"sample {kind} plugin",
        "entrypoint": entry,
        "runtime": "python",
        "protocol": "ndjson-stdio",
        "capabilities": ["event.process"] if kind == "sensor" else [],
        "limits": {"max_events": 1000, "max_line_bytes": 65536,
                   "timeout_seconds": 60},
    }
    if kind == "responder":
        manifest["actions"] = "actions.json"
        manifest["permissions"] = {"filesystem": ["${root}/plugin-samples"]}
        (target / "actions.json").write_text(json.dumps({
            "actions": [{
                "name": f"{name}.touch",
                "description": "create and remove a sample file",
                "args_schema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
                "preview": ["python", entry, "preview", "{{path}}"],
                "apply": ["python", entry, "apply", "{{path}}"],
                "verify": ["python", entry, "verify", "{{path}}"],
                "rollback": ["python", entry, "rollback", "{{path}}"],
                "reversible": True,
            }]
        }, indent=1) + "\n", encoding="utf-8")
    (target / "plugin.json").write_text(
        json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    (target / "README.md").write_text(
        f"# {name}\n\nGenerated by `plasma plugin new`. See docs/plugin-api.md.\n",
        encoding="utf-8")
    return {"ok": True, "path": str(target), "kind": kind,
            "manifest": str(target / "plugin.json")}
