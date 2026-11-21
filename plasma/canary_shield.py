"""Active canary shield: a canary that kills the process that touches it.

Passive canaries detect impact after the fact. The shield closes the gap
between "the canary was modified" and "the process that modified it is
still running".

How it works:

* canary files and decoy registry keys are tagged in a **narrow** Sysmon
  include. Sysmon records FileCreate/FileDelete and RegistryEvent for those
  objects only;
* a SYSTEM task runs ``canary shield sweep --apply`` every minute;
* the sweep reads the Sysmon channel, proves the accessing process still
  exists and still has the recorded image, refuses protected/trusted
  processes, then kills the process and journals the decision.

No kernel driver. No broad file auditing. No read/open trigger: only
create, overwrite, delete and registry writes count. A user merely opening a
canary is not killed; Explorer deleting a canary is skipped; Plasma itself
is skipped. That is the false-positive boundary, stated explicitly.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import time
import uuid
from pathlib import Path
from xml.etree import ElementTree as ET

from . import actuate, agentstate, canary, killswitch

TASK_NAME = "PlasmaCanaryShield"
CONFIG_NAME = "canary-shield.json"
STATE_NAME = "canary-shield-state.json"
JOURNAL_NAME = "canary-shield-journal.jsonl"
PLAN_NAME = "canary-shield-plans.jsonl"
REGISTRY_NAME = "registry-canaries.json"
SYSMON_CONFIG = "plasma-sysmon-baseline.xml"
SYSMON_BACKUP = "plasma-sysmon-pre-shield.xml"
MAX_KILLS = 5
DEFAULT_SINCE_MINUTES = 10

DEFAULT_TRUSTED = (
    "explorer.exe", "dllhost.exe", "searchprotocolhost.exe",
    "searchindexer.exe", "msmpeng.exe", "mssense.exe", "sense.exe",
    "plasma.exe", "plasma-1.25.0-windows-x64.exe", "msiexec.exe",
    "svchost.exe", "system", "registry", "idle", "taskhostw.exe",
)

IS_WINDOWS = os.name == "nt"

_FILE_EVENTS = {11, 23}
_REGISTRY_EVENTS = {12, 13, 14}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _file_canaries(root) -> list[dict]:
    try:
        blob = json.loads(canary.manifest_path(root).read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return []
    rows = blob.get("canaries") if isinstance(blob, dict) else None
    return rows if isinstance(rows, list) else []


def _base(value) -> str:
    return str(value or "").replace("\\", "/").rsplit("/", 1)[-1].lower()


def _norm_path(value) -> str:
    text = str(value or "").strip().replace("/", "\\")
    for prefix in ("\\??\\", "\\\\?\\"):
        text = text.removeprefix(prefix)
    return text.lower()


def _pid(value):
    text = str(value or "").strip().lower()
    if not text or text == "-":
        return None
    try:
        number = int(text, 16) if text.startswith("0x") else int(text)
    except (TypeError, ValueError):
        return None
    return number if 1 <= number <= 2_147_483_647 else None


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def config_path(root) -> Path:
    return Path(root) / CONFIG_NAME


def state_path(root) -> Path:
    return Path(root) / STATE_NAME


def journal_path(root) -> Path:
    return Path(root) / JOURNAL_NAME


def plan_path(root) -> Path:
    return Path(root) / PLAN_NAME


def registry_path(root) -> Path:
    return Path(root) / REGISTRY_NAME


# ---------------------------------------------------------------------------
# Registry canaries
# ---------------------------------------------------------------------------

def _load_registry(root) -> list[dict]:
    path = registry_path(root)
    if not path.exists():
        return []
    try:
        blob = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"registry canary file unreadable: {exc}") from exc
    keys = blob.get("keys") if isinstance(blob, dict) else None
    return keys if isinstance(keys, list) else []


def _save_registry(root, keys) -> None:
    agentstate.write_json(registry_path(root), {"keys": keys})


def _ps(script: str, timeout: int = 120) -> tuple[int, str]:
    exe = shutil.which("powershell.exe") or shutil.which("pwsh")
    if not exe:
        return 1, "powershell not available"
    try:
        proc = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", script],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)[:300]
    return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()


def _ps_json(script: str, timeout: int = 120):
    rc, out = _ps(script, timeout)
    if rc != 0:
        return None, out[:400]
    for line in reversed(out.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line), None
            except json.JSONDecodeError:
                continue
    return None, out[:400]


def registry_deploy(root, hive: str = "HKCU", count: int = 1) -> dict:
    """Create decoy registry keys that no legitimate software should write."""
    root = Path(root)
    hive = str(hive or "HKCU").upper()
    if hive not in ("HKCU", "HKLM"):
        return {"error": "hive must be HKCU or HKLM", "code": "REFUSED"}
    count = max(1, min(int(count), 10))
    created = []
    keys = _load_registry(root)
    existing = {k.get("id") for k in keys}
    for _ in range(count):
        token = uuid.uuid4().hex[:12]
        if token in existing:
            continue
        root_key = "HKCU:\\Software\\PlasmaDecoy" if hive == "HKCU" else \
            "HKLM:\\Software\\PlasmaDecoy"
        ps_path = f"{root_key}\\{token}"
        payload = (
            "$ErrorActionPreference='Stop'\n"
            f"New-Item -Path '{ps_path}' -Force | Out-Null\n"
            f"New-ItemProperty -Path '{ps_path}' -Name 'CredentialHint' "
            "-Value 'stale' -PropertyType String -Force | Out-Null\n"
            "[pscustomobject]@{ok=$true} | ConvertTo-Json -Compress")
        rc, out = _ps(payload, timeout=60)
        if rc != 0:
            return {"error": "registry canary create failed",
                    "detail": out[:300], "code": "FAILED",
                    "created": created}
        entry = {
            "id": token,
            "hive": hive,
            "path": f"{hive}\\Software\\PlasmaDecoy\\{token}",
            "fragment": f"PlasmaDecoy\\{token}",
            "value": "CredentialHint",
            "created_at": _now(),
        }
        keys.append(entry)
        created.append(entry)
    _save_registry(root, keys)
    return {"ok": True, "created": created, "count": len(keys)}


def registry_list(root) -> dict:
    keys = _load_registry(root)
    return {"ok": True, "count": len(keys), "keys": keys}


def registry_remove(root, canary_id: str) -> dict:
    root = Path(root)
    keys = _load_registry(root)
    entry = next((k for k in keys if k.get("id") == canary_id), None)
    if entry is None:
        return {"error": f"no registry canary {canary_id}", "code": "NO_SUCH"}
    ps_path = ("HKCU:\\" if entry["hive"] == "HKCU" else "HKLM:\\") + \
        entry["path"].split("\\", 1)[1]
    payload = (
        "$ErrorActionPreference='SilentlyContinue'\n"
        f"Remove-Item -Path '{ps_path}' -Recurse -Force\n"
        "[pscustomobject]@{ok=$true} | ConvertTo-Json -Compress")
    rc, out = _ps(payload, timeout=60)
    if rc != 0:
        return {"error": "registry canary remove failed",
                "detail": out[:300], "code": "FAILED"}
    _save_registry(root, [k for k in keys if k.get("id") != canary_id])
    return {"ok": True, "removed": canary_id, "remaining": len(keys) - 1}


# ---------------------------------------------------------------------------
# Sysmon include generation
# ---------------------------------------------------------------------------

def _config_file(root) -> Path:
    return Path(root) / "tools" / SYSMON_CONFIG


def _base_xml(root) -> str:
    path = _config_file(root)
    if path.exists():
        return path.read_text(encoding="utf-8-sig")
    from .cli import sysmon_baseline_config
    return sysmon_baseline_config()


def _add_condition(parent, tag: str, condition: str, value: str) -> None:
    for child in parent.findall(tag):
        if child.get("condition") == condition and (child.text or "") == value:
            return
    node = ET.SubElement(parent, tag)
    node.set("condition", condition)
    node.text = value


def _include(parent) -> None:
    parent.set("onmatch", "include")


def shield_config(root, file_canaries=None, registry_canaries=None) -> dict:
    """Return a Sysmon XML config with narrow canary includes."""
    root = Path(root)
    text = _base_xml(root)
    try:
        tree = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"base Sysmon config is not valid XML: {exc}") from exc
    filtering = tree.find("EventFiltering")
    if filtering is None:
        raise ValueError("base Sysmon config has no EventFiltering")
    file_canaries = file_canaries if file_canaries is not None else \
        _file_canaries(root)
    registry_canaries = registry_canaries if registry_canaries is not None else \
        _load_registry(root)

    file_create = filtering.find("FileCreate")
    if file_create is None:
        file_create = ET.SubElement(filtering, "FileCreate")
    _include(file_create)
    for entry in file_canaries:
        name = _base(entry.get("path") or entry.get("name"))
        if name:
            _add_condition(file_create, "TargetFilename", "end with", "\\" + name)

    file_delete = filtering.find("FileDelete")
    if file_delete is None:
        file_delete = ET.SubElement(filtering, "FileDelete")
    _include(file_delete)
    for entry in file_canaries:
        name = _base(entry.get("path") or entry.get("name"))
        if name:
            _add_condition(file_delete, "TargetFilename", "end with", "\\" + name)

    registry = filtering.find("RegistryEvent")
    if registry is None:
        registry = ET.SubElement(filtering, "RegistryEvent")
    _include(registry)
    for entry in registry_canaries:
        fragment = entry.get("fragment") or ""
        if fragment:
            _add_condition(registry, "TargetObject", "contains", fragment)

    return {
        "xml": ET.tostring(tree, encoding="unicode", xml_declaration=True),
        "file_conditions": sum(1 for _ in file_create.findall("TargetFilename")),
        "registry_conditions": sum(1 for _ in registry.findall("TargetObject")),
        "canaries": len(file_canaries),
        "registry_canaries": len(registry_canaries),
    }


# ---------------------------------------------------------------------------
# Plan gate and journal
# ---------------------------------------------------------------------------

def _read_plans(root) -> list[dict]:
    path = plan_path(root)
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _append_plan(root, entry: dict) -> dict:
    path = plan_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with agentstate.lock(path.parent / ".canary-shield-plan.lock", stale=300):
        rows = _read_plans(root)
        entry["id"] = max((int(r.get("id") or 0) for r in rows), default=0) + 1
        entry.setdefault("ts", _now())
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def _check_plan(root, plan, kind: str, digest: str, reason) -> dict:
    if plan is None:
        return {"error": "install/uninstall requires --plan <id> from a "
                         "prior dry-run", "code": "REFUSED"}
    if not reason or not str(reason).strip():
        return {"error": "a --reason is mandatory for install/uninstall",
                "code": "REFUSED"}
    rows = _read_plans(root)
    dry = next((r for r in rows if int(r.get("id") or 0) == int(plan)), None)
    if not dry:
        return {"error": f"--plan {plan}: no such canary-shield plan",
                "code": "REFUSED"}
    if dry.get("status") != "dry-run" or dry.get("kind") != kind:
        return {"error": f"--plan {plan} is not a dry-run {kind}",
                "code": "REFUSED"}
    if dry.get("payload_sha256") != digest:
        return {"error": f"--plan {plan} rendered a different payload; "
                         "re-run the dry-run", "code": "REFUSED"}
    if any(r.get("plan") == plan and r.get("status") in ("claimed", "applied")
           for r in rows):
        return {"error": f"--plan {plan} has already been used",
                "code": "REFUSED"}
    return {}


def _claim_plan(root, plan, kind, digest, reason) -> dict:
    path = plan_path(root)
    with agentstate.lock(path.parent / ".canary-shield-claim.lock", stale=300):
        error = _check_plan(root, plan, kind, digest, reason)
        if "error" in error:
            return error
        _append_plan(root, {"kind": kind, "status": "claimed", "plan": plan,
                            "payload_sha256": digest, "reason": reason})
    return {}


def _journal(root, entry: dict) -> dict:
    path = journal_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    entry.setdefault("ts", _now())
    with agentstate.lock(path.parent / ".canary-shield-journal.lock", stale=300), \
            path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


# ---------------------------------------------------------------------------
# Install / uninstall
# ---------------------------------------------------------------------------

def _task_script(root) -> str:
    exe = Path(root) / "bin" / "plasma.exe"
    exe_q = str(exe).replace("'", "''")
    root_q = str(root).replace("'", "''")
    argument = (f"canary shield sweep --root '{root_q}' --apply "
                f"--reason \"scheduled canary shield\" --max-kills 5")
    return (
        "$ErrorActionPreference='Stop'\n"
        f"$a=New-ScheduledTaskAction -Execute '{exe_q}' -Argument '{argument}'\n"
        "$t=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) "
        "-RepetitionInterval (New-TimeSpan -Minutes 1) "
        "-RepetitionDuration (New-TimeSpan -Days 3650)\n"
        "$p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' "
        "-LogonType ServiceAccount -RunLevel Highest\n"
        f"Register-ScheduledTask -TaskName '{TASK_NAME}' -Action $a "
        "-Trigger $t -Principal $p -Force | Out-Null\n"
        "[pscustomobject]@{ok=$true} | ConvertTo-Json -Compress")


def install(root, apply: bool = False, plan=None, reason=None) -> dict:
    root = Path(root)
    try:
        cfg = shield_config(root)
    except ValueError as exc:
        return {"error": str(exc), "code": "REFUSED"}
    if not _file_canaries(root) and not _load_registry(root):
        return {"error": "no canary files or registry canaries to shield; "
                         "run canary deploy or canary registry deploy first",
                "code": "NO_CANARIES"}
    exe = Path(root) / "bin" / "plasma.exe"
    payload = (
        "Write alive. This string is only the plan digest marker.\n"
        + cfg["xml"] + "\n" + _task_script(root))
    digest = _sha(payload)
    if not apply:
        entry = _append_plan(root, {
            "kind": "install", "status": "dry-run", "payload_sha256": digest,
            "reason": reason, "file_conditions": cfg["file_conditions"],
            "registry_conditions": cfg["registry_conditions"],
            "canaries": cfg["canaries"],
            "registry_canaries": cfg["registry_canaries"],
            "task": TASK_NAME, "exe": str(exe),
            "preview": payload[:2500],
        })
        return {"ok": True, "dry_run": True, "plan": entry["id"],
                "payload_sha256": digest, "task": TASK_NAME,
                "canaries": cfg["canaries"],
                "registry_canaries": cfg["registry_canaries"],
                "file_conditions": cfg["file_conditions"],
                "registry_conditions": cfg["registry_conditions"]}
    blocked = killswitch.blocked(root, host=socket.gethostname(),
                                 risk="critical")
    if blocked:
        return {"error": "kill switch is engaged — canary shield install is "
                         "blocked", "code": "KILLSWITCH"}
    claimed = _claim_plan(root, plan, "install", digest, reason)
    if "error" in claimed:
        return claimed
    if not exe.exists():
        return {"error": f"canonical plasma.exe not found: {exe}",
                "code": "FAILED"}
    cfg_path = _config_file(root)
    backup = Path(root) / "tools" / SYSMON_BACKUP
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    if cfg_path.exists() and not backup.exists():
        shutil.copy2(cfg_path, backup)
    cfg_path.write_text(cfg["xml"], encoding="utf-8")
    reload_exe = next((Path(os.environ.get("SystemRoot", r"C:\Windows")) / n
                       for n in ("Sysmon64.exe", "Sysmon.exe")
                       if (Path(os.environ.get("SystemRoot", r"C:\Windows")) / n).exists()), None)
    if reload_exe is None:
        if backup.exists():
            shutil.copy2(backup, cfg_path)
        return {"error": "Sysmon binary not found; config not loaded",
                "code": "FAILED"}
    rc, out = _ps(f"& '{str(reload_exe).replace(chr(39), chr(39)*2)}' "
                  f"-c '{str(cfg_path).replace(chr(39), chr(39)*2)}'",
                  timeout=120)
    if rc != 0:
        if backup.exists():
            shutil.copy2(backup, cfg_path)
        return {"error": "Sysmon rejected the canary shield config",
                "detail": out[:500], "code": "FAILED"}
    rc, out = _ps(_task_script(root), timeout=120)
    if rc != 0:
        if backup.exists():
            shutil.copy2(backup, cfg_path)
            system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
            restore_exe = next((system_root / n for n in
                                ("Sysmon64.exe", "Sysmon.exe")
                                if (system_root / n).exists()), None)
            if restore_exe is not None:
                _ps(f"& '{str(restore_exe).replace(chr(39), chr(39)*2)}' "
                    f"-c '{str(cfg_path).replace(chr(39), chr(39)*2)}'",
                    timeout=120)
        return {"error": "scheduled task registration failed; config restored",
                "detail": out[:500], "code": "FAILED"}
    entry = _journal(root, {
        "kind": "install", "status": "applied", "plan": plan, "reason": reason,
        "payload_sha256": digest, "task": TASK_NAME,
        "canaries": cfg["canaries"],
        "registry_canaries": cfg["registry_canaries"],
        "file_conditions": cfg["file_conditions"],
        "registry_conditions": cfg["registry_conditions"],
    })
    return {"ok": True, "installed": True, "journal": entry.get("id"),
            "task": TASK_NAME, "canaries": cfg["canaries"],
            "registry_canaries": cfg["registry_canaries"]}


def uninstall(root, apply: bool = False, plan=None, reason=None) -> dict:
    root = Path(root)
    payload = "uninstall canary shield: remove task and restore Sysmon config"
    digest = _sha(payload)
    if not apply:
        entry = _append_plan(root, {
            "kind": "uninstall", "status": "dry-run",
            "payload_sha256": digest, "reason": reason,
            "task": TASK_NAME,
        })
        return {"ok": True, "dry_run": True, "plan": entry["id"],
                "payload_sha256": digest, "task": TASK_NAME}
    blocked = killswitch.blocked(root, host=socket.gethostname(),
                                 risk="high")
    if blocked:
        return {"error": "kill switch is engaged — canary shield uninstall "
                         "is blocked", "code": "KILLSWITCH"}
    claimed = _claim_plan(root, plan, "uninstall", digest, reason)
    if "error" in claimed:
        return claimed
    rc, out = _ps(f"Unregister-ScheduledTask -TaskName '{TASK_NAME}' "
                  "-Confirm:$false -ErrorAction SilentlyContinue; "
                  "[pscustomobject]@{ok=$true} | ConvertTo-Json -Compress",
                  timeout=60)
    if rc != 0:
        return {"error": "task removal failed", "detail": out[:400],
                "code": "FAILED"}
    cfg_path = _config_file(root)
    backup = Path(root) / "tools" / SYSMON_BACKUP
    if backup.exists():
        shutil.copy2(backup, cfg_path)
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        reload_exe = next((system_root / n for n in ("Sysmon64.exe", "Sysmon.exe")
                           if (system_root / n).exists()), None)
        if reload_exe is not None:
            _ps(f"& '{str(reload_exe).replace(chr(39), chr(39)*2)}' "
                f"-c '{str(cfg_path).replace(chr(39), chr(39)*2)}'", timeout=120)
    entry = _journal(root, {
        "kind": "uninstall", "status": "applied", "plan": plan,
        "reason": reason, "task": TASK_NAME,
    })
    return {"ok": True, "uninstalled": True, "journal": entry.get("id")}


# ---------------------------------------------------------------------------
# Sweep
# ---------------------------------------------------------------------------

_SWEEP_PS = r"""
$ErrorActionPreference='SilentlyContinue'
$since=(Get-Date).AddMinutes(-{minutes})
try {
  $ev=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=11,23,12,13,14; StartTime=$since} -MaxEvents 2000 -ErrorAction Stop
} catch {
  [pscustomobject]@{events=@(); error=$_.Exception.Message} | ConvertTo-Json -Depth 4 -Compress
  exit 0
}
$rows=@()
foreach($e in $ev) {
  $x=[xml]$e.ToXml(); $d=@{}
  foreach($p in $x.Event.EventData.Data) { if($p.Name) { $d[$p.Name]=$p.'#text' } }
  $rows += [pscustomobject]@{
    record_id=$e.RecordId
    ts=$e.TimeCreated.ToUniversalTime().ToString('o')
    event_id=$e.Id
    image=$d['Image']
    process_id=$d['ProcessId']
    target=$d['TargetFilename']
    target_object=$d['TargetObject']
    user=$d['User']
  }
}
[pscustomobject]@{events=@($rows); error=$null} | ConvertTo-Json -Depth 5 -Compress
"""


def _load_state(root) -> dict:
    try:
        data = json.loads(state_path(root).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save_state(root, state: dict) -> None:
    agentstate.write_json(state_path(root), state)


def _matches_file(target, canaries) -> dict | None:
    text = _norm_path(target)
    for entry in canaries:
        path = _norm_path(entry.get("path"))
        name = _base(path)
        parent = Path(path.replace("\\", "/")).parent.name.lower()
        if not name:
            continue
        if text == path:
            return entry
        if parent and text.endswith(f"\\{parent}\\{name}"):
            return entry
        if text.endswith(f"\\{name}") and path.endswith(f"\\{name}"):
            # Device-path variants lose the drive, but the random canary
            # basename is unique; the parent check above is preferred.
            return entry
    return None


def _matches_registry(target, keys) -> dict | None:
    text = str(target or "").lower()
    for entry in keys:
        fragment = str(entry.get("fragment") or "").lower()
        if fragment and fragment in text:
            return entry
    return None


def _trusted(image, extra) -> bool:
    name = _base(image)
    return name in {x.lower() for x in DEFAULT_TRUSTED} or name in {
        str(x).lower() for x in (extra or [])}


def _live_process(pid: int) -> dict | None:
    data, _ = _ps_json(
        "$ErrorActionPreference='SilentlyContinue'; "
        f"$p=Get-Process -Id {int(pid)} -ErrorAction SilentlyContinue; "
        "if($p){ [pscustomobject]@{id=$p.Id; name=$p.ProcessName; "
        "path=$p.Path; start=$p.StartTime.ToUniversalTime().ToString('o')} "
        "| ConvertTo-Json -Compress }", timeout=30)
    return data if isinstance(data, dict) else None


def _kill(pid: int) -> dict:
    data, err = _ps_json(
        "$ErrorActionPreference='Stop'; "
        f"Stop-Process -Id {int(pid)} -Force -ErrorAction Stop; "
        "Start-Sleep -Milliseconds 200; "
        f"$p=Get-Process -Id {int(pid)} -ErrorAction SilentlyContinue; "
        "if($p){ '{\"ok\":false}' } else { '{\"ok\":true}' }", timeout=30)
    if data is None:
        return {"ok": False, "error": err}
    return data


def sweep(root, since_minutes: int = DEFAULT_SINCE_MINUTES,
          apply: bool = False, reason=None, max_kills: int = MAX_KILLS) -> dict:
    root = Path(root)
    if not IS_WINDOWS and not shutil.which("powershell.exe"):
        return {"error": "canary shield needs Windows and Sysmon",
                "code": "UNSUPPORTED"}
    if apply and not reason:
        return {"error": "a --reason is mandatory for an applying sweep",
                "code": "REFUSED"}
    if apply:
        blocked = killswitch.blocked(root, host=socket.gethostname(),
                                     risk="critical")
        if blocked:
            return {"error": "kill switch is engaged — canary shield kill is "
                             "blocked", "code": "KILLSWITCH"}
    canaries = _file_canaries(root)
    keys = _load_registry(root)
    if not canaries and not keys:
        return {"error": "no canaries to shield", "code": "NO_CANARIES"}
    minutes = max(1, min(int(since_minutes), 1440))
    data, err = _ps_json(_SWEEP_PS.replace("{minutes}", str(minutes)),
                         timeout=120)
    if data is None:
        return {"error": "cannot read Sysmon canary events", "detail": err,
                "code": "COLLECT_FAILED"}
    if data.get("error"):
        return {"error": "Sysmon event read failed", "detail": data["error"],
                "code": "COLLECT_FAILED"}
    rows = data.get("events") or []
    if isinstance(rows, dict):
        rows = [rows]
    cfg = _load_state(root)
    seen = set(cfg.get("seen") or [])
    trusted_extra = cfg.get("trusted_processes") or []
    kills, skipped, matched = [], [], 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        event_id = int(row.get("event_id") or 0)
        target = row.get("target") or row.get("target_object")
        if event_id in _FILE_EVENTS:
            canary_entry = _matches_file(target, canaries)
            kind = "file"
        elif event_id in _REGISTRY_EVENTS:
            canary_entry = _matches_registry(target, keys)
            kind = "registry"
        else:
            continue
        if canary_entry is None:
            continue
        matched += 1
        key = hashlib.sha256(json.dumps({
            "id": row.get("record_id"), "event": event_id,
            "pid": row.get("process_id"), "target": target,
            "ts": row.get("ts"),
        }, sort_keys=True).encode()).hexdigest()
        if key in seen:
            continue
        seen.add(key)
        pid = _pid(row.get("process_id"))
        image = row.get("image") or ""
        decision = {"event_id": event_id, "kind": kind,
                    "target": target, "pid": pid, "image": image,
                    "user": row.get("user"), "ts": row.get("ts")}
        if pid is None:
            skipped.append({**decision, "reason": "no process id"})
            continue
        if _trusted(image, trusted_extra):
            skipped.append({**decision, "reason": "trusted process"})
            continue
        if _base(image) in {x.lower() for x in actuate.PROTECTED_PROCESSES}:
            skipped.append({**decision, "reason": "protected process"})
            continue
        live = _live_process(pid)
        if not live:
            skipped.append({**decision, "reason": "process already gone"})
            continue
        live_name = str(live.get("name") or "").lower()
        image_name = _base(image)
        image_name = image_name.removesuffix(".exe")
        if live_name and image_name and live_name != image_name:
            skipped.append({**decision, "reason": "pid reused or image changed"})
            continue
        if not apply:
            skipped.append({**decision, "reason": "dry-run"})
            continue
        if len(kills) >= max(1, min(int(max_kills), 25)):
            skipped.append({**decision, "reason": "max kills reached"})
            continue
        result = _kill(pid)
        entry = _journal(root, {
            "kind": "kill", "status": "killed" if result.get("ok") else "failed",
            **decision, "result": result, "reason": reason,
        })
        (kills if result.get("ok") else skipped).append(
            {**decision, "result": result, "journal": entry.get("id")})
    state = {
        "last_sweep": _now(), "last_events": len(rows),
        "last_matched": matched, "last_killed": len(kills),
        "seen": list(seen)[-5000:],
    }
    _save_state(root, state)
    return {"ok": True, "events": len(rows), "matched": matched,
            "killed": len(kills), "skipped": len(skipped),
            "dry_run": not apply, "kills": kills, "skips": skipped,
            "state": state}


def status(root) -> dict:
    root = Path(root)
    task = {}
    if os.name == "nt" or shutil.which("powershell.exe"):
        data, _ = _ps_json(
            f"$t=Get-ScheduledTask -TaskName '{TASK_NAME}' "
            "-ErrorAction SilentlyContinue; if($t){ "
            "[pscustomobject]@{installed=$true; state=[string]$t.State} | "
            "ConvertTo-Json -Compress } else { "
            "[pscustomobject]@{installed=$false} | ConvertTo-Json -Compress }",
            timeout=30)
        task = data if isinstance(data, dict) else {"installed": None}
    canaries = _file_canaries(root)
    keys = _load_registry(root)
    state = _load_state(root)
    cfg = _config_file(root)
    xml = ""
    try:
        xml = cfg.read_text(encoding="utf-8-sig") if cfg.exists() else ""
    except OSError:
        xml = ""
    return {
        "ok": True, "task": task, "canaries": len(canaries),
        "registry_canaries": len(keys),
        "sysmon_has_file_include": "<FileCreate" in xml and
        "onmatch=\"include\"" in xml,
        "sysmon_has_registry_include": "<RegistryEvent" in xml and
        "onmatch=\"include\"" in xml,
        "last_sweep": state.get("last_sweep"),
        "last_killed": state.get("last_killed"),
        "trusted_processes": list(DEFAULT_TRUSTED),
    }
