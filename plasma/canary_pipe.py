"""Named-pipe canaries: a decoy pipe that kills the client that connects.

A named pipe is a real local IPC object. Nothing legitimate should connect to
a randomly named decoy pipe, but attackers and commodity tooling enumerate
and probe pipes. This module creates decoy pipe names, runs a listener as
SYSTEM, identifies the connecting process with
``GetNamedPipeClientProcessId``, verifies it, and kills it.

The same false-positive boundary as the file/registry shield applies:
protected processes are refused, Plasma/Defender/backup/system processes are
trusted, and the listener is opt-in. A scanner that *enumerates* pipes is not
touched; only a client that actually connects is.

Windows only. This is a user-mode listener, not a kernel driver.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import secrets
import shutil
import socket
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path

from . import actuate, agentstate, canary_shield, killswitch

TASK_NAME = "PlasmaCanaryPipe"
PIPES_NAME = "canary-pipes.json"
STATE_NAME = "canary-pipe-state.json"
JOURNAL_NAME = "canary-pipe-journal.jsonl"
PLAN_NAME = "canary-pipe-plans.jsonl"
DEFAULT_COUNT = 1
MAX_PIPES = 10

_WORDS = ("svc", "rpc", "cache", "session", "agent", "updater", "broker")

PIPE_ACCESS_DUPLEX = 0x00000003
PIPE_TYPE_BYTE = 0x00000000
PIPE_READMODE_BYTE = 0x00000000
PIPE_WAIT = 0x00000000
PIPE_UNLIMITED_INSTANCES = 255
ERROR_PIPE_CONNECTED = 535
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def pipes_path(root) -> Path:
    return Path(root) / PIPES_NAME


def state_path(root) -> Path:
    return Path(root) / STATE_NAME


def journal_path(root) -> Path:
    return Path(root) / JOURNAL_NAME


def plan_path(root) -> Path:
    return Path(root) / PLAN_NAME


def _load_pipes(root) -> list[dict]:
    path = pipes_path(root)
    if not path.exists():
        return []
    try:
        blob = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"pipe canary registry unreadable: {exc}") from exc
    rows = blob.get("pipes") if isinstance(blob, dict) else None
    return rows if isinstance(rows, list) else []


def _save_pipes(root, rows) -> None:
    agentstate.write_json(pipes_path(root), {"pipes": rows})


def deploy(root, count: int = DEFAULT_COUNT) -> dict:
    root = Path(root)
    count = max(1, min(int(count), MAX_PIPES))
    rows = _load_pipes(root)
    existing = {r.get("name") for r in rows}
    created = []
    for _ in range(count):
        for _try in range(20):
            name = f"{secrets.token_hex(4)}_{secrets.choice(_WORDS)}"
            if name not in existing:
                break
        else:
            continue
        entry = {
            "id": secrets.token_hex(6),
            "name": name,
            "path": rf"\\.\pipe\{name}",
            "created_at": _now(),
        }
        rows.append(entry)
        existing.add(name)
        created.append(entry)
    _save_pipes(root, rows)
    return {"ok": True, "created": created, "count": len(rows)}


def list_pipes(root) -> dict:
    rows = _load_pipes(root)
    return {"ok": True, "count": len(rows), "pipes": rows}


def remove(root, pipe_id: str) -> dict:
    rows = _load_pipes(root)
    entry = next((r for r in rows if r.get("id") == pipe_id), None)
    if entry is None:
        return {"error": f"no pipe canary {pipe_id}", "code": "NO_SUCH"}
    _save_pipes(root, [r for r in rows if r.get("id") != pipe_id])
    return {"ok": True, "removed": pipe_id, "remaining": len(rows) - 1}


# ---------------------------------------------------------------------------
# Plan gate and task
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
    with agentstate.lock(path.parent / ".canary-pipe-plan.lock", stale=300):
        rows = _read_plans(root)
        entry["id"] = max((int(r.get("id") or 0) for r in rows), default=0) + 1
        entry.setdefault("ts", _now())
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def _check_plan(root, plan, kind: str, digest: str, reason) -> dict:
    if plan is None:
        return {"error": "pipe install/uninstall requires --plan <id> from a "
                         "prior dry-run", "code": "REFUSED"}
    if not reason or not str(reason).strip():
        return {"error": "a --reason is mandatory for pipe install/uninstall",
                "code": "REFUSED"}
    rows = _read_plans(root)
    dry = next((r for r in rows if int(r.get("id") or 0) == int(plan)), None)
    if not dry:
        return {"error": f"--plan {plan}: no such canary-pipe plan",
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
    with agentstate.lock(path.parent / ".canary-pipe-claim.lock", stale=300):
        error = _check_plan(root, plan, kind, digest, reason)
        if "error" in error:
            return error
        _append_plan(root, {"kind": kind, "status": "claimed", "plan": plan,
                            "payload_sha256": digest, "reason": reason})
    return {}


def _canonical_exe(root) -> Path:
    root = Path(root)
    for path in (root / "bin" / "plasma.exe",
                 root.parent / "bin" / "plasma.exe"):
        if path.exists():
            return path
    return Path(sys.executable)


def _task_script(root, exe=None) -> str:
    exe = Path(exe) if exe else _canonical_exe(root)
    exe_q = str(exe).replace("'", "''")
    argument = (f'canary pipe serve --root "{root}" --apply '
                f'--reason "scheduled canary pipe"')
    argument = argument.replace("'", "''")
    return (
        "$ErrorActionPreference='Stop'\n"
        f"$a=New-ScheduledTaskAction -Execute '{exe_q}' -Argument '{argument}'\n"
        "$t=New-ScheduledTaskTrigger -AtStartup\n"
        "$s=New-ScheduledTaskSettingsSet -RestartCount 999 "
        "-RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable "
        "-ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew\n"
        "$p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' "
        "-LogonType ServiceAccount -RunLevel Highest\n"
        f"Register-ScheduledTask -TaskName '{TASK_NAME}' -Action $a "
        "-Trigger $t -Settings $s -Principal $p -Force | Out-Null\n"
        f"Start-ScheduledTask -TaskName '{TASK_NAME}'\n"
        "[pscustomobject]@{ok=$true} | ConvertTo-Json -Compress")


def install(root, apply: bool = False, plan=None, reason=None) -> dict:
    root = Path(root)
    rows = _load_pipes(root)
    if not rows:
        return {"error": "no pipe canaries; run canary pipe deploy first",
                "code": "NO_PIPES"}
    exe = _canonical_exe(root)
    payload = _task_script(root, exe)
    digest = hashlib.sha256(payload.encode()).hexdigest()
    if not apply:
        entry = _append_plan(root, {
            "kind": "install", "status": "dry-run", "payload_sha256": digest,
            "reason": reason, "pipes": len(rows), "exe": str(exe),
            "preview": payload[:2500],
        })
        return {"ok": True, "dry_run": True, "plan": entry["id"],
                "pipes": len(rows), "task": TASK_NAME, "exe": str(exe)}
    blocked = killswitch.blocked(root, host=socket.gethostname(),
                                 risk="critical")
    if blocked:
        return {"error": "kill switch is engaged — pipe install is blocked",
                "code": "KILLSWITCH"}
    claimed = _claim_plan(root, plan, "install", digest, reason)
    if "error" in claimed:
        return claimed
    if not exe.exists():
        return {"error": f"canonical plasma.exe not found: {exe}",
                "code": "FAILED"}
    rc, out = canary_shield._ps(payload, timeout=120)
    if rc != 0:
        return {"error": "pipe task registration failed", "detail": out[:500],
                "code": "FAILED"}
    entry = canary_shield._journal(root, {
        "kind": "pipe-install", "status": "applied", "plan": plan,
        "reason": reason, "task": TASK_NAME, "pipes": len(rows),
    })
    return {"ok": True, "installed": True, "task": TASK_NAME,
            "pipes": len(rows), "journal": entry.get("id")}


def uninstall(root, apply: bool = False, plan=None, reason=None) -> dict:
    root = Path(root)
    payload = "uninstall canary pipe listener"
    digest = hashlib.sha256(payload.encode()).hexdigest()
    if not apply:
        entry = _append_plan(root, {
            "kind": "uninstall", "status": "dry-run",
            "payload_sha256": digest, "reason": reason, "task": TASK_NAME,
        })
        return {"ok": True, "dry_run": True, "plan": entry["id"],
                "task": TASK_NAME}
    blocked = killswitch.blocked(root, host=socket.gethostname(),
                                 risk="high")
    if blocked:
        return {"error": "kill switch is engaged — pipe uninstall is blocked",
                "code": "KILLSWITCH"}
    claimed = _claim_plan(root, plan, "uninstall", digest, reason)
    if "error" in claimed:
        return claimed
    rc, out = canary_shield._ps(
        f"Stop-ScheduledTask -TaskName '{TASK_NAME}' -ErrorAction SilentlyContinue; "
        f"Unregister-ScheduledTask -TaskName '{TASK_NAME}' -Confirm:$false "
        "-ErrorAction SilentlyContinue; "
        "[pscustomobject]@{ok=$true} | ConvertTo-Json -Compress", timeout=60)
    if rc != 0:
        return {"error": "pipe task removal failed", "detail": out[:400],
                "code": "FAILED"}
    entry = canary_shield._journal(root, {
        "kind": "pipe-uninstall", "status": "applied", "plan": plan,
        "reason": reason, "task": TASK_NAME,
    })
    return {"ok": True, "uninstalled": True, "journal": entry.get("id")}


# ---------------------------------------------------------------------------
# Listener
# ---------------------------------------------------------------------------

def _kernel32():
    if os.name != "nt":
        raise OSError("named-pipe canaries require Windows")
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateNamedPipeW.restype = wintypes.HANDLE
    k32.CreateNamedPipeW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID]
    k32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
    k32.ConnectNamedPipe.restype = wintypes.BOOL
    k32.GetNamedPipeClientProcessId.argtypes = [wintypes.HANDLE,
                                                ctypes.POINTER(wintypes.ULONG)]
    k32.GetNamedPipeClientProcessId.restype = wintypes.BOOL
    k32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
    k32.DisconnectNamedPipe.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    return k32


def _ensure_event(root, entry, pid, image, decision) -> None:
    root = Path(root)
    row = {
        "ts": _now(), "host": socket.gethostname() or "localhost",
        "source": "canary", "kind": "alert", "event_id": 9001,
        "severity": "critical", "score": 0.95,
        "action": "blocked" if decision == "killed" else "logged",
        "alert_id": f"canary:pipe:{entry.get('id', 'unknown')}"[:64],
        "process": canary_shield._base(image) or "unknown",
        "pid": pid if isinstance(pid, int) and pid > 0 else None,
        "description": f"canary named pipe accessed: {entry.get('path')} "
                       f"by {image or 'unknown'} (pid {pid}); {decision}",
    }
    row = {k: v for k, v in row.items() if v is not None}
    path = root / "data" / "events.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with agentstate.lock(path.parent / ".events.lock", timeout=10, stale=60):
        agentstate.ensure_trailing_newline(path)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")


def _handle_client(root, entry, pid, apply, reason, max_kills, kill_count) -> dict:
    live = canary_shield._live_process(pid)
    image = (live or {}).get("path") or ""
    base = canary_shield._base(image)
    decision = "observed"
    result = {"ok": True}
    if not live:
        decision = "process gone"
    elif not image:
        decision = "image unknown"
    elif canary_shield._trusted(image, []) or base in {
            x.lower() for x in actuate.PROTECTED_PROCESSES}:
        decision = "skipped protected/trusted"
    elif not apply:
        decision = "dry-run"
    elif kill_count[0] >= max_kills:
        decision = "max kills reached"
    else:
        result = canary_shield._kill(pid)
        if result.get("ok"):
            decision = "killed"
            kill_count[0] += 1
        else:
            decision = "kill failed"
    row = canary_shield._journal(root, {
        "kind": "pipe", "pipe": entry.get("name"), "path": entry.get("path"),
        "pid": pid, "image": image, "decision": decision, "result": result,
        "reason": reason,
    })
    _ensure_event(root, entry, pid, image, decision)
    return {"pipe": entry.get("name"), "pid": pid, "image": image,
            "decision": decision, "journal": row.get("id")}


def serve(root, apply: bool = False, reason=None, max_kills: int = 5,
          max_connections: int = 0) -> int:
    """Block and listen on every deployed pipe canary."""
    root = Path(root)
    if apply and not reason:
        print(json.dumps({"error": "a --reason is mandatory for --apply",
                          "code": "REFUSED"}))
        return 2
    if apply and killswitch.blocked(root, host=socket.gethostname(),
                                    risk="critical"):
        print(json.dumps({"error": "kill switch is engaged — pipe listener "
                                   "cannot kill", "code": "KILLSWITCH"}))
        return 2
    rows = _load_pipes(root)
    if not rows:
        print(json.dumps({"error": "no pipe canaries; run canary pipe deploy",
                          "code": "NO_PIPES"}))
        return 1
    try:
        k32 = _kernel32()
    except OSError as exc:
        print(json.dumps({"error": str(exc), "code": "UNSUPPORTED"}))
        return 1

    counter = {"connections": 0}
    kills = [0]
    lock = threading.Lock()
    stop = threading.Event()

    def listener(entry):
        name = entry.get("path") or rf"\\.\pipe\{entry.get('name')}"
        while not stop.is_set():
            handle = k32.CreateNamedPipeW(
                name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE
                | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, None)
            if handle == INVALID_HANDLE_VALUE:
                time.sleep(1)
                continue
            try:
                k32.ConnectNamedPipe(handle, None)
                # ERROR_PIPE_CONNECTED is normal when the client connected
                # before ConnectNamedPipe was called. Some Windows builds do
                # not surface it through get_last_error(), so do not gate on
                # the return code: ask for the client PID and decide from that.
                pid = wintypes.ULONG(0)
                if not k32.GetNamedPipeClientProcessId(handle,
                                                       ctypes.byref(pid)):
                    time.sleep(0.2)
                    continue
                with lock:
                    counter["connections"] += 1
                    result = _handle_client(root, entry, int(pid.value),
                                            apply, reason, max_kills, kills)
                    print(json.dumps(result, default=str), flush=True)
                    if max_connections and counter["connections"] >= max_connections:
                        stop.set()
            finally:
                k32.DisconnectNamedPipe(handle)
                k32.CloseHandle(handle)
            if stop.is_set():
                break

    threads = [threading.Thread(target=listener, args=(entry,), daemon=True)
               for entry in rows]
    for thread in threads:
        thread.start()
    try:
        while any(t.is_alive() for t in threads):
            for thread in threads:
                thread.join(timeout=0.5)
            if stop.is_set():
                break
    except KeyboardInterrupt:
        stop.set()
    state = {
        "last_run": _now(), "pipes": len(rows), "connections": counter["connections"],
        "killed": kills[0], "apply": bool(apply),
    }
    agentstate.write_json(state_path(root), state)
    return 0 if counter["connections"] >= 0 else 1


def status(root) -> dict:
    root = Path(root)
    task = {}
    if os.name == "nt" or shutil.which("powershell.exe"):
        data, _ = canary_shield._ps_json(
            f"$t=Get-ScheduledTask -TaskName '{TASK_NAME}' "
            "-ErrorAction SilentlyContinue; if($t){ "
            "[pscustomobject]@{installed=$true; state=[string]$t.State} | "
            "ConvertTo-Json -Compress } else { "
            "[pscustomobject]@{installed=$false} | ConvertTo-Json -Compress }",
            timeout=30)
        task = data if isinstance(data, dict) else {"installed": None}
    try:
        state = json.loads(state_path(root).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        state = {}
    return {"ok": True, "task": task, "pipes": len(_load_pipes(root)),
            "last_run": state.get("last_run"),
            "last_connections": state.get("connections"),
            "last_killed": state.get("killed")}
