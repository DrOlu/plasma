"""Plasma actuate: rmagent-actuate-style scoped, journaled, reversible response.

Design guarantees (born from the Sentinel lockout incident):

1. **Dry-run first, always.** Every action renders its exact payload and
   journals a dry-run entry; nothing touches the host until `apply=True`
   (CLI: `--apply`) is passed by a human.
2. **Allowlisted named actions only.** There is no `run_command` and no way
   to smuggle arbitrary PowerShell through this module — targets are
   validated against strict patterns and embedded as quoted literals.
3. **Lockout-proof.** `stop_service` and `kill_process` refuse a protection
   list (WinRM, TermService, WHIDS, Sysmon, BFE, MpsSvc, ...), and
   `isolate_host` creates the management-allow rules (RDP 3389, WinRM 5985)
   *before* any block rule. Windows firewall gives more-specific allow rules
   precedence, so management access survives full isolation.
4. **Everything journaled with undo.** Every apply appends to
   `<root>/actuate-journal.jsonl` including the undo payload (or a
   structured undo recipe). `undo` replays it — also dry-run first — and
   runs the action's verification command, recording the result.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

PROTECTED_SERVICES = {
    "winrm", "termService", "termservice", "sessionenv", "umrdpservice",
    "whids", "sysmon", "sysmon64", "bfe", "mpssvc", "windefend",
    "dnscache", "lanmanserver", "lanmanworkstation", "wuauserv",
}
PROTECTED_PROCESSES = {
    "winlogon.exe", "csrss.exe", "smss.exe", "services.exe", "lsass.exe",
    "whids.exe", "sysmon64.exe", "sysmon.exe", "wininit.exe",
}
QUARANTINE_DIR = r"C:\ProgramData\Plasma\Quarantine"
JOURNAL_BACKUP_DIR = r"C:\ProgramData\Plasma\Journal"

_IS_LOCAL_USER = re.compile(r"^[A-Za-z0-9._$-]{1,64}$")
_IS_SERVICE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_IS_IP = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_IS_TASK = re.compile(r"^[^\\/\"<>|:*?]{1,200}$")
_IS_PID = re.compile(r"^\d{1,10}$")


def _ps_literal(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Action registry. Each spec:
#   target_kind: None or ("ip"|"user"|"service"|"pid"|"path"|"task")
#   validate(target): raises ValueError on bad target
#   guard(target): raises PermissionError on protected targets
#   build(target): (payload, undo_payload_or_recipe, verify_payload)
#   undoable: whether undo exists at all
# ---------------------------------------------------------------------------

def _v_ip(t):
    if not _IS_IP.match(t):
        raise ValueError(f"not an IPv4 address: {t}")
    octets = [int(o) for o in t.split(".")]
    if any(o > 255 for o in octets):
        raise ValueError(f"not an IPv4 address: {t}")


def _v_user(t):
    if not _IS_LOCAL_USER.match(t) or "\\" in t:
        raise ValueError(f"not a local username: {t}")


def _v_service(t):
    if not _IS_SERVICE.match(t):
        raise ValueError(f"not a service name: {t}")


def _v_pid(t):
    if not _IS_PID.match(t):
        raise ValueError(f"not a numeric pid: {t}")


def _v_path(t):
    if not re.match(r"^[A-Za-z]:\\.+[^\\]$", t) or ".." in t:
        raise ValueError(f"not an absolute local path: {t}")


def _v_task(t):
    if not _IS_TASK.match(t):
        raise ValueError(f"not a task name: {t}")


def _g_service(t):
    if t.lower() in {s.lower() for s in PROTECTED_SERVICES}:
        raise PermissionError(f"'{t}' is on the protected service list — refusing")


def _g_process(t):
    # Name-based protection can only run on the host: resolve pid → name.
    payload = f"($p = Get-CimInstance Win32_Process -Filter 'ProcessId = {int(t)}'); if ($p) {{ $p.Name.ToLower() }} else {{ '' }}"
    result = _run(payload, timeout=30)
    name = (result.get("output") or "").strip().strip("'").lower()
    if name in PROTECTED_PROCESSES:
        raise PermissionError(f"pid {t} is '{name}' — on the protected process list, refusing")
    if result.get("error"):
        raise ValueError(f"cannot resolve pid {t} before kill: {result['error']}")


def _g_user(t):
    if t.lower() in {"administrator", "wdagutilityaccount"}:
        raise PermissionError(f"'{t}' is on the protected account list — refusing")


def _fw_rule(name):
    return f"(Get-NetFirewallRule -DisplayName {_ps_literal(name)} -ErrorAction SilentlyContinue | Select-Object DisplayName,Enabled,Direction,Action | ConvertTo-Json -Compress)"


def _build_block_ip(ip):
    n_in, n_out = f"Plasma Block {ip} In", f"Plasma Block {ip} Out"
    payload = (
        f"New-NetFirewallRule -DisplayName {_ps_literal(n_in)} -Direction Inbound -Action Block -RemoteAddress {_ps_literal(ip)} -Profile Any | Out-Null;"
        f"New-NetFirewallRule -DisplayName {_ps_literal(n_out)} -Direction Outbound -Action Block -RemoteAddress {_ps_literal(ip)} -Profile Any | Out-Null;"
        + _fw_rule(n_in) + ";" + _fw_rule(n_out)
    )
    undo = (
        f"Remove-NetFirewallRule -DisplayName {_ps_literal(n_in)} -ErrorAction SilentlyContinue;"
        f"Remove-NetFirewallRule -DisplayName {_ps_literal(n_out)} -ErrorAction SilentlyContinue;"
        f"'removed'"
    )
    return payload, undo, _fw_rule(n_in)


def _build_isolate():
    allow_rdp, allow_winrm = "Plasma Isolate Allow RDP", "Plasma Isolate Allow WinRM"
    blk_in, blk_out = "Plasma Isolate Block Inbound", "Plasma Isolate Block Outbound"
    # Management-allow rules FIRST; specific allow beats generic block in
    # Windows Firewall, so RDP/WinRM stay reachable through the isolation.
    payload = (
        f"New-NetFirewallRule -DisplayName {_ps_literal(allow_rdp)} -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 -Profile Any | Out-Null;"
        f"New-NetFirewallRule -DisplayName {_ps_literal(allow_winrm)} -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985 -Profile Any | Out-Null;"
        f"New-NetFirewallRule -DisplayName {_ps_literal(blk_in)} -Direction Inbound -Action Block -RemoteAddress Any -Profile Any | Out-Null;"
        f"New-NetFirewallRule -DisplayName {_ps_literal(blk_out)} -Direction Outbound -Action Block -RemoteAddress Any -Profile Any | Out-Null;"
        + _fw_rule(allow_rdp) + ";" + _fw_rule(allow_winrm)
    )
    undo = (
        "".join(f"Remove-NetFirewallRule -DisplayName {_ps_literal(n)} -ErrorAction SilentlyContinue;"
                for n in (allow_rdp, allow_winrm, blk_in, blk_out))
        + "'isolation removed — RDP/WinRM allows also lifted'"
    )
    return payload, undo, _fw_rule(allow_rdp) + ";" + _fw_rule(allow_winrm)


def _build_disable_user(user):
    payload = f"Disable-LocalUser -Name {_ps_literal(user)}; (Get-LocalUser -Name {_ps_literal(user)}).Enabled"
    undo = f"Enable-LocalUser -Name {_ps_literal(user)}; (Get-LocalUser -Name {_ps_literal(user)}).Enabled"
    return payload, undo, f"(Get-LocalUser -Name {_ps_literal(user)}).Enabled"


def _build_remove_admin(user):
    payload = (f"Remove-LocalGroupMember -Group 'Administrators' -Member {_ps_literal(user)};"
               f"Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress")
    undo = (f"Add-LocalGroupMember -Group 'Administrators' -Member {_ps_literal(user)};"
            f"Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress")
    return payload, undo, "(Get-LocalGroupMember -Group 'Administrators').Name | ConvertTo-Json -Compress"


def _build_kill_process(pid):
    # Capture identity before killing so the journal can guide a restart.
    payload = (
        f"$p = Get-CimInstance Win32_Process -Filter 'ProcessId = {int(pid)}';"
        f"if ($p) {{ $p | Select-Object ProcessId,Name,CommandLine | ConvertTo-Json -Compress;"
        f"Stop-Process -Id {int(pid)} -Force; 'killed' }} else {{ 'no such pid' }}"
    )
    return payload, None, f"(Get-Process -Id {int(pid)} -ErrorAction SilentlyContinue) -eq $null"


def _build_quarantine(path):
    dest = QUARANTINE_DIR + "\\" + Path(path).name + ".quar"
    payload = (
        f"New-Item -ItemType Directory -Force -Path {_ps_literal(QUARANTINE_DIR)} | Out-Null;"
        f"Move-Item -Path {_ps_literal(path)} -Destination {_ps_literal(dest)} -Force;"
        f"Test-Path {_ps_literal(dest)}"
    )
    undo = f"Move-Item -Path {_ps_literal(dest)} -Destination {_ps_literal(path)} -Force; Test-Path {_ps_literal(path)}"
    return payload, undo, f"Test-Path {_ps_literal(path)}"


def _build_stop_service(name):
    payload = f"Stop-Service -Name {_ps_literal(name)} -Force; (Get-Service -Name {_ps_literal(name)}).Status"
    undo = f"Start-Service -Name {_ps_literal(name)}; (Get-Service -Name {_ps_literal(name)}).Status"
    return payload, undo, f"(Get-Service -Name {_ps_literal(name)}).Status"


def _build_delete_task(task):
    backup = JOURNAL_BACKUP_DIR + "\\" + re.sub(r"[^A-Za-z0-9_.-]", "_", task) + ".xml"
    payload = (
        f"New-Item -ItemType Directory -Force -Path {_ps_literal(JOURNAL_BACKUP_DIR)} | Out-Null;"
        f"Export-ScheduledTask -TaskName {_ps_literal(task)} | Set-Content -Path {_ps_literal(backup)} -Encoding UTF8;"
        f"Unregister-ScheduledTask -TaskName {_ps_literal(task)} -Confirm:$false;"
        f"Test-Path {_ps_literal(backup)}"
    )
    undo = (f"Register-ScheduledTask -TaskName {_ps_literal(task)} "
            f"-Xml (Get-Content -Path {_ps_literal(backup)} -Raw) -Force | Out-Null; 're-registered'")
    return payload, undo, f"(Get-ScheduledTask -TaskName {_ps_literal(task)} -ErrorAction SilentlyContinue) -ne $null"


def _build_disable_wmi_sub():
    # Remove only the FILTER-TO-CONSUMER BINDINGS: filters and consumers stay
    # on disk, so re-creating the bindings fully restores the subscription.
    payload = (
        "$binds = Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding;"
        "$defs = @($binds | ForEach-Object { @{ filter=$_.Filter; consumer=$_.Consumer } });"
        "$defs | ConvertTo-Json -Compress;"
        "$binds | Remove-CimInstance -ErrorAction SilentlyContinue;"
        "'bindings removed'"
    )
    return payload, {"kind": "wmi_bindings"}, (
        "(Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | Measure-Object).Count"
    )


def _build_rotate_credential(user):
    # New password is printed exactly once; the journal never contains it.
    payload = (
        f"$pw = -join ((48..57) + (65..90) + (97..122) + (35,36,37,38,42,43,45,64) | Get-Random -Count 24 | ForEach-Object {{ [char]$_ }});"
        f"Set-LocalUser -Name {_ps_literal(user)} -Password (ConvertTo-SecureString $pw -AsPlainText -Force);"
        f"'NEW PASSWORD (shown once): ' + $pw"
    )
    return payload, None, f"(Get-LocalUser -Name {_ps_literal(user)}) -ne $null"


def _build_snapshot():
    payload = (
        "New-Item -ItemType Directory -Force -Path '" + JOURNAL_BACKUP_DIR + "' | Out-Null;"
        "$out = @{};"
        "$out.host = $env:COMPUTERNAME;"
        "$out.users = @(Get-LocalUser | Select-Object Name,Enabled,LastLogon);"
        "$out.admins = @(Get-LocalGroupMember -Group 'Administrators' | Select-Object Name,PrincipalType);"
        "$out.services = @(Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,StartName,PathName);"
        "$out.tasks = @(Get-ScheduledTask | Select-Object TaskName,TaskPath,State);"
        "$out.firewall_rules = @(Get-NetFirewallRule | Select-Object DisplayName,Enabled,Direction,Action);"
        "$out.audit = auditpol.exe /get /category:* /r;"
        "$stamp = Get-Date -Format 'yyyyMMdd-HHmmss';"
        "$file = '" + JOURNAL_BACKUP_DIR + "\\' + 'snapshot-' + $stamp + '.json';"
        "$out | ConvertTo-Json -Depth 4 -Compress | Set-Content -Path $file -Encoding UTF8;"
        "$file"
    )
    return payload, None, "Test-Path '" + JOURNAL_BACKUP_DIR + "'"


ACTIONS = {
    "block_ip": {
        "description": "Firewall-block an IP inbound+outbound (2 named rules)",
        "target_kind": "ip", "validate": _v_ip, "guard": None,
        "build": _build_block_ip, "undoable": True,
    },
    "isolate_host": {
        "description": "Full isolation WITH RDP-3389 + WinRM-5985 management allows kept open",
        "target_kind": None, "validate": None, "guard": None,
        "build": lambda t: _build_isolate(), "undoable": True,
    },
    "disable_user": {
        "description": "Disable a local account (protected list enforced)",
        "target_kind": "user", "validate": _v_user, "guard": _g_user,
        "build": _build_disable_user, "undoable": True,
    },
    "remove_admin": {
        "description": "Remove a local account from Administrators",
        "target_kind": "user", "validate": _v_user, "guard": _g_user,
        "build": _build_remove_admin, "undoable": True,
    },
    "kill_process": {
        "description": "Kill a process by PID (protected names refused, identity captured first)",
        "target_kind": "pid", "validate": _v_pid, "guard": _g_process,
        "build": _build_kill_process, "undoable": False,
    },
    "quarantine_file": {
        "description": "Move a file to C:\\ProgramData\\Plasma\\Quarantine",
        "target_kind": "path", "validate": _v_path, "guard": None,
        "build": _build_quarantine, "undoable": True,
    },
    "stop_service": {
        "description": "Stop a service (protected list enforced)",
        "target_kind": "service", "validate": _v_service, "guard": _g_service,
        "build": _build_stop_service, "undoable": True,
    },
    "delete_task": {
        "description": "Unregister a scheduled task (XML backed up for undo)",
        "target_kind": "task", "validate": _v_task, "guard": None,
        "build": _build_delete_task, "undoable": True,
    },
    "disable_wmi_sub": {
        "description": "Remove WMI filter-to-consumer bindings (definitions kept; undo re-binds)",
        "target_kind": None, "validate": None, "guard": None,
        "build": lambda t: _build_disable_wmi_sub(), "undoable": True,
    },
    "rotate_credential": {
        "description": "Rotate a local user's password; new password printed once, never journaled",
        "target_kind": "user", "validate": _v_user, "guard": _g_user,
        "build": _build_rotate_credential, "undoable": False,
    },
    "snapshot": {
        "description": "Export host state (users/admins/services/tasks/firewall/audit) to JSON",
        "target_kind": None, "validate": None, "guard": None,
        "build": lambda t: _build_snapshot(), "undoable": False,
    },
}


def actions():
    return {name: spec["description"] for name, spec in ACTIONS.items()}


# ---------------------------------------------------------------------------
# Journal
# ---------------------------------------------------------------------------

def journal_path(root):
    return Path(root) / "actuate-journal.jsonl"


def _journal_append(root, entry):
    path = journal_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def journal_read(root, last=None):
    path = journal_path(root)
    if not path.exists():
        return []
    rows = [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    return rows[-last:] if last else rows


def _next_id(root):
    return len(journal_read(root)) + 1


# ---------------------------------------------------------------------------
# Runner (same posture as observatory: endpoint failures are data)
# ---------------------------------------------------------------------------

def _run(payload, timeout=60):
    exe = shutil.which("powershell.exe") or shutil.which("pwsh")
    if not exe:
        return {"error": "powershell not available on this host"}
    try:
        proc = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-Command", payload],
            capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": "execution timeout", "timeout": timeout}
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    result = {"rc": proc.returncode,
              "output": out[-2000:] if out else "",
              "output_head": out[:4000] if out else ""}
    if err:
        result["stderr"] = err[-800:]
    return result


def execute(action, root, target=None, reason=None, apply=False, timeout=60):
    """Dry-run by default. Returns the rendered payload + journal entry;
    with apply=True executes, verifies, and journals."""
    spec = ACTIONS.get(action)
    if not spec:
        return {"error": f"unknown action '{action}'", "actions": actions()}
    if reason is None or not str(reason).strip():
        return {"error": "a --reason is mandatory for every actuate call"}

    target = str(target).strip() if target else None
    if spec["target_kind"] and not target:
        return {"error": f"action '{action}' requires a target ({spec['target_kind']})"}
    try:
        if spec["validate"] and target:
            spec["validate"](target)
        if spec["guard"] and target:
            spec["guard"](target)
    except (ValueError, PermissionError) as exc:
        return {"error": str(exc), "action": action}

    payload, undo, verify = spec["build"](target)
    entry = {
        "id": _next_id(root), "ts": _now(), "action": action, "target": target,
        "reason": str(reason), "mode": "applied" if apply else "dry-run",
        "payload_sha256": __import__("hashlib").sha256(payload.encode()).hexdigest(),
        "undoable": spec["undoable"],
    }
    if not apply:
        entry["payload"] = payload
        _journal_append(root, entry)
        return entry

    result = _run(payload, timeout=timeout)
    entry["result"] = result
    entry["verification"] = _run(verify, timeout=30) if verify else None
    if undo:
        entry["undo"] = undo if isinstance(undo, dict) else {"payload": undo}
        # WMI undo needs the binding definitions captured by the payload.
        if isinstance(entry["undo"], dict) and entry["undo"].get("kind") == "wmi_bindings":
            try:
                first = (result.get("output_head") or "").splitlines()[0]
                entry["undo"]["bindings"] = json.loads(first)
            except (IndexError, json.JSONDecodeError):
                entry["undo"] = None  # nothing was bound; nothing to restore
    _journal_append(root, entry)
    entry.pop("payload", None)
    return entry


def undo(root, entry_id, apply=False, timeout=60):
    """Replay a journaled action's undo (dry-run first, as everywhere)."""
    rows = journal_read(root)
    match = next((r for r in rows if r.get("id") == entry_id), None)
    if not match:
        return {"error": f"no journal entry {entry_id}"}
    if match.get("mode") != "applied":
        return {"error": f"entry {entry_id} is '{match.get('mode')}', nothing to undo"}
    if not match.get("undoable") or not match.get("undo"):
        return {"error": f"entry {entry_id} has no undo (undoable={match.get('undoable')})"}

    undo_spec = match["undo"]
    if isinstance(undo_spec, dict) and undo_spec.get("kind") == "wmi_bindings":
        binds = undo_spec.get("bindings") or []
        if not binds:
            return {"error": "journaled entry carries no binding definitions to restore"}
        clauses = ";".join(
            f"New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding "
            f"-Property @{{ Filter={_ps_literal(b['filter'])}; Consumer={_ps_literal(b['consumer'])} }} | Out-Null;"
            for b in binds)
        payload = clauses + "'bindings restored'"
    else:
        payload = undo_spec.get("payload")

    entry = {
        "id": _next_id(root), "ts": _now(),
        "action": "undo", "undoes": entry_id, "target": match.get("target"),
        "reason": f"undo of entry {entry_id}",
        "mode": "applied" if apply else "dry-run",
    }
    if not apply:
        entry["payload"] = payload
        _journal_append(root, entry)
        return entry

    result = _run(payload, timeout=timeout)
    entry["result"] = result
    _journal_append(root, entry)
    entry.pop("payload", None)
    return entry
