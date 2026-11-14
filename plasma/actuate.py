"""Plasma actuate: rmagent-actuate-style scoped, journaled, reversible response.

Design guarantees (born from the Sentinel lockout incident):

1. **Dry-run first, always.** Every action renders its exact payload and
   journals a dry-run entry; nothing touches the host until `apply=True`
   (CLI: `--apply`) is passed by a human **with `--plan <id>`** — the id of
   that seen dry-run, for the same action and target, with a matching
   payload digest. No plan, no mutation.
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

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import time
from contextlib import contextmanager
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
    if octets[0] in (0, 127) or t == "255.255.255.255":
        raise ValueError(f"refusing to block a loopback/unspecified address: {t}")


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


# Files whose removal would break the endpoint or its own defences. These
# are refused even with a valid plan: no response action should be able to
# quarantine the EDR, the sensor, or a core Windows binary.
PROTECTED_PATH_PREFIXES = (
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\winsxs",
    "c:\\windows\\servicing",
    "c:\\programdata\\plasma",
    "c:\\program files\\whids",
    "c:\\program files\\sysmon",
)


def _g_path(t):
    low = str(t).lower().replace("/", "\\")
    for prefix in PROTECTED_PATH_PREFIXES:
        if low == prefix or low.startswith(prefix + "\\"):
            raise PermissionError(
                f"'{t}' is a protected path — refusing to quarantine it")
    return True


def _file_sha256(path) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest().lower()
    except OSError:
        return None


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
    if not name:
        raise ValueError(f"pid {t} does not exist (or its name is unreadable)")
    if name in PROTECTED_PROCESSES:
        raise PermissionError(f"pid {t} is '{name}' — on the protected process list, refusing")
    if result.get("error"):
        raise ValueError(f"cannot resolve pid {t} before kill: {result['error']}")


def _g_user(t):
    current = (os.environ.get("USERNAME") or "").lower()
    if t.lower() in {"administrator", "wdagutilityaccount", "system",
                     "localservice", "networkservice", "defaultaccount"} or \
            (current and t.lower() == current):
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
    allow_out_rdp, allow_out_winrm = ("Plasma Isolate Allow Out RDP",
                                      "Plasma Isolate Allow Out WinRM")
    blk_in, blk_out = "Plasma Isolate Block Inbound", "Plasma Isolate Block Outbound"
    # Management-allow rules FIRST; specific allow beats generic block in
    # Windows Firewall, so RDP/WinRM stay reachable through the isolation.
    # The payload *verifies* both allow rules exist before it creates any
    # block rule. A failed allow creation therefore aborts with the host
    # still reachable, instead of isolating it from its own operators.
    payload = (
        "$ErrorActionPreference = 'Stop';"
        f"New-NetFirewallRule -DisplayName {_ps_literal(allow_rdp)} -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 -Profile Any -ErrorAction SilentlyContinue | Out-Null;"
        f"New-NetFirewallRule -DisplayName {_ps_literal(allow_winrm)} -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985 -Profile Any -ErrorAction SilentlyContinue | Out-Null;"
        f"New-NetFirewallRule -DisplayName {_ps_literal(allow_out_rdp)} -Direction Outbound -Action Allow -Protocol TCP -LocalPort 3389 -Profile Any -ErrorAction SilentlyContinue | Out-Null;"
        f"New-NetFirewallRule -DisplayName {_ps_literal(allow_out_winrm)} -Direction Outbound -Action Allow -Protocol TCP -LocalPort 5985 -Profile Any -ErrorAction SilentlyContinue | Out-Null;"
        f"$allow = @(Get-NetFirewallRule -DisplayName {_ps_literal(allow_rdp)},{_ps_literal(allow_winrm)},{_ps_literal(allow_out_rdp)},{_ps_literal(allow_out_winrm)} -ErrorAction SilentlyContinue | Where-Object {{ $_.Enabled -eq 'True' -and $_.Action -eq 'Allow' }});"
        "$allowCount = @($allow).Count;"
        "if ($allowCount -lt 4) { throw 'management allow rules missing; refusing to apply isolation' };"
        f"New-NetFirewallRule -DisplayName {_ps_literal(blk_in)} -Direction Inbound -Action Block -RemoteAddress Any -Profile Any -ErrorAction SilentlyContinue | Out-Null;"
        f"New-NetFirewallRule -DisplayName {_ps_literal(blk_out)} -Direction Outbound -Action Block -RemoteAddress Any -Profile Any -ErrorAction SilentlyContinue | Out-Null;"
        f"$blocks = @(Get-NetFirewallRule -DisplayName {_ps_literal(blk_in)},{_ps_literal(blk_out)} -ErrorAction SilentlyContinue | Where-Object {{ $_.Enabled -eq 'True' -and $_.Action -eq 'Block' }});"
        "if (@($blocks).Count -lt 2) { throw 'isolation block rules missing; host may not be isolated' };"
        + _fw_rule(allow_rdp) + ";" + _fw_rule(allow_winrm)
    )
    undo = (
        "".join(f"Remove-NetFirewallRule -DisplayName {_ps_literal(n)} -ErrorAction SilentlyContinue;"
                for n in (blk_in, blk_out, allow_rdp, allow_winrm,
                          allow_out_rdp, allow_out_winrm))
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
    # The plan pins the file's current SHA256. A file swapped between the
    # dry-run and --apply therefore changes the rendered payload, and the
    # plan gate refuses it. The destination is unique per source path too,
    # so two files with the same basename can never overwrite each other.
    digest = _file_sha256(path)
    if digest is None:
        raise ValueError(f"source file not found or unreadable: {path}")
    token = hashlib.sha256(str(path).encode("utf-8")).hexdigest()[:12]
    dest = QUARANTINE_DIR + "\\" + Path(str(path).replace("\\", "/")).name + "-" + token + ".quar"
    guard = ""
    if digest:
        guard = (f"if (-not (Test-Path -LiteralPath {_ps_literal(path)})) "
                 f"{{ throw 'source file is gone since the plan' }};"
                 f"$h = (Get-FileHash -Algorithm SHA256 -LiteralPath {_ps_literal(path)}).Hash.ToLower();"
                 f"if ($h -ne {_ps_literal(digest)}) "
                 f"{{ throw 'source file changed since the plan' }};")
    payload = (
        f"New-Item -ItemType Directory -Force -Path {_ps_literal(QUARANTINE_DIR)} | Out-Null;"
        f"if (Test-Path -LiteralPath {_ps_literal(dest)}) "
        f"{{ throw 'quarantine destination already exists' }};"
        + guard +
        f"Move-Item -LiteralPath {_ps_literal(path)} -Destination {_ps_literal(dest)} -ErrorAction Stop;"
        f"Test-Path {_ps_literal(dest)}"
    )
    undo = (
        f"if (Test-Path -LiteralPath {_ps_literal(path)}) "
        f"{{ throw 'original path exists; refusing to overwrite it during undo' }};"
        f"Move-Item -LiteralPath {_ps_literal(dest)} -Destination {_ps_literal(path)} -ErrorAction Stop;"
        f"Test-Path {_ps_literal(path)}"
    )
    return payload, undo, f"Test-Path {_ps_literal(path)}"


def _build_stop_service(name):
    payload = f"Stop-Service -Name {_ps_literal(name)} -Force; (Get-Service -Name {_ps_literal(name)}).Status"
    undo = f"Start-Service -Name {_ps_literal(name)}; (Get-Service -Name {_ps_literal(name)}).Status"
    return payload, undo, f"(Get-Service -Name {_ps_literal(name)}).Status"


def _build_disable_task(task):
    # Disable (not delete): state is trivially reversible, XML backup still
    # captured so the task definition travels with the journal.
    backup = JOURNAL_BACKUP_DIR + "\\" + re.sub(r"[^A-Za-z0-9_.-]", "_", task) + ".xml"
    payload = (
        f"New-Item -ItemType Directory -Force -Path {_ps_literal(JOURNAL_BACKUP_DIR)} | Out-Null;"
        f"Export-ScheduledTask -TaskName {_ps_literal(task)} | Set-Content -Path {_ps_literal(backup)} -Encoding UTF8;"
        f"Disable-ScheduledTask -TaskName {_ps_literal(task)} | Out-Null;"
        f"(Get-ScheduledTask -TaskName {_ps_literal(task)}).State"
    )
    undo = (f"Enable-ScheduledTask -TaskName {_ps_literal(task)} | Out-Null;"
            f"(Get-ScheduledTask -TaskName {_ps_literal(task)}).State")
    return payload, undo, f"(Get-ScheduledTask -TaskName {_ps_literal(task)}).State"


_RUN_KEY_RE = re.compile(
    r"^HK(LM|CU):\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run(Once)?$")
_VALUE_RE = re.compile(r"^[A-Za-z0-9._ -]{1,100}$")


def _v_run_key(t):
    if not _RUN_KEY_RE.match(t):
        raise ValueError("run key path must be an allowlisted ...\\CurrentVersion\\Run(Once)? key")


def _v_runkey_combo(t):
    if "|" not in t:
        raise ValueError("target must be '<key path>|<value name>' (pipe-separated)")
    key, name = t.split("|", 1)
    _v_run_key(key)
    if not _VALUE_RE.match(name):
        raise ValueError(f"bad registry value name: {name}")


def _build_remove_run_key(key_path, value_name):
    # String-typed Run-key values only; the value data is captured to a
    # sidecar file (same discipline as WMI bindings) so undo restores it.
    backup = (JOURNAL_BACKUP_DIR + "\\runkey-"
              + re.sub(r"[^A-Za-z0-9_.-]", "_", value_name) + ".json")
    payload = (
        f"New-Item -ItemType Directory -Force -Path {_ps_literal(JOURNAL_BACKUP_DIR)} | Out-Null;"
        f"$k = Get-Item {_ps_literal(key_path)};"
        f"$v = $k.GetValue({_ps_literal(value_name)});"
        f"if ($null -eq $v) {{ 'absent' }}"
        f"elseif ($v -isnot [string]) {{ throw 'only string Run-key values are managed' }}"
        f"else {{ ConvertTo-Json -InputObject @{{ name={_ps_literal(value_name)}; data=$v }} "
        f"| Set-Content -Path {_ps_literal(backup)} -Encoding UTF8;"
        f"Remove-ItemProperty -Path {_ps_literal(key_path)} -Name {_ps_literal(value_name)};"
        f"'{backup}' }}"
    )
    return payload, {"kind": "run_key_value", "key": key_path, "name": value_name}, \
        f"(Get-ItemProperty {_ps_literal(key_path)} -Name {_ps_literal(value_name)} -ErrorAction SilentlyContinue) -eq $null"


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
    # Capture *names* (and the consumer class), not serialized CIM objects:
    # a binding needs live Filter/Consumer instances, and a JSON dump of a
    # CimInstance cannot be passed back as one.
    payload = (
        "New-Item -ItemType Directory -Force -Path '" + JOURNAL_BACKUP_DIR + "' | Out-Null;"
        "$binds = Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding;"
        "$defs = @($binds | Select-Object -First 200 | ForEach-Object { "
        "@{ filter_name=$_.Filter.Name; consumer_name=$_.Consumer.Name; "
        "consumer_class=$_.Consumer.CimClass.CimClassName } });"
        "$file = '" + JOURNAL_BACKUP_DIR + "\\' + 'bindings-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json';"
        "ConvertTo-Json -InputObject @($defs) -Compress | Set-Content -Path $file -Encoding UTF8;"
        "$file;"
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
        "description": "Move a file to C:\\ProgramData\\Plasma\\Quarantine (hash-pinned, protected paths refused)",
        "target_kind": "path", "validate": _v_path, "guard": _g_path,
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
    "disable_task": {
        "description": "Disable a scheduled task (definition backed up; enable to undo)",
        "target_kind": "task", "validate": _v_task, "guard": None,
        "build": _build_disable_task, "undoable": True,
    },
    "remove_run_key": {
        "description": "Remove a string Run-key value (target 'HKLM:\\...Run|name'; value backed up for undo)",
        "target_kind": "runkey", "validate": _v_runkey_combo, "guard": None,
        "build": lambda t: _build_remove_run_key(*t.split("|", 1)), "undoable": True,
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


@contextmanager
def _journal_lock(root):
    """Cross-process lock so two agents cannot mint the same journal id or
    consume the same plan. Stale locks are reclaimed after 30s."""
    directory = journal_path(root).parent
    directory.mkdir(parents=True, exist_ok=True)
    lock = directory / ".actuate-journal.lock"
    deadline = time.time() + 10
    fd = None
    while fd is None:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                if time.time() - lock.stat().st_mtime > 30:
                    lock.unlink()
                    continue
            except OSError:
                pass
            if time.time() > deadline:
                raise RuntimeError("actuate journal is locked by another writer")
            time.sleep(0.05)
    try:
        yield
    finally:
        try:
            os.close(fd)
        finally:
            try:
                lock.unlink()
            except OSError:
                pass


def _journal_append(root, entry):
    path = journal_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    return entry


def journal_read(root, last=None):
    path = journal_path(root)
    if not path.exists():
        return []
    rows = []
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            rows.append(json.loads(ln))
        except json.JSONDecodeError:
            continue      # torn line (crash mid-append) — never brick the journal
    return rows[-last:] if last else rows


def _next_id(root):
    """Next id from the highest surviving id.

    Using len()+1 would reuse an id when a torn/corrupt line was skipped,
    which silently makes two journal entries claim the same plan key.
    """
    ids = [r.get("id") for r in journal_read(root)
           if isinstance(r.get("id"), int)]
    return max(ids, default=0) + 1


def _append_entry(root, entry):
    """Assign an id and append under the journal lock."""
    with _journal_lock(root):
        entry = dict(entry)
        entry["id"] = _next_id(root)
        return _journal_append(root, entry)


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
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
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


def execute(action, root, target=None, reason=None, apply=False, timeout=60,
            plan=None):
    """Dry-run by default. Returns the rendered payload + journal entry;
    with apply=True executes, verifies, and journals.

    apply=True REQUIRES `plan`: the id of a prior dry-run entry for the same
    action+target, whose rendered payload digest matches what would run now
    (dry-run first, always — no plan, no mutation)."""
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
        return {"error": str(exc), "code": "REFUSED", "action": action}

    try:
        payload, undo, verify = spec["build"](target)
    except (ValueError, PermissionError, OSError) as exc:
        return {"error": str(exc), "code": "REFUSED", "action": action}
    payload_sha = hashlib.sha256(payload.encode()).hexdigest()

    if apply:
        # The kill switch blocks execution, not planning: a human may still
        # dry-run while containment is paused.
        from . import killswitch
        if killswitch.blocked(root, host=socket.gethostname(), risk="medium"):
            return {"error": "kill switch is engaged for this host — "
                             "response actions are blocked (reads and dry-runs "
                             "remain available)", "code": "KILLSWITCH",
                    "action": action}
        if plan is None:
            return {"error": "--apply requires --plan <id> from a prior dry-run "
                             "(dry-run first, always)", "code": "REFUSED",
                    "action": action}

    entry = {
        "ts": _now(), "action": action, "target": target,
        "reason": str(reason)[:500], "mode": "applied" if apply else "dry-run",
        "payload_sha256": payload_sha,
        "undoable": spec["undoable"],
    }
    if apply:
        entry["plan"] = plan

    # Everything from plan validation through the journal append happens
    # under one lock, so two callers cannot both consume the same plan.
    with _journal_lock(root):
        rows = journal_read(root)
        if apply:
            dr = next((r for r in rows if r.get("id") == plan), None)
            if not dr:
                return {"error": f"--plan {plan}: no such journal entry",
                        "code": "REFUSED", "action": action}
            if dr.get("mode") != "dry-run" or dr.get("action") != action:
                return {"error": f"--plan {plan} is not a dry-run of '{action}'",
                        "code": "REFUSED", "action": action}
            if str(dr.get("target") or "") != str(target or ""):
                return {"error": f"--plan {plan} targeted '{dr.get('target')}', "
                                 f"not '{target}'", "code": "REFUSED",
                        "action": action}
            if dr.get("payload_sha256") != payload_sha:
                return {"error": f"--plan {plan} rendered a different payload than the "
                                 f"current state would (re-run the dry-run)",
                        "code": "REFUSED", "action": action}
            if any(r.get("mode") == "applied" and r.get("plan") == plan for r in rows):
                return {"error": f"--plan {plan} has already been used",
                        "code": "REFUSED", "action": action}

        entry["id"] = _next_id(root)
        if not apply:
            entry["payload"] = payload
            _journal_append(root, entry)
            return entry

        result = _run(payload, timeout=timeout)
        entry["result"] = result
        entry["verification"] = _run(verify, timeout=30) if verify else None
        if undo:
            entry["undo"] = undo if isinstance(undo, dict) else {"payload": undo}
            # sidecar-captured undo data (WMI bindings, run-key values) — the
            # payload's first output line is the capture file path
            if isinstance(entry["undo"], dict) and \
                    entry["undo"].get("kind") in ("wmi_bindings", "run_key_value"):
                try:
                    first = (result.get("output_head") or "").splitlines()[0].strip()
                except IndexError:
                    first = ""
                if first and not first.startswith("{"):
                    field = "bindings_file" if entry["undo"]["kind"] == "wmi_bindings" \
                        else "backup_file"
                    entry["undo"][field] = first
                else:
                    entry["undo"] = None  # nothing captured: nothing was changed

        secret = None
        if action == "rotate_credential":
            # The new password is shown to the caller exactly once and is
            # scrubbed from the journaled result. A credential must never be
            # persisted in an audit trail.
            out = result.get("output") or ""
            for line in out.splitlines():
                if line.startswith("NEW PASSWORD"):
                    secret = line.split(":", 1)[-1].strip()
                    break
            if secret:
                redacted = dict(result,
                                output="[credential redacted from journal]",
                                output_head="[credential redacted from journal]")
                entry["result"] = redacted
                ver = entry.get("verification")
                if isinstance(ver, dict):
                    entry["verification"] = dict(
                        ver,
                        output="[credential redacted from journal]",
                        output_head="[credential redacted from journal]")

        _journal_append(root, entry)
        entry.pop("payload", None)
        if secret:
            entry["new_password"] = secret
            entry["secret_note"] = ("shown once — not written to the journal; "
                                    "store it in your password manager now")
        return entry


def _undo_payload(match):
    """Resolve a journaled undo recipe to a runnable payload."""
    undo_spec = match.get("undo")
    if isinstance(undo_spec, dict) and undo_spec.get("kind") == "wmi_bindings":
        binds = undo_spec.get("bindings") or []
        bindings_file = undo_spec.get("bindings_file")
        if not binds and bindings_file:
            try:
                loaded = json.loads(
                    Path(bindings_file).read_text(encoding="utf-8-sig"))
            except (OSError, json.JSONDecodeError) as exc:
                return None, f"cannot read binding capture {bindings_file}: {exc}"
            binds = loaded if isinstance(loaded, list) else [loaded]
        if not binds:
            return None, "journaled entry carries no binding definitions to restore"
        clauses = []
        skipped = 0
        for b in binds:
            if not isinstance(b, dict):
                skipped += 1
                continue
            fname, cname = b.get("filter_name"), b.get("consumer_name")
            # Backward compatibility: older journals stored either CIM
            # object dumps or object paths. Recover a Name when possible.
            if not fname and isinstance(b.get("filter"), dict):
                fname = b["filter"].get("Name")
            if not cname and isinstance(b.get("consumer"), dict):
                cname = b["consumer"].get("Name")
            for source in (b.get("filter"), b.get("consumer")):
                if isinstance(source, str) and source.startswith("\\\\"):
                    found = re.search(r'Name="([^"]+)"', source)
                    if found and not fname:
                        fname = found.group(1)
            if not fname or not cname:
                skipped += 1
                continue
            cclass = str(b.get("consumer_class") or "__EventConsumer")
            if not re.match(r"^[A-Za-z_][A-Za-z0-9_]{0,100}$", cclass):
                cclass = "__EventConsumer"
            clauses.append(
                "$f = Get-CimInstance -Namespace root/subscription -ClassName __EventFilter "
                f"-Filter {_ps_literal('Name=' + repr(str(fname)))} -ErrorAction Stop;"
                f"$c = Get-CimInstance -Namespace root/subscription -ClassName {cclass} "
                f"-Filter {_ps_literal('Name=' + repr(str(cname)))} -ErrorAction Stop;"
                "if (-not $f -or -not $c) { throw 'filter or consumer no longer exists' };"
                "New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding "
                "-Property @{ Filter=$f; Consumer=$c } | Out-Null;")
        if not clauses:
            return None, "binding capture has no usable filter/consumer names"
        note = f"'bindings restored ({len(clauses)})'" + (
            f"; 'WARNING: {skipped} binding(s) skipped'" if skipped else "")
        return ";".join(clauses) + ";" + note, None
    if isinstance(undo_spec, dict) and undo_spec.get("kind") == "run_key_value":
        key, name = undo_spec.get("key"), undo_spec.get("name")
        backup_file = undo_spec.get("backup_file")
        data = undo_spec.get("data")
        if data is None and backup_file:
            try:
                cap = json.loads(Path(backup_file).read_text(encoding="utf-8-sig"))
            except (OSError, json.JSONDecodeError) as exc:
                return None, f"cannot read run-key capture {backup_file}: {exc}"
            name, data = cap.get("name"), cap.get("data")
        if data is None:
            return None, "journaled entry carries no run-key value to restore"
        return (f"New-ItemProperty -Path {_ps_literal(key)} -Name {_ps_literal(name)} "
                f"-Value {_ps_literal(str(data))} -PropertyType String -Force | Out-Null; "
                f"'run-key value restored'"), None
    payload = undo_spec.get("payload") if isinstance(undo_spec, dict) else undo_spec
    if not payload:
        return None, "journaled entry carries no undo payload"
    return payload, None


def undo(root, entry_id, apply=False, plan=None, timeout=60):
    """Replay a journaled action's undo. Dry-run first, always.

    Applying an undo requires a prior undo dry-run (``--plan``). The same
    undo cannot be applied twice, and the payload digest must still match.
    When exactly one undo dry-run exists it may be selected implicitly;
    more than one is ambiguous and requires an explicit plan id.
    """
    with _journal_lock(root):
        rows = journal_read(root)
        match = next((r for r in rows if r.get("id") == entry_id), None)
        if not match:
            return {"error": f"no journal entry {entry_id}"}
        if match.get("mode") != "applied":
            return {"error": f"entry {entry_id} is '{match.get('mode')}', nothing to undo"}
        if not match.get("undoable") or not match.get("undo"):
            return {"error": f"entry {entry_id} has no undo (undoable={match.get('undoable')})"}
        if any(r.get("action") == "undo" and r.get("mode") == "applied"
               and r.get("undoes") == entry_id for r in rows):
            return {"error": f"entry {entry_id} has already been undone"}

        payload, error = _undo_payload(match)
        if error:
            return {"error": error}
        payload_sha = hashlib.sha256(payload.encode()).hexdigest()

        if apply:
            candidates = [r for r in rows
                          if r.get("action") == "undo" and r.get("mode") == "dry-run"
                          and r.get("undoes") == entry_id]
            if plan is None and len(candidates) == 1:
                plan = candidates[0]["id"]
            if plan is None:
                detail = ("multiple undo dry-runs exist — choose one"
                          if len(candidates) > 1 else "dry-run the undo first")
                return {"error": f"--apply requires --plan <id> from a prior undo dry-run "
                                 f"({detail})", "code": "REFUSED"}
            dr = next((r for r in rows if r.get("id") == plan), None)
            if (not dr or dr.get("action") != "undo" or dr.get("mode") != "dry-run"
                    or dr.get("undoes") != entry_id):
                return {"error": f"--plan {plan} is not a dry-run undo of entry {entry_id}",
                        "code": "REFUSED"}
            if dr.get("payload_sha256") != payload_sha:
                return {"error": f"--plan {plan} rendered a different undo payload "
                                 f"than the current state would (re-run the dry-run)",
                        "code": "REFUSED"}

        entry = {
            "id": _next_id(root), "ts": _now(),
            "action": "undo", "undoes": entry_id, "target": match.get("target"),
            "reason": f"undo of entry {entry_id}",
            "mode": "applied" if apply else "dry-run",
            "payload_sha256": payload_sha,
        }
        if apply:
            entry["plan"] = plan
        if not apply:
            entry["payload"] = payload
            _journal_append(root, entry)
            return entry

        result = _run(payload, timeout=timeout)
        entry["result"] = result
        entry["ok"] = (not result.get("error")
                       and result.get("rc") in (0, None))
        _journal_append(root, entry)
        entry.pop("payload", None)
        return entry
