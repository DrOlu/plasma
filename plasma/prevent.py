"""Plasma prevent: Tier 1 prevention through Windows enforcement points.

Plasma does not ship a kernel driver. Real, inline prevention is delivered by
the signed enforcement points Windows already has — AppLocker/WDAC for
execution, Windows Firewall for egress, Defender ASR for behaviour, LSA
protection for credential access. This module generates and applies those
policies with the same operating discipline as the response plane:

* **Dry-run first, always.** Every apply renders its payload and requires
  ``--plan <id>`` from a prior dry-run whose digest still matches.
* **Bounded and reversible.** Every control writes an undo recipe and can be
  rolled back by journal id.
* **Refuses ambiguity.** Unknown controls, malformed addresses, non-GUID ASR
  ids and unreadable baselines are rejected before PowerShell is invoked.

Blocking with a bad policy is how hosts stop booting. The defaults are
audit-only; enforcement is an explicit operator decision.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from xml.sax.saxutils import escape

PREFIX = "PlasmaPrevent"
JOURNAL = "prevent-journal.jsonl"
BACKUP_DIR = "prevent-backups"

_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$")
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                   r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_ASR_ACTIONS = {"Enabled": "Enabled", "Audit": "AuditMode",
                "AuditMode": "AuditMode", "Disabled": "Disabled",
                "Block": "Enabled"}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def journal_path(root) -> Path:
    return Path(root) / JOURNAL


def _read_journal(root) -> list[dict]:
    path = journal_path(root)
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _append_journal(root, entry) -> dict:
    path = journal_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = _read_journal(root)
    entry["id"] = max((int(r.get("id") or 0) for r in rows), default=0) + 1
    entry.setdefault("ts", _now())
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def _ps(script: str, timeout: int = 120) -> tuple[int, str]:
    exe = shutil.which("powershell.exe") or shutil.which("pwsh")
    if not exe:
        return 1, "powershell not available"
    try:
        proc = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", script],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)[:200]
    return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()


def _ps_json(script: str, timeout: int = 120):
    rc, out = _ps(script, timeout)
    if rc != 0:
        return None, out[:300]
    try:
        return json.loads(out.splitlines()[-1]), None
    except (json.JSONDecodeError, IndexError):
        return None, out[:300]


def _q(value) -> str:
    return "'" + str(value).replace("'", "''") + "'"


# ---------------------------------------------------------------------------
# Read-only status
# ---------------------------------------------------------------------------

_STATUS_PS = r"""
$ErrorActionPreference='SilentlyContinue'
$d = @{}
$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
if($mp){ $d.defender = [pscustomobject]@{
  antimalware=$mp.AMServiceEnabled; realtime=$mp.RealTimeProtectionEnabled;
  engine=$mp.AMEngineVersion } }
$pref = Get-MpPreference -ErrorAction SilentlyContinue
if($pref){ $d.asr_ids=@($pref.AttackSurfaceReductionRules_Ids);
           $d.asr_actions=@($pref.AttackSurfaceReductionRules_Actions) }
$d.applocker_service = (Get-Service AppIDSvc -ErrorAction SilentlyContinue).Status
$local = Get-AppLockerPolicy -Local -ErrorAction SilentlyContinue
$d.applocker_rules = if($local){
  [int](@($local.RuleCollections | ForEach-Object { $_.Count }) |
        Measure-Object -Sum).Sum } else { 0 }
$d.applocker_audit = if($local){
  [bool](@($local.RuleCollections | Where-Object { "$($_.EnforcementMode)" -eq 'AuditOnly' }).Count)
} else { $false }
$d.wdac_policies = @(Get-ChildItem 'C:\Windows\System32\CodeIntegrity\CiPolicies\Active\*.cip' -ErrorAction SilentlyContinue).Count
$d.firewall = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object {
  "$($_.Name):$($_.DefaultOutboundAction)" })
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
$d.lsa_protection = $lsa.RunAsPPL
$d.prefix_rules = @(Get-NetFirewallRule -DisplayName 'PlasmaPrevent-*' -ErrorAction SilentlyContinue).Count
$d | ConvertTo-Json -Depth 5 -Compress
"""


def status() -> dict:
    data, err = _ps_json(_STATUS_PS)
    if data is None:
        return {"error": "could not read prevention state", "detail": err}
    ids = [i for i in (data.get("asr_ids") or []) if i]
    actions = list(data.get("asr_actions") or [])
    data["asr"] = dict(zip(ids, actions)) if ids else {}
    data.pop("asr_ids", None)
    data.pop("asr_actions", None)
    return data


# ---------------------------------------------------------------------------
# AppLocker (execution control)
# ---------------------------------------------------------------------------

DEFAULT_ALLOWED_PATHS = ["%WINDIR%\\*", "%PROGRAMFILES%\\*",
                         "%PROGRAMFILES(X86)%\\*"]


def _path_rule(path: str, name: str, action: str, sid: str) -> str:
    rule_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"plasma:{name}:{path}"))
    return (
        f'    <FilePathRule Id="{rule_id}" Name="{escape(name)}" '
        f'Description="Plasma generated" UserOrGroupSid="{sid}" '
        f'Action="{action}">\n'
        f'      <Conditions><FilePathCondition Path="{escape(path)}"/></Conditions>\n'
        f'    </FilePathRule>\n')


def applocker_xml(mode: str = "audit", allow_paths=None) -> str:
    """Generate an AppLocker Exe policy XML. mode: audit|enforce."""
    if mode not in ("audit", "enforce"):
        raise ValueError("mode must be audit or enforce")
    enforcement = "AuditOnly" if mode == "audit" else "Enabled"
    paths = list(DEFAULT_ALLOWED_PATHS)
    for path in allow_paths or []:
        path = str(path).strip()
        if not path or len(path) > 260 or any(ch in path for ch in '<>"'):
            raise ValueError(f"unsafe allow path: {path!r}")
        if path not in paths:
            paths.append(path)
    rules = "".join(_path_rule(path, f"Plasma allow {path}", "Allow", "S-1-1-0")
                    for path in paths)
    # Administrators always keep access to everything; without this an
    # enforcement mistake locks the operator out of their own tooling.
    admin_rule = _path_rule("%OSDRIVE%\\*", "Plasma allow Administrators",
                            "Allow", "S-1-5-32-544")
    return (
        '<AppLockerPolicy Version="1">\n'
        f'  <RuleCollection Type="Exe" EnforcementMode="{enforcement}">\n'
        f'{rules}{admin_rule}'
        '  </RuleCollection>\n'
        '</AppLockerPolicy>\n')


_APPLOCKER_BACKUP_PS = r"""
$ErrorActionPreference='Stop'
$dir = __BACKUP_DIR__
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$path = Join-Path $dir ('applocker-' + (Get-Date -Format 'yyyyMMddHHmmss') + '.xml')
$xml = (Get-AppLockerPolicy -Effective -Xml -ErrorAction SilentlyContinue)
if($xml){ [IO.File]::WriteAllText($path, $xml) } else { '' | Out-File $path -Encoding utf8 }
$path
"""

_APPLOCKER_APPLY_PS = r"""
$ErrorActionPreference='Stop'
$policy = __POLICY_PATH__
Set-AppLockerPolicy -XmlPolicy $policy -ErrorAction Stop | Out-Null
# Verify against the LOCAL policy object. `-Effective` lags the local write
# and returned zero rules in the field even though the policy had applied.
$local = Get-AppLockerPolicy -Local -ErrorAction SilentlyContinue
$rules = if($local){
  [int](@($local.RuleCollections | ForEach-Object { $_.Count }) |
        Measure-Object -Sum).Sum } else { 0 }
$audit = if($local){
  [bool](@($local.RuleCollections | Where-Object { "$($_.EnforcementMode)" -eq 'AuditOnly' }).Count)
} else { $false }
[pscustomobject]@{applied=$true; rules=$rules; audit=$audit; sha=$(
  (Get-FileHash $policy -Algorithm SHA256).Hash.ToLower())} | ConvertTo-Json -Compress
"""

_APPLOCKER_ROLLBACK_PS = r"""
$ErrorActionPreference='Stop'
$backup = __BACKUP_PATH__
if($backup -and (Test-Path $backup)){
  $xml = Get-Content $backup -Raw
  if($xml -and $xml -match '<AppLockerPolicy'){
    Set-AppLockerPolicy -XmlPolicy $backup -ErrorAction Stop | Out-Null
    [pscustomobject]@{restored=$true; from=$backup} | ConvertTo-Json -Compress
    exit 0
  }
}
# No prior policy: apply an empty policy, which clears the local rule set.
$empty = Join-Path $env:TEMP 'plasma-empty-applocker.xml'
[IO.File]::WriteAllText($empty, '<AppLockerPolicy Version="1" />')
Set-AppLockerPolicy -XmlPolicy $empty -ErrorAction Stop | Out-Null
[pscustomobject]@{restored=$false; cleared=$true} | ConvertTo-Json -Compress
"""


def _backup_dir(root) -> Path:
    return Path(root) / BACKUP_DIR


def applocker(root, mode="audit", allow_paths=None, apply=False, plan=None,
              reason=None) -> dict:
    root = Path(root)
    try:
        xml = applocker_xml(mode, allow_paths)
    except ValueError as exc:
        return {"error": str(exc), "code": "REFUSED"}
    digest = hashlib.sha256(xml.encode()).hexdigest()
    backup = _backup_dir(root)
    if not apply:
        return _append_journal(root, {
            "control": "applocker", "mode": mode, "payload_sha256": digest,
            "status": "dry-run", "reason": reason,
            "undo": {"kind": "applocker", "backup_dir": str(backup)},
            "preview": xml[:4000],
        })
    entry = _check_plan(root, plan, "applocker", digest, reason)
    if "error" in entry:
        return entry
    backup.mkdir(parents=True, exist_ok=True)
    rc, out = _ps(_APPLOCKER_BACKUP_PS.replace("__BACKUP_DIR__", _q(str(backup))))
    if rc != 0:
        return {"error": "could not back up the current AppLocker policy",
                "detail": out[:300], "code": "REFUSED"}
    backup_file = out.splitlines()[-1].strip() if out.strip() else ""
    policy_file = backup / f"plasma-applocker-{digest[:12]}.xml"
    policy_file.write_text(xml, encoding="utf-8")
    rc, out = _ps(_APPLOCKER_APPLY_PS.replace("__POLICY_PATH__", _q(str(policy_file))))
    result, err = _parse_json_tail(rc, out)
    if result is None:
        return {"error": "AppLocker policy apply failed", "detail": err,
                "code": "FAILED"}
    return _append_journal(root, {
        "control": "applocker", "mode": mode, "payload_sha256": digest,
        "status": "applied", "reason": reason, "plan": plan,
        "verification": result,
        "undo": {"kind": "applocker", "backup": backup_file,
                 "policy_file": str(policy_file)},
    })


# ---------------------------------------------------------------------------
# Firewall egress default-deny
# ---------------------------------------------------------------------------

def validate_allow(entries) -> list[dict]:
    out = []
    for raw in entries or []:
        text = str(raw).strip()
        host, _, port = text.partition(":")
        if not _IPV4.match(host):
            raise ValueError(f"not an IPv4 address or CIDR: {raw!r}")
        if _IPV4.match(host) and "/" in host:
            prefix = int(host.split("/", 1)[1])
            if prefix > 32:
                raise ValueError(f"invalid CIDR prefix: {raw!r}")
        octets = host.split("/", 1)[0].split(".")
        if any(int(o) > 255 for o in octets):
            raise ValueError(f"invalid IPv4 address: {raw!r}")
        if port:
            if not port.isdigit() or not 1 <= int(port) <= 65535:
                raise ValueError(f"invalid port: {raw!r}")
        out.append({"remote": host, "port": int(port) if port else None})
    return out


def egress_warnings(entries) -> list[str]:
    """Advisory checks the payload cannot enforce for the operator."""
    allows = validate_allow(entries)
    warnings = []
    if not any(item["port"] == 53 for item in allows):
        warnings.append(
            "no port-53 destination in the allowlist: DNS resolution may "
            "fail — add your DNS server explicitly (IP:53)")
    return warnings


def egress_payload(entries) -> str:
    """Render the PowerShell that creates allow rules then one block rule."""
    allows = validate_allow(entries)
    lines = ["$ErrorActionPreference='Stop'",
             "Get-NetFirewallRule -DisplayName 'PlasmaPrevent-Egress-*' "
             "-ErrorAction SilentlyContinue | Remove-NetFirewallRule "
             "-ErrorAction SilentlyContinue"]
    if not allows:
        raise ValueError("at least one allowed destination is required "
                         "(blocking all egress without an allowlist locks "
                         "the host out of updates and DNS)")
    for index, item in enumerate(allows):
        proto = "-Protocol TCP " if item["port"] else ""
        port = (f"-RemotePort {item['port']} " if item["port"] else "")
        lines.append(
            f"New-NetFirewallRule -DisplayName 'PlasmaPrevent-Egress-Allow-{index}' "
            f"-Direction Outbound -Action Allow {proto}{port}"
            f"-RemoteAddress '{item['remote']}' -Profile Any | Out-Null")
    lines.append(
        "New-NetFirewallRule -DisplayName 'PlasmaPrevent-Egress-Block' "
        "-Direction Outbound -Action Block -Profile Any | Out-Null")
    lines.append(
        "$n = @(Get-NetFirewallRule -DisplayName 'PlasmaPrevent-Egress-*').Count; "
        "[pscustomobject]@{applied=$true; rules=$n} | ConvertTo-Json -Compress")
    return "\n".join(lines)


def egress(root, allow, apply=False, plan=None, reason=None) -> dict:
    root = Path(root)
    try:
        payload = egress_payload(allow)
    except ValueError as exc:
        return {"error": str(exc), "code": "REFUSED"}
    digest = hashlib.sha256(payload.encode()).hexdigest()
    warnings = egress_warnings(allow)
    if not apply:
        return _append_journal(root, {
            "control": "egress", "payload_sha256": digest, "status": "dry-run",
            "reason": reason, "allow": list(allow or []), "warnings": warnings,
            "undo": {"kind": "egress"}, "preview": payload[:4000],
        })
    entry = _check_plan(root, plan, "egress", digest, reason)
    if "error" in entry:
        return entry
    rc, out = _ps(payload, timeout=180)
    result, err = _parse_json_tail(rc, out)
    if result is None:
        return {"error": "egress policy apply failed", "detail": err,
                "code": "FAILED"}
    return _append_journal(root, {
        "control": "egress", "payload_sha256": digest, "status": "applied",
        "reason": reason, "plan": plan, "allow": list(allow or []),
        "warnings": warnings, "verification": result,
        "undo": {"kind": "egress"},
    })


# ---------------------------------------------------------------------------
# Defender ASR
# ---------------------------------------------------------------------------

def parse_asr(ids, action="Audit") -> list[str]:
    if action not in _ASR_ACTIONS:
        raise ValueError("action must be Audit, Enabled/Block or Disabled")
    if isinstance(ids, str):
        ids = ids.split(",")
    out = []
    for raw in ids or []:
        text = str(raw).strip()
        if not text:
            continue
        if not _GUID.match(text):
            raise ValueError(f"not an ASR rule GUID: {text!r}")
        out.append(text.lower())
    if not out:
        raise ValueError("at least one ASR rule id is required")
    return out


_ASR_STATUS_PS = r"""
$ErrorActionPreference='SilentlyContinue'
$p = Get-MpPreference
[pscustomobject]@{ids=@($p.AttackSurfaceReductionRules_Ids);
                  actions=@($p.AttackSurfaceReductionRules_Actions)} |
  ConvertTo-Json -Compress
"""


def _asr_previous(ids) -> dict:
    data, _ = _ps_json(_ASR_STATUS_PS, timeout=60)
    previous = {}
    if data:
        current = dict(zip(data.get("ids") or [], data.get("actions") or []))
        for rule in ids:
            match = next((k for k in current if str(k).lower() == rule), None)
            previous[rule] = current.get(match) if match else "Disabled"
    return previous


def asr(ids, action="Audit", apply=False, plan=None, reason=None, root=".") -> dict:
    root = Path(root)
    try:
        rules = parse_asr(ids, action)
    except ValueError as exc:
        return {"error": str(exc), "code": "REFUSED"}
    target = _ASR_ACTIONS[action]
    list_literal = ",".join(f"'{r}'" for r in rules)
    payload = (
        "$ErrorActionPreference='Stop'\n"
        f"Add-MpPreference -AttackSurfaceReductionRules_Ids {list_literal} "
        f"-AttackSurfaceReductionRules_Actions {target} -ErrorAction Stop\n"
        "[pscustomobject]@{applied=$true} | ConvertTo-Json -Compress")
    digest = hashlib.sha256(payload.encode()).hexdigest()
    if not apply:
        return _append_journal(root, {
            "control": "asr", "action": target, "ids": rules,
            "payload_sha256": digest, "status": "dry-run", "reason": reason,
            "undo": {"kind": "asr", "ids": rules}, "preview": payload[:4000],
        })
    entry = _check_plan(root, plan, "asr", digest, reason)
    if "error" in entry:
        return entry
    previous = _asr_previous(rules)
    rc, out = _ps(payload, timeout=180)
    result, err = _parse_json_tail(rc, out)
    if result is None:
        return {"error": "ASR apply failed (Defender may be absent or managed "
                         "by policy)", "detail": err, "code": "FAILED"}
    return _append_journal(root, {
        "control": "asr", "action": target, "ids": rules,
        "payload_sha256": digest, "status": "applied", "reason": reason,
        "plan": plan, "verification": result,
        "undo": {"kind": "asr", "ids": rules, "previous": previous},
    })


# ---------------------------------------------------------------------------
# LSA protection
# ---------------------------------------------------------------------------

def lsa(apply=False, plan=None, reason=None, root=".", enable=True) -> dict:
    root = Path(root)
    value = 1 if enable else 0
    payload = (
        "$ErrorActionPreference='Stop'\n"
        "$p='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'\n"
        f"New-ItemProperty -Path $p -Name RunAsPPL -Value {value} "
        "-PropertyType DWord -Force | Out-Null\n"
        "$v=(Get-ItemProperty $p).RunAsPPL\n"
        "[pscustomobject]@{applied=$true; RunAsPPL=$v; reboot_required=$true} "
        "| ConvertTo-Json -Compress")
    digest = hashlib.sha256(payload.encode()).hexdigest()
    if not apply:
        return _append_journal(root, {
            "control": "lsa", "enable": bool(enable),
            "payload_sha256": digest, "status": "dry-run", "reason": reason,
            "undo": {"kind": "lsa"}, "preview": payload[:2000],
        })
    entry = _check_plan(root, plan, "lsa", digest, reason)
    if "error" in entry:
        return entry
    rc, out = _ps(payload, timeout=60)
    result, err = _parse_json_tail(rc, out)
    if result is None:
        return {"error": "LSA protection apply failed", "detail": err,
                "code": "FAILED"}
    return _append_journal(root, {
        "control": "lsa", "enable": bool(enable), "payload_sha256": digest,
        "status": "applied", "reason": reason, "plan": plan,
        "verification": result, "undo": {"kind": "lsa"},
    })


# ---------------------------------------------------------------------------
# Plan gate, rollback, status
# ---------------------------------------------------------------------------

def _check_plan(root, plan, control, digest, reason) -> dict:
    if plan is None:
        return {"error": "--apply requires --plan <id> from a prior dry-run "
                         "(dry-run first, always)", "code": "REFUSED"}
    if not reason or not str(reason).strip():
        return {"error": "a --reason is mandatory for every apply",
                "code": "REFUSED"}
    rows = _read_journal(root)
    dry = next((r for r in rows if int(r.get("id") or 0) == int(plan)), None)
    if not dry:
        return {"error": f"--plan {plan}: no such journal entry",
                "code": "REFUSED"}
    if dry.get("status") != "dry-run" or dry.get("control") != control:
        return {"error": f"--plan {plan} is not a dry-run of '{control}'",
                "code": "REFUSED"}
    if dry.get("payload_sha256") != digest:
        return {"error": f"--plan {plan} rendered a different payload; "
                         f"re-run the dry-run", "code": "REFUSED"}
    if any(r.get("status") == "applied" and r.get("plan") == plan for r in rows):
        return {"error": f"--plan {plan} has already been used",
                "code": "REFUSED"}
    return {}


def _parse_json_tail(rc: int, out: str):
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


def rollback(root, entry_id: int, apply: bool = False) -> dict:
    root = Path(root)
    rows = _read_journal(root)
    row = next((r for r in rows if int(r.get("id") or 0) == int(entry_id)), None)
    if not row:
        return {"error": f"no prevention entry {entry_id}"}
    if row.get("status") != "applied":
        return {"error": f"entry {entry_id} is {row.get('status')}, not applied"}
    undo = row.get("undo") or {}
    kind = undo.get("kind")
    if kind == "applocker":
        script = _APPLOCKER_ROLLBACK_PS.replace(
            "__BACKUP_PATH__", _q(undo.get("backup") or ""))
    elif kind == "egress":
        script = (
            "$ErrorActionPreference='Stop'\n"
            "Get-NetFirewallRule -DisplayName 'PlasmaPrevent-Egress-*' "
            "-ErrorAction SilentlyContinue | Remove-NetFirewallRule "
            "-ErrorAction Continue\n"
            "[pscustomobject]@{removed=$true} | ConvertTo-Json -Compress")
    elif kind == "asr":
        previous = undo.get("previous") or {}
        payload_lines = []
        for rule, action in previous.items():
            payload_lines.append(
                f"Add-MpPreference -AttackSurfaceReductionRules_Ids '{rule}' "
                f"-AttackSurfaceReductionRules_Actions {action} "
                "-ErrorAction SilentlyContinue")
        script = ("$ErrorActionPreference='Continue'\n"
                  + "\n".join(payload_lines) +
                  "\n[pscustomobject]@{restored=$true} | ConvertTo-Json -Compress")
    elif kind == "lsa":
        script = (
            "$ErrorActionPreference='Stop'\n"
            "$p='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'\n"
            "Remove-ItemProperty -Path $p -Name RunAsPPL -Force "
            "-ErrorAction SilentlyContinue\n"
            "[pscustomobject]@{restored=$true; reboot_required=$true} "
            "| ConvertTo-Json -Compress")
    else:
        return {"error": f"entry {entry_id} has no rollback recipe"}
    if not apply:
        return {"entry": entry_id, "control": kind, "dry_run": True,
                "script_preview": script[:2000]}
    rc, out = _ps(script, timeout=180)
    result, err = _parse_json_tail(rc, out)
    if result is None:
        return {"error": "rollback failed", "detail": err, "code": "FAILED"}
    _append_journal(root, {
        "control": kind, "status": "rolled_back", "rollback_of": entry_id,
        "verification": result, "undo": {"kind": kind},
    })
    return {"entry": entry_id, "control": kind, "rolled_back": True,
            "result": result}
