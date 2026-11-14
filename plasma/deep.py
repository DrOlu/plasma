"""Plasma deep: persistence_deep — every auto-start location, in one answer.

Sysmon tells you when a persistence location CHANGES. This probe sees them
ALL, always: registry run keys, services (+ service DLLs), scheduled task
actions, IFEO debugger hijacks, Winlogon shell/userinit, and WMI event
subscriptions — each with Authenticode signature status where a binary is
involved. Read-only, bounded, one JSON answer.

An item is flagged `suspect` when it is UNSIGNED and lives outside
C:\\Windows — a heuristic, surfaced as data, never as an automatic action.
"""

from __future__ import annotations

import json
import shutil
import subprocess

_WINDOWS = r"C:\Windows"

_PS_TEMPLATE = r"""
$ErrorActionPreference = 'SilentlyContinue'
$rows = @()
foreach ($rk in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run') {{
  $k = Get-Item $rk -ErrorAction SilentlyContinue
  if ($k) {{ foreach ($n in $k.GetValueNames()) {{
    $rows += [pscustomobject]@{{ source='run_key'; name=$n; detail="$rk"; path=[string]$k.GetValue($n) }}
  }} }}
}}
$rows += Get-CimInstance Win32_Service |
  Where-Object {{ $_.PathName }} |
  Select-Object -First {cap} |
  ForEach-Object {{ [pscustomobject]@{{ source='service'; name=$_.Name;
    detail=('start=' + $_.StartMode + ' as=' + $_.StartName); path=$_.PathName }} }}
$rows += Get-ScheduledTask |
  Where-Object {{ $_.TaskPath -notlike '\Microsoft*' }} |
  Select-Object -First {cap} |
  ForEach-Object {{
    $act = ($_.Actions | ForEach-Object {{ $_.Execute + ' ' + $_.Arguments }}) -join '; '
    [pscustomobject]@{{ source='scheduled_task'; name=$_.TaskName;
      detail=('path=' + $_.TaskPath + ' state=' + $_.State); path=$act }}
  }}
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {{
  $dbg = (Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
  if ($dbg) {{ $rows += [pscustomobject]@{{ source='ifeo'; name=$_.PSChildName; detail='debugger'; path=[string]$dbg }} }}
}}
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
foreach ($f in 'Shell','Userinit') {{
  if ($wl.$f) {{ $rows += [pscustomobject]@{{ source='winlogon'; name=$f; detail='winlogon'; path=[string]$wl.$f }} }}
}}
$subs = Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
foreach ($f in $subs) {{ $rows += [pscustomobject]@{{ source='wmi_filter'; name=$f.Name; detail='event filter'; path=$f.Query }} }}
foreach ($c in (Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue)) {{
  $rows += [pscustomobject]@{{ source='wmi_consumer'; name=$c.Name; detail=$c.PSClass; path='' }}
}}
$binds = Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue
$rows += [pscustomobject]@{{ source='wmi_bindings'; name=[string]$binds.Count; detail='filter-to-consumer bindings'; path='' }}
# signature check on distinct local binary paths (bounded)
$bins = @($rows | ForEach-Object {{
    if ($_.path -match '^"([^"]+)"') {{ $Matches[1] }} else {{ ($_.path -split ' -| /| /')[0] }}
  }} | Where-Object {{ $_ -match '^[A-Za-z]:\\' -and (Test-Path $_) }} | Sort-Object -Unique | Select-Object -First {cap})
$sigs = @{{}}
foreach ($b in $bins) {{
  $s = Get-AuthenticodeSignature $b
  $sigs[$b.ToLower()] = @{{
    signed = [bool]($s -and $s.SignerCertificate)
    signer = if ($s -and $s.SignerCertificate) {{ ($s.SignerCertificate.Subject -split ',')[0] }} else {{ '' }}
  }}
}}
@{{ rows = $rows; signatures = $sigs }} | ConvertTo-Json -Depth 4 -Compress
"""


def _run_ps(cap: int = 200) -> dict:
    exe = shutil.which("powershell.exe") or shutil.which("pwsh")
    if not exe:
        return {"error": "powershell not available on this host"}
    try:
        proc = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-Command",
             _PS_TEMPLATE.format(cap=int(cap))],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=180)
    except subprocess.TimeoutExpired:
        return {"error": "persistence probe timeout"}
    text = (proc.stdout or "").strip()
    if not text:
        return {"error": "persistence probe emitted no output"}
    try:
        start = text.find("{")
        return json.loads(text[start:]) if start >= 0 else {"error": "no JSON"}
    except json.JSONDecodeError:
        return {"error": "persistence probe did not emit JSON"}


def normalize(payload: dict, windows_dir: str = _WINDOWS.lower()) -> dict:
    """Raw probe payload -> cleaned rows with signature + suspect flags."""
    rows = payload.get("rows") or []
    sigs = payload.get("signatures") or {}
    out = []
    for r in rows:
        path = str(r.get("path") or "").strip()
        key = path.lower().strip('"')
        sig = sigs.get(key) or {}
        signed = sig.get("signed")
        in_windows = key.startswith(windows_dir)
        executable = key.endswith((".exe", ".dll", ".scr", ".com", ".ps1",
                                   ".bat", ".cmd", ".vbs", ".js", ".hta", ".msi"))
        suspect = bool(executable and signed is False and not in_windows and path)
        out.append({
            "source": str(r.get("source") or ""),
            "name": str(r.get("name") or "")[:128],
            "detail": str(r.get("detail") or "")[:160],
            "path": path[:400],
            "signed": signed if isinstance(signed, bool) else None,
            "signer": str(sig.get("signer") or "")[:160] or None,
            "suspect": suspect,
        })
    by_source: dict[str, int] = {}
    for r in out:
        by_source[r["source"]] = by_source.get(r["source"], 0) + 1
    suspects = [r for r in out if r["suspect"]]
    return {"items": out, "by_source": by_source,
            "suspect_count": len(suspects),
            "suspects": suspects[:25],
            "total": len(out)}


def run(out=None, cap: int = 200) -> dict:
    """Full probe: collect on-box, normalize, optionally write JSON."""
    payload = _run_ps(cap=cap)
    if "error" in payload:
        return payload
    result = normalize(payload)
    result["probe"] = "persistence_deep"
    if out:
        from pathlib import Path
        p = Path(out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(result, indent=1, ensure_ascii=False) + "\n",
                     encoding="utf-8")
        result["written"] = str(p)
    return result
