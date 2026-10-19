"""Plasma observatory: rmagent-so-style named questions answered locally.

Every question is a fixed, read-only PowerShell payload executed on the
endpoint (`powershell.exe -NoProfile -Command <payload>`). Payloads are
PS 5.1-compatible, never interpolate targets, and end with a single
ConvertTo-Json line. Event fields are read BY NAME from the event XML
(Ed() helper) so Windows schema index drift cannot corrupt answers.

Questions (rmagent-so lineage, Windows-native):
  attest         witness liveness + blind_check (can the sensor actually see?)
  sketch         identity snapshot: admins, group adds, new services/tasks,
                 untrusted drivers (24h window)
  edges          who logged in from where (4624), explicit-cred and elevation
                 counts (24h)
  explain        account/group/service/WMI changes, audit clears, LOLBin
                 spawns (24h) — the "why did this happen" narrative
  pslogs         PowerShell scriptblock logging (4104), capped snippets
  attackmap      registry persistence checks (Run/IFEO/SPE/Winlogon/LSA),
                 ATT&CK technique tagged
  regedges       Sysmon registry-set edges (EID 13) over 24h, capped
  flowstats      adapter counters + top remote TCP peers with owning process
  canary         did any configured canary username authenticate recently?
  sysmon_health  Sysmon channel volume by event id (kernring-lite)

Everything here is read-only: payloads contain no Set-*, no netsh writes,
no Stop-* verbs. Endpoint-side failures come back as data ({"error": ...}),
never as exceptions — a blind witness is itself a finding.
"""

from __future__ import annotations

import json
import shutil
import subprocess

QUESTION_CAP = 25          # rows per answer, mirroring ROW_CAP digests
CHAR_CAP = 16384           # answer size cap
COLLECT_TIMEOUT = 90       # seconds

# Shared PowerShell prologue: strict-ish, named-field event parser, cap.
_PS_HEAD = r"""
$ErrorActionPreference = 'SilentlyContinue'
$cap = 25
function Ed($e) {
    $x = [xml]$e.ToXml(); $o = @{}
    foreach ($d in $x.Event.EventData.Data) { if ($d.Name) { $o[$d.Name] = $d.'#text' } }
    return $o
}
function TrimTxt($v, $n) {
    $s = ($v | Out-String).Trim()
    if ($s.Length -gt $n) { $s.Substring(0, $n) } else { $s }
}
"""


def _ps_literal(value: str) -> str:
    """Escape a value for embedding in a single-quoted PS string literal."""
    return "'" + str(value).replace("'", "''") + "'"


# ---------------------------------------------------------------------------
# Payloads. One function per question; each returns the PowerShell script.
# ---------------------------------------------------------------------------

def _ps_attest():
    return _PS_HEAD + r"""
$ans = @{}
$os = Get-CimInstance Win32_OperatingSystem
$ans.host = $env:COMPUTERNAME
$ans.boot_time = if ($os) { $os.LastBootUpTime.ToString('o') } else { $null }
$ans.uptime_hours = if ($os) { [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1) } else { $null }

# blind_check: is the audit policy actually watching what we rely on?
$blind = @()
$audit = (auditpol.exe /get /category:* /r) 2>$null | ConvertFrom-Csv
foreach ($s in @('Logon','Logoff','Process Creation','Registry','File Share','Other Logon/Logoff Events')) {
    $row = $audit | Where-Object { $_.'Subcategory' -eq $s }
    if (-not $row -or $row.'Inclusion Setting' -notmatch 'Success') { $blind += $s }
}
$sbReg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction SilentlyContinue
if (-not $sbReg -or -not $sbReg.ProcessCreationIncludeCmdLine_Enabled) { $blind += 'Process Creation: command line off' }
$sbLog = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104 } -MaxEvents 1
if (-not $sbLog) { $blind += 'ScriptBlockLogging: no 4104 on record' }
$ans.blind_subcategories = @($blind)
$ans.blind_count = @($blind).Count
$ans.blind_severity = if (@($blind).Count -gt 0) { 'blind' } else { 'ok' }

# Sensor liveness: newest event ages
$sysev = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=1 } -MaxEvents 1
$ans.sysmon_newest_event_age_min = if ($sysev) { [math]::Round(((Get-Date) - $sysev.TimeCreated).TotalMinutes, 1) } else { $null }
$ans.sysmon_service = (Get-Service Sysmon64 -ErrorAction SilentlyContinue).Status
if (-not $ans.sysmon_service) { $ans.sysmon_service = (Get-Service Sysmon -ErrorAction SilentlyContinue).Status }
$ans.whids_service = (Get-Service Whids -ErrorAction SilentlyContinue).Status
$ans.whids_alerts_present = Test-Path 'C:\Program Files\Whids\Logs\Alerts'

# 24h logon volume
$since = (Get-Date).AddHours(-24)
$sec = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4624,4625; StartTime=$since }
$ans.logon_ok_24h = @($sec | Where-Object Id -eq 4624).Count
$ans.logon_fail_24h = @($sec | Where-Object Id -eq 4625).Count
$ans.admin_fail_24h = @($sec | Where-Object {
    ($_.Id -eq 4625) -and ((Ed $_).TargetUserName -eq 'Administrator') }).Count
$oldest = Get-WinEvent -Oldest -FilterHashtable @{ LogName='Security' } -MaxEvents 1
$ans.oldest_security_event = if ($oldest) { $oldest.TimeCreated.ToString('o') } else { $null }
$ans | ConvertTo-Json -Depth 6 -Compress
"""


def _ps_sketch():
    return _PS_HEAD + r"""
$ans = @{}
$since = (Get-Date).AddHours(-24)

$admins = @(Get-LocalGroupMember -Group 'Administrators' | ForEach-Object { $_.Name } | Sort-Object)
$ans.administrators = $admins

$adds = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4732,4728; StartTime=$since }
$ans.admin_group_adds_24h = @($adds | Select-Object -First $cap | ForEach-Object {
    $d = Ed $_
    @{ when=$_.TimeCreated.ToString('o'); group=$d.TargetUserName; member=$d.MemberName } })
$ans.admin_group_adds_total_24h = @($adds).Count

$svc = Get-WinEvent -FilterHashtable @{ LogName='System'; Id=7045; StartTime=$since }
$ans.services_installed_24h = @($svc | Select-Object -First $cap | ForEach-Object {
    $d = Ed $_
    @{ when=$_.TimeCreated.ToString('o'); name=$d.ServiceName; path=TrimTxt $d.ImagePath 220 } })

$ans.system_services_unusual = @(Get-CimInstance Win32_Service |
    Where-Object { $_.StartName -eq 'LocalSystem' -and $_.PathName -and
                   ($_.PathName -notmatch 'Windows\\\\') -and ($_.PathName -notmatch 'Program Files') } |
    Select-Object -First $cap | ForEach-Object {
        @{ name=$_.Name; path=TrimTxt $_.PathName 220 } })

$tasks = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4698; StartTime=$since }
$ans.tasks_created_24h = @($tasks | Select-Object -First $cap | ForEach-Object {
    $d = Ed $_
    @{ when=$_.TimeCreated.ToString('o'); task=$d.TaskName; actor=$d.SubjectUserName } })

$ans.untrusted_drivers = @(Get-CimInstance Win32_SystemDriver |
    Where-Object { $_.PathName } | Select-Object -First 80 | ForEach-Object {
        $p = $_.PathName -replace '^\\\\\\?\\',''
        $sig = Get-AuthenticodeSignature $p
        if ($sig -and $sig.SignerCertificate -and ($sig.SignerCertificate.Subject -notmatch 'Microsoft')) {
            @{ name=$_.Name; signer=($sig.SignerCertificate.Subject -split ',')[0] }
        } })
$ans | ConvertTo-Json -Depth 6 -Compress
"""


def _ps_edges():
    return _PS_HEAD + r"""
$since = (Get-Date).AddHours(-24)
$logons = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4624; StartTime=$since }
$rows = @()
foreach ($e in ($logons | Select-Object -First 120)) {
    $d = Ed $e
    if ($d.IpAddress -and $d.IpAddress -ne '-') {
        $rows += @{ when=$e.TimeCreated.ToString('o'); user=$d.TargetUserName
                    logon_type=$d.LogonType; source_ip=$d.IpAddress
                    process=TrimTxt $d.ProcessName 120 }
    }
}
$ans = @{
    logons_considered_24h = @($logons).Count
    explicit_creds_24h = @(Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4648; StartTime=$since }).Count
    elevated_24h = @(Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4672; StartTime=$since }).Count
    edges = @($rows | Select-Object -First $cap)
}
$ans | ConvertTo-Json -Depth 6 -Compress
"""


def _ps_explain():
    return _PS_HEAD + r"""
$since = (Get-Date).AddHours(-24)
$ans = @{}
$ans.account_changes = @(Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4720,4722,4725,4726,4738; StartTime=$since } |
    Select-Object -First $cap | ForEach-Object {
        $d = Ed $_
        @{ when=$_.TimeCreated.ToString('o'); id=$_.Id; target=$d.TargetUserName; actor=$d.SubjectUserName } })
$ans.group_changes = @(Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4728,4732,4735; StartTime=$since } |
    Select-Object -First $cap | ForEach-Object {
        $d = Ed $_
        @{ when=$_.TimeCreated.ToString('o'); id=$_.Id; group=$d.TargetUserName; member=$d.MemberName } })
$ans.service_installs = @(Get-WinEvent -FilterHashtable @{ LogName='System'; Id=7045; StartTime=$since } |
    Select-Object -First $cap | ForEach-Object {
        $d = Ed $_
        @{ when=$_.TimeCreated.ToString('o'); name=$d.ServiceName; image=TrimTxt $d.ImagePath 220 } })
$ans.wmi_subscriptions = @(Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WMI-Activity/Operational'; Id=5861; StartTime=$since } |
    Select-Object -First $cap | ForEach-Object {
        $d = Ed $_
        @{ when=$_.TimeCreated.ToString('o'); ns=$d.Namespace; query=TrimTxt $d.Query 200 } })
$ans.audit_cleared_24h = @(Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=1102; StartTime=$since }).Count
$lolbins = @('powershell.exe','cmd.exe','certutil.exe','mshta.exe','rundll32.exe','regsvr32.exe','msbuild.exe','installutil.exe')
$ans.lolbin_spawns = @(Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=$since } |
    Select-Object -First 200 | ForEach-Object {
        $d = Ed $_
        if ($lolbins -contains ($d.Image.ToLower().Split('\')[-1])) {
            @{ when=$_.TimeCreated.ToString('o'); proc=$d.Image.ToLower().Split('\')[-1]
               parent=TrimTxt $d.ParentImage 120; cmd=TrimTxt $d.CommandLine 250 } } } |
    Select-Object -First $cap)
$ans | ConvertTo-Json -Depth 6 -Compress
"""


def _ps_pslogs():
    return _PS_HEAD + r"""
$events = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104 } -MaxEvents 40
$rows = @()
foreach ($e in ($events | Select-Object -First $cap)) {
    $d = Ed $e
    $rows += @{ when=$e.TimeCreated.ToString('o')
                path=$d.Path
                snippet=TrimTxt $d.ScriptBlockText 300 }
}
$ans = @{ scriptblocks_on_record = @($events).Count; blocks = $rows }
$ans | ConvertTo-Json -Depth 6 -Compress
"""


def _ps_attackmap():
    return _PS_HEAD + r"""
$ans = @{ findings = @() }
function Add-F($t, $loc, $val) {
    $ans.findings += @{ technique=$t; location=$loc; value=TrimTxt $val 250 }
}
$runPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($p in $runPaths) {
    $k = Get-Item $p -ErrorAction SilentlyContinue
    if ($k) { foreach ($n in $k.GetValueNames()) { Add-F 'T1547.001' "$p\$n" ($k.GetValue($n) | Out-String) } }
}
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
foreach ($k in (Get-ChildItem $ifeo -ErrorAction SilentlyContinue)) {
    $dbg = $k.GetValue('Debugger')
    if ($dbg) { Add-F 'T1546.012' "$ifeo\$($k.PSChildName)\Debugger" $dbg }
}
$spe = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
foreach ($k in (Get-ChildItem $spe -ErrorAction SilentlyContinue)) {
    Add-F 'T1546.012' "$spe\$($k.PSChildName)" ($k.GetValueNames() -join ',')
}
$wl = Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
foreach ($n in @('Shell','Userinit','AppSetup')) { Add-F 'T1547.004' "Winlogon\$n" ($wl.GetValue($n) | Out-String) }
$lsa = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$ans.lsa_protection = $lsa.GetValue('RunAsPPL')
$ans.lsa_notification_packages = @($lsa.GetValue('Notification Packages'))
foreach ($p in $ans.lsa_notification_packages) {
    if ($p -and ($p.ToLower() -ne 'scecli')) { Add-F 'T1547.005' 'Lsa\Notification Packages' $p }
}
$ans.findings = @($ans.findings | Select-Object -First $cap)
$ans | ConvertTo-Json -Depth 6 -Compress
"""


def _ps_regedges():
    return _PS_HEAD + r"""
$since = (Get-Date).AddHours(-24)
$ev = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=13; StartTime=$since }
$rows = @()
foreach ($e in ($ev | Select-Object -First 120)) {
    $d = Ed $e
    $rows += @{ when=$e.TimeCreated.ToString('o'); etype=$d.EventType
                target=TrimTxt $d.TargetObject 220; image=TrimTxt $d.Image 160 }
}
$ans = @{ registry_sets_24h = @($ev).Count; edges = @($rows | Select-Object -First $cap) }
$ans | ConvertTo-Json -Depth 6 -Compress
"""


def _ps_flowstats():
    return _PS_HEAD + r"""
$ans = @{}
$ans.adapters = @(Get-NetAdapterStatistics | ForEach-Object {
    @{ name=$_.Name; sent_gb=[math]::Round($_.SentBytes/1GB,2); recv_gb=[math]::Round($_.ReceivedBytes/1GB,2) } })
$peers = @{}
foreach ($c in (Get-NetTCPConnection -State Established)) {
    if ($c.RemoteAddress -notmatch '^(127\.|0\.0\.0\.0|::1|::)') {
        $key = "$($c.RemoteAddress):$($c.RemotePort)"
        if (-not $peers[$key]) {
            $peers[$key] = @{ remote=$key; connections=0; procs=(New-Object System.Collections.Generic.HashSet[string]) }
        }
        $peers[$key].connections++
        $pn = (Get-Process -Id $c.OwningProcess).ProcessName
        if ($pn) { [void]$peers[$key].procs.Add($pn) }
    }
}
$ans.remote_peers = @($peers.Values | Sort-Object connections -Descending |
    Select-Object -First $cap | ForEach-Object {
        @{ remote=$_.remote; connections=$_.connections; processes=@($_.procs) } })
$ans | ConvertTo-Json -Depth 6 -Compress
"""


def _ps_canary(canaries):
    names = ", ".join(_ps_literal(c) for c in canaries)
    return _PS_HEAD + f"""
$canaries = @({names})
$since = (Get-Date).AddDays(-7)
$ev = Get-WinEvent -FilterHashtable @{{ LogName='Security'; Id=4624,4625; StartTime=$since }}
$rows = @()
foreach ($e in $ev) {{
    $d = Ed $e
    if ($canaries -contains $d.TargetUserName) {{
        $rows += @{{ when=$e.TimeCreated.ToString('o'); id=$e.Id; user=$d.TargetUserName
                    source_ip=$d.IpAddress; logon_type=$d.LogonType }}
    }}
}}
$ans = @{{ canaries=$canaries; window_days=7; hit_count=@($rows).Count; hits=@($rows | Select-Object -First $cap) }}
$ans | ConvertTo-Json -Depth 6 -Compress
"""


def _ps_sysmon_health():
    return _PS_HEAD + r"""
$since = (Get-Date).AddHours(-6)
$ev = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$since }
$byId = @($ev | Group-Object Id | Sort-Object Count -Descending |
    Select-Object -First 15 | ForEach-Object { @{ id=[int]$_.Name; count=$_.Count } })
$svc = Get-Service Sysmon64, Sysmon -ErrorAction SilentlyContinue
$ans = @{
    events_6h = @($ev).Count
    by_event_id = $byId
    sysmon_services = @($svc | ForEach-Object { @{ name=$_.Name; status=$_.Status } })
}
$ans | ConvertTo-Json -Depth 6 -Compress
"""


QUESTIONS = {
    "attest": lambda canaries: _ps_attest(),
    "sketch": lambda canaries: _ps_sketch(),
    "edges": lambda canaries: _ps_edges(),
    "explain": lambda canaries: _ps_explain(),
    "pslogs": lambda canaries: _ps_pslogs(),
    "attackmap": lambda canaries: _ps_attackmap(),
    "regedges": lambda canaries: _ps_regedges(),
    "flowstats": lambda canaries: _ps_flowstats(),
    "canary": lambda canaries: _ps_canary(canaries or ("plasma-canary",)),
    "sysmon_health": lambda canaries: _ps_sysmon_health(),
}


def questions():
    return sorted(QUESTIONS)


# ---------------------------------------------------------------------------
# Execution: run a payload locally, cap and return JSON. Never raises for
# endpoint-side failures — errors come back as data ({"error": ...}).
# ---------------------------------------------------------------------------

def _clip(value, limit=CHAR_CAP):
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def run_question(name, canaries=(), timeout=COLLECT_TIMEOUT):
    if name not in QUESTIONS:
        return {"error": f"unknown question '{name}'", "questions": questions()}
    exe = shutil.which("powershell.exe") or shutil.which("pwsh")
    if not exe:
        return {"error": "powershell not available on this host",
                "question": name, "host_support": False}
    try:
        proc = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-Command", QUESTIONS[name](canaries)],
            capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": "collector timeout", "question": name, "timeout": timeout}
    text = (proc.stdout or "").strip()
    if not text:
        return {"error": _clip((proc.stderr or "collector failed").strip(), 800),
                "question": name}
    try:
        answer = json.loads(text.splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return {"error": "collector did not emit JSON", "question": name,
                "raw_tail": _clip(text, 800)}
    answer["question"] = name
    return answer


def summarize(answer):
    """One-line human digest for CLI/notify paths (operator-facing)."""
    if "error" in answer:
        return f"{answer.get('question', '?')}: ERROR {str(answer['error'])[:80]}"
    name = answer.get("question", "?")
    if name == "attest":
        return (f"attest: blind={answer.get('blind_count', '?')} "
                f"logons24h ok={answer.get('logon_ok_24h', '?')} "
                f"fail={answer.get('logon_fail_24h', '?')} "
                f"sysmon={answer.get('sysmon_service', '?')} whids={answer.get('whids_service', '?')}")
    if name == "attackmap":
        n = len(answer.get("findings") or [])
        return f"attackmap: {n} persistence entries"
    if name == "canary":
        return f"canary: {answer.get('hit_count', 0)} hits / 7d"
    if name == "sysmon_health":
        return f"sysmon_health: {answer.get('events_6h', 0)} events / 6h"
    return f"{name}: ok"
