"""Plasma identity: Security-channel audit events into the store.

The ETW tap covers kernel-ish providers, but Security-channel audit events
(4624/4625 and friends) are written by LSA straight into the channel — they
are not re-emitted to realtime ETW sessions (proven on WS1: 75s window with
live 4625 generation, events_seen=0). This collector therefore reads the
Security channel through the Event Log API (fixed, read-only PowerShell),
normalizes records onto the strict PlasmaEvent contract and appends with
dedupe.

Covered shape:

* ``kind="auth"`` — 4624/4625 (logons), 4768/4769/4770/4771 (Kerberos
  TGT/TGS/renewal/pre-auth), 4776 (NTLM credential validation). Kerberos
  events only exist on a KDC (domain controller); on a member server they
  are legitimately zero and the result says so, it does not error.
* ``kind="process"`` — 4688 (process creation, including the creator
  subject, parent image and command line when the audit policy records it).
  This is the process-lineage feed; Sysmon EID 1 remains the richer source
  where it is installed.

Pull-based and bounded like everything else in Plasma: run it when you want
identity events, or let the ``PlasmaIdentityPull`` task do it on a cadence.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from . import agentstate

TASK_NAME = "PlasmaIdentityPull"
DEFAULT_IDS = (4624, 4625, 4688, 4768, 4769, 4770, 4771, 4776)
SUPPORTED_IDS = frozenset(DEFAULT_IDS)
LOGON_IDS = frozenset({4624, 4625})
KERBEROS_IDS = frozenset({4768, 4769, 4770, 4771})
NTLM_ID = 4776
PROCESS_ID = 4688
MAX_EVENTS = 2000
STATUS_SUCCESS = {"0x0", "0", "-"}

SEVERITY_BY_ID = {4624: "info", 4625: "medium", 4688: "info",
                  4768: "info", 4769: "info", 4770: "info",
                  4771: "medium", 4776: "info"}
SCORE_BY_ID = {4624: 0.2, 4625: 0.5, 4688: 0.2, 4768: 0.2, 4769: 0.2,
               4770: 0.2, 4771: 0.5, 4776: 0.2}
KIND_BY_ID = {PROCESS_ID: "process"}

_PS_TEMPLATE = r"""
$ErrorActionPreference = 'Stop'
$since = (Get-Date).AddMinutes(-{since_minutes})
try {{
  $ev = Get-WinEvent -FilterHashtable @{{ LogName='Security'; Id={ids}; StartTime=$since }} -MaxEvents {max_events} -ErrorAction Stop
}} catch {{
  [pscustomobject]@{{ events = @(); error = $_.Exception.Message }} |
    ConvertTo-Json -Depth 4 -Compress
  exit 0
}}
$rows = @()
foreach ($e in $ev) {{
  $x = [xml]$e.ToXml(); $d = @{{}}
  foreach ($p in $x.Event.EventData.Data) {{ if ($p.Name) {{ $d[$p.Name] = $p.'#text' }} }}
  $rows += [pscustomobject]@{{
    ts = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    event_id = $e.Id
    user = if ($e.Id -eq 4688) {{ $d['SubjectUserName'] }} elseif ($d['TargetUserName']) {{ $d['TargetUserName'] }} else {{ $d['SubjectUserName'] }}
    domain = if ($e.Id -eq 4688) {{ $d['SubjectDomainName'] }} elseif ($d['TargetDomainName']) {{ $d['TargetDomainName'] }} else {{ $d['SubjectDomainName'] }}
    logonType = $d['LogonType']
    workstation = if ($d['WorkstationName']) {{ $d['WorkstationName'] }} else {{ $d['Workstation'] }}
    source_ip = $d['IpAddress']
    process = $d['NewProcessName']
    pid = if ($d['NewProcessId']) {{ $d['NewProcessId'] }} else {{ $d['ProcessId'] }}
    parent = $d['ParentProcessName']
    cmdline = $d['CommandLine']
    service = $d['ServiceName']
    status = $d['Status']
    package = $d['PackageName']
  }}
}}
[pscustomobject]@{{ events = @($rows); error = $null }} |
  ConvertTo-Json -Depth 4 -Compress
"""


def parse_ids(value) -> tuple[int, ...]:
    """Validate an operator-supplied event-id list against the allowlist."""
    if value in (None, ""):
        return DEFAULT_IDS
    if isinstance(value, (list, tuple, set)):
        raw = list(value)
    else:
        raw = str(value).split(",")
    ids = []
    for item in raw:
        text = str(item).strip()
        if not text:
            continue
        if not text.isdigit():
            raise ValueError(f"event id {item!r} is not numeric")
        eid = int(text)
        if eid not in SUPPORTED_IDS:
            raise ValueError(f"event id {eid} is not supported")
        if eid not in ids:
            ids.append(eid)
    if not ids:
        raise ValueError("no event ids requested")
    return tuple(ids)


def _run_ps(since_minutes: int, ids=DEFAULT_IDS,
            max_events: int = MAX_EVENTS) -> dict:
    exe = shutil.which("powershell.exe") or shutil.which("pwsh")
    if not exe:
        return {"error": "powershell not available on this host"}
    payload = _PS_TEMPLATE.format(
        since_minutes=int(since_minutes),
        ids=",".join(str(int(i)) for i in ids),
        max_events=int(max_events))
    try:
        proc = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", payload],
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, check=False)
    except subprocess.TimeoutExpired:
        return {"error": "identity collector timeout"}
    text = (proc.stdout or "").strip()
    if not text:
        detail = (proc.stderr or "").strip()[-500:]
        return {"error": "identity collector produced no output"
                         + (f": {detail}" if detail else ""),
                "rc": proc.returncode}
    try:
        payload = json.loads(text.splitlines()[-1])
    except json.JSONDecodeError:
        return {"error": "identity collector did not emit JSON",
                "rc": proc.returncode}
    if isinstance(payload, dict) and "events" in payload:
        if payload.get("error"):
            return {"error": str(payload["error"])[:500],
                    "rc": proc.returncode}
        rows = payload.get("events") or []
    elif isinstance(payload, dict):      # single row (older collector)
        rows = [payload]
    elif isinstance(payload, list):
        rows = payload
    else:
        return {"error": "identity collector returned an unexpected shape",
                "rc": proc.returncode}
    if proc.returncode not in (0, None):
        return {"error": f"identity collector exited {proc.returncode}",
                "rc": proc.returncode}
    return {"events": rows}


def _clip(value, limit):
    if value is None:
        return None
    text = str(value)
    return text[:limit] if len(text) > limit else text


def _base_name(path):
    if path is None:
        return None
    return str(path).replace("\\", "/").rsplit("/", 1)[-1]


def _status_ok(row: dict) -> bool:
    return str(row.get("status") or "0x0").strip().lower() in STATUS_SUCCESS


def _auth_description(eid: int, row: dict, source_ip) -> str:
    if eid in LOGON_IDS:
        return (f"logon {'success' if eid == 4624 else 'FAILED'} "
                f"type={row.get('logonType')} from={source_ip or 'local'} "
                f"workstation={row.get('workstation')}")
    if eid == 4768:
        return (f"Kerberos TGT {'success' if _status_ok(row) else 'FAILED'} "
                f"from={source_ip or 'local'} status={row.get('status') or '0x0'}")
    if eid == 4769:
        return (f"Kerberos service ticket {'success' if _status_ok(row) else 'FAILED'} "
                f"service={row.get('service')} from={source_ip or 'local'} "
                f"status={row.get('status') or '0x0'}")
    if eid == 4770:
        return (f"Kerberos service ticket renewed service={row.get('service')} "
                f"from={source_ip or 'local'}")
    if eid == 4771:
        return (f"Kerberos pre-auth {'success' if _status_ok(row) else 'FAILED'} "
                f"from={source_ip or 'local'} status={row.get('status') or '0x0'}")
    if eid == NTLM_ID:
        return (f"NTLM credential validation "
                f"{'success' if _status_ok(row) else 'FAILED'} "
                f"workstation={row.get('workstation')} package={row.get('package')} "
                f"status={row.get('status') or '0x0'}")
    return f"security event {eid}"


def normalize_logon(row: dict, host: str) -> dict:
    """One Security auth record -> strict PlasmaEvent dict (kind=auth)."""
    eid = int(row.get("event_id") or 0)
    domain, user = row.get("domain"), row.get("user")
    # TargetDomainName is "-" for several local-logon shapes; treating it as
    # a real domain produced "-\\Administrator" and broke user joins.
    if str(domain or "").strip() in ("", "-"):
        domain = None
    # Kerberos puts a realm-qualified UPN in TargetUserName; prefixing a
    # domain would produce "CORP.LOCAL\\olu@CORP.LOCAL" and break user joins.
    already_qualified = "@" in str(user or "") or "\\" in str(user or "")
    full_user = (user if already_qualified else
                 f"{domain}\\{user}" if domain and user and
                 str(user).lower() not in ("-", "") else user)
    # Machine accounts are noise; Kerberos may suffix the account with a
    # realm, so test the account part before "@".
    account = str(full_user or "").split("@", 1)[0]
    if account.endswith("$") or str(user or "").lower() in ("-", ""):
        full_user = None
    source_ip = row.get("source_ip")
    if source_ip in ("-", "", "::1", "127.0.0.1", "0.0.0.0", None):
        source_ip = None
    # 4776 puts the calling machine in Workstation, not IpAddress.
    if eid == NTLM_ID and not source_ip:
        workstation = str(row.get("workstation") or "").strip()
        source_ip = workstation if workstation not in ("", "-") else None
    ts = str(row.get("ts") or "").strip()
    if not ts:
        raise ValueError("logon record has no timestamp")
    failed = (eid in (4625, 4771, NTLM_ID) and not _status_ok(row)) or eid == 4625
    severity = "medium" if failed else SEVERITY_BY_ID.get(eid, "info")
    event = {
        "ts": ts,
        "host": host,
        "source": "plasma",
        "kind": "auth",
        "event_id": max(eid, 1),
        "severity": severity,
        "score": 0.5 if failed else SCORE_BY_ID.get(eid, 0.2),
        "action": "logged",
        "user": _clip(full_user, 128),
        "process": _clip(_base_name(row.get("process")), 260),
        "pid": int(row["pid"]) if str(row.get("pid") or "").isdigit() and
               int(row["pid"]) <= 2_147_483_647 else None,
        "dest_ip": _clip(source_ip, 45),
        "description": _clip(_auth_description(eid, row, source_ip), 512),
    }
    return {k: v for k, v in event.items() if v is not None}


def normalize_process(row: dict, host: str) -> dict:
    """One Security 4688 record -> process event with lineage (kind=process).

    4688 carries the creator subject, parent image and (when the audit
    policy enables it) the command line. That is the lineage edge Plasma
    otherwise only gets from Sysmon EID 1, which is not stored for every
    process — only when a rule fires.
    """
    eid = int(row.get("event_id") or PROCESS_ID)
    domain, user = row.get("domain"), row.get("user")
    if str(domain or "").strip() in ("", "-"):
        domain = None
    already_qualified = "@" in str(user or "") or "\\" in str(user or "")
    full_user = (user if already_qualified else
                 f"{domain}\\{user}" if domain and user and
                 str(user).lower() not in ("-", "") else user)
    account = str(full_user or "").split("@", 1)[0]
    if account.endswith("$") or str(user or "").lower() in ("-", ""):
        full_user = None
    image = row.get("process")
    parent = row.get("parent")
    cmdline = row.get("cmdline")
    if cmdline:
        from .redact import redact_text
        cmdline = redact_text(str(cmdline))
    ts = str(row.get("ts") or "").strip()
    if not ts:
        raise ValueError("process record has no timestamp")
    event = {
        "ts": ts,
        "host": host,
        "source": "plasma",
        "kind": "process",
        "event_id": max(eid, 1),
        "severity": "info",
        "score": 0.2,
        "action": "logged",
        "user": _clip(full_user, 128),
        "process": _clip(_base_name(image), 260),
        "pid": int(row["pid"]) if str(row.get("pid") or "").isdigit() and
               int(row["pid"]) <= 2_147_483_647 else None,
        "parent": _clip(_base_name(parent), 260),
        "image": _clip(image, 512),
        "cmdline": _clip(cmdline, 2048),
        "description": _clip(
            f"process created by {full_user or 'unknown'} "
            f"parent={_base_name(parent) or 'unknown'} "
            f"image={_base_name(image) or 'unknown'}", 512),
    }
    return {k: v for k, v in event.items() if v is not None}


def normalize_event(row: dict, host: str) -> dict:
    """Dispatch one Security record onto its event kind."""
    eid = int(row.get("event_id") or 0)
    if eid == PROCESS_ID:
        return normalize_process(row, host)
    return normalize_logon(row, host)


def pull(events_path, host: str, since_minutes: int = 15,
         ids=DEFAULT_IDS, max_events: int = MAX_EVENTS) -> dict:
    """Read recent identity events from the Security channel into the store."""
    # Bound an operator-supplied window: a year of Security log is not a
    # bounded read, and Get-WinEvent would churn for minutes.
    since_minutes = max(1, min(int(since_minutes), 10080))
    max_events = max(1, min(int(max_events), 50000))
    try:
        ids = parse_ids(ids)
    except ValueError as exc:
        return {"error": str(exc), "written": 0}
    result = _run_ps(since_minutes, ids=ids, max_events=max_events)
    if "error" in result:
        result.setdefault("written", 0)
        return result
    rows = result["events"]

    from pathlib import Path
    events = Path(events_path)

    existing = set()
    if events.exists():
        for ln in events.read_text(encoding="utf-8-sig", errors="replace").splitlines():
            if ln.strip():
                try:
                    existing.add(hashlib.sha256(
                        json.dumps(json.loads(ln), ensure_ascii=False,
                                   sort_keys=True).encode()).hexdigest())
                except json.JSONDecodeError:
                    continue

    written = 0
    by_id: dict[str, int] = {}
    events.parent.mkdir(parents=True, exist_ok=True)
    agentstate.ensure_trailing_newline(events)
    with events.open("a", encoding="utf-8") as out:
        for row in rows:
            try:
                event = normalize_event(row, host=host)
                payload = json.dumps(event, ensure_ascii=False, sort_keys=True)
            except (TypeError, ValueError):
                continue
            digest = hashlib.sha256(payload.encode()).hexdigest()
            if digest in existing:
                continue
            out.write(payload + "\n")
            existing.add(digest)
            written += 1
            key = str(event["event_id"])
            by_id[key] = by_id.get(key, 0) + 1
    # `logons_seen` is kept for existing callers; `events_seen` is the
    # accurate name now that the collector covers more than logons.
    return {"since_minutes": since_minutes, "ids": list(ids),
            "events_seen": len(rows), "logons_seen": len(rows),
            "written": written, "written_by_id": dict(sorted(by_id.items())),
            "store": str(events)}


def _ps_task(script: str, timeout: int = 120) -> tuple[int, str]:
    exe = shutil.which("powershell.exe") or shutil.which("pwsh")
    if not exe:
        return 1, "powershell not available"
    try:
        proc = subprocess.run([exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)[:200]
    return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()


def _canonical_exe(root) -> str | None:
    bin_dir = Path(root) / "bin"
    candidates = sorted(bin_dir.glob("plasma-*.exe"),
                        key=lambda p: p.stat().st_mtime, reverse=True)
    return str(candidates[0]) if candidates else None


def _q(value) -> str:
    return str(value).replace("'", "''")


def schedule(root, every_minutes: int = 15, exe=None) -> dict:
    """Register a SYSTEM task that pulls logons on a cadence.

    Authentication is the one thing a HIDS should watch continuously; leaving
    4624/4625 behind an operator command made brute force a scheduled-scan
    finding. The task runs the same bounded pull `watch` would otherwise
    require a human to run.
    """
    minutes = max(1, min(int(every_minutes), 1440))
    root = Path(root)
    exe = exe or _canonical_exe(root)
    if not exe:
        return {"ok": False, "task": TASK_NAME,
                "error": "no Plasma executable under <root>/bin; "
                         "pass --exe with the installed plasma.exe"}
    if not str(exe).lower().endswith(".exe"):
        return {"ok": False, "task": TASK_NAME,
                "error": f"task executable is not a Windows .exe: {exe}"}
    events = root / "data" / "events.jsonl"
    argument = f'identity pull --events "{events}" --since {minutes}'
    script = (
        f"$a = New-ScheduledTaskAction -Execute '{_q(exe)}' "
        f"-Argument '{_q(argument)}'; "
        f"$t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) "
        f"-RepetitionInterval (New-TimeSpan -Minutes {minutes}) "
        f"-RepetitionDuration (New-TimeSpan -Days 3650); "
        f"$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' "
        f"-LogonType ServiceAccount -RunLevel Highest; "
        f"Register-ScheduledTask -TaskName '{TASK_NAME}' -Action $a "
        f"-Trigger $t -Principal $p -Force | Out-Null"
    )
    rc, out = _ps_task(script)
    return {"ok": rc == 0, "task": TASK_NAME, "every_minutes": minutes,
            "exe": str(exe), "events": str(events), "detail": out[:200]}


def unschedule() -> dict:
    rc, out = _ps_task(
        f"Unregister-ScheduledTask -TaskName '{TASK_NAME}' -Confirm:$false")
    return {"ok": rc == 0, "task": TASK_NAME, "detail": out[:200]}


def schedule_status() -> dict:
    script = (
        f"$t = Get-ScheduledTask -TaskName '{TASK_NAME}' -ErrorAction SilentlyContinue; "
        f"if(-not $t){{ '{{\"installed\":false}}' }} else {{ "
        f"$i = Get-ScheduledTaskInfo -TaskName '{TASK_NAME}'; "
        f"[pscustomobject]@{{installed=$true; state=[string]$t.State; "
        f"last_run=[string]$i.LastRunTime; last_result=$i.LastTaskResult; "
        f"next_run=[string]$i.NextRunTime}} | ConvertTo-Json -Compress }}"
    )
    rc, out = _ps_task(script, timeout=60)
    if rc != 0:
        return {"installed": None, "error": out[:200]}
    try:
        return json.loads(out.splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return {"installed": None, "error": out[:200]}
