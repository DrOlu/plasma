"""Plasma identity: logon events into the store via the Event Log API.

The ETW tap covers kernel-ish providers, but Security-channel audit events
(4624/4625) are written by LSA straight into the channel — they are not
re-emitted to realtime ETW sessions (proven on WS1: 75s window with live
4625 generation, events_seen=0). This collector therefore reads the
Security channel through the Event Log API (fixed, read-only PowerShell),
keeps only logon records, normalizes them onto the strict PlasmaEvent
contract (kind="auth", user=TargetUserName) and appends with dedupe.

Pull-based and on-demand like everything else in Plasma: run it when you
want identity events, never as a standing collector.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess

SEVERITY_BY_ID = {4624: "info", 4625: "medium"}
SCORE_BY_ID = {4624: 0.2, 4625: 0.5}

_PS_TEMPLATE = r"""
$ErrorActionPreference = 'SilentlyContinue'
$since = (Get-Date).AddMinutes(-{since_minutes})
$ev = Get-WinEvent -FilterHashtable @{{ LogName='Security'; Id=4624,4625; StartTime=$since }} -ErrorAction SilentlyContinue
$rows = @()
foreach ($e in $ev) {{
  $x = [xml]$e.ToXml(); $d = @{{}}
  foreach ($p in $x.Event.EventData.Data) {{ if ($p.Name) {{ $d[$p.Name] = $p.'#text' }} }}
  $rows += [pscustomobject]@{{
    ts = $e.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    event_id = $e.Id
    user = $d['TargetUserName']
    domain = $d['TargetDomainName']
    logonType = $d['LogonType']
    workstation = $d['WorkstationName']
    source_ip = $d['IpAddress']
    process = ($d['ProcessName'] -replace '^.*\\\\', '')
    pid = $d['ProcessId']
  }}
}}
$rows | ConvertTo-Json -Depth 4 -Compress
"""


def _run_ps(since_minutes: int) -> dict:
    exe = shutil.which("powershell.exe") or shutil.which("pwsh")
    if not exe:
        return {"error": "powershell not available on this host"}
    payload = _PS_TEMPLATE.format(since_minutes=int(since_minutes))
    try:
        proc = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", payload],
                              capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return {"error": "identity collector timeout"}
    text = (proc.stdout or "").strip()
    if not text:
        return {"events": []}
    try:
        rows = json.loads(text.splitlines()[-1])
    except json.JSONDecodeError:
        return {"error": "identity collector did not emit JSON"}
    if isinstance(rows, dict):      # single row
        rows = [rows]
    return {"events": rows}


def _clip(value, limit):
    if value is None:
        return None
    text = str(value)
    return text[:limit] if len(text) > limit else text


def normalize_logon(row: dict, host: str) -> dict:
    """One Security 4624/4625 record -> strict PlasmaEvent dict (kind=auth)."""
    eid = int(row.get("event_id") or 0)
    domain, user = row.get("domain"), row.get("user")
    full_user = f"{domain}\\{user}" if domain and user and \
        str(user).lower() not in ("-", "") else user
    if str(full_user or "").endswith("$") or str(user or "").lower() in ("-", ""):
        full_user = None                      # machine accounts are noise
    source_ip = row.get("source_ip")
    if source_ip in ("-", "", "::1", "127.0.0.1", None):
        source_ip = None
    event = {
        "ts": row.get("ts"),
        "host": host,
        "source": "plasma",
        "kind": "auth",
        "event_id": max(eid, 1),
        "severity": SEVERITY_BY_ID.get(eid, "info"),
        "score": SCORE_BY_ID.get(eid, 0.2),
        "action": "logged",
        "user": _clip(full_user, 128),
        "process": _clip(row.get("process"), 260),
        "pid": int(row["pid"]) if str(row.get("pid") or "").isdigit() and
               int(row["pid"]) <= 2_147_483_647 else None,
        "dest_ip": _clip(source_ip, 45),
        "description": _clip(
            f"logon {'success' if eid == 4624 else 'FAILED'} type={row.get('logonType')} "
            f"from={source_ip or 'local'} workstation={row.get('workstation')}", 512),
    }
    return {k: v for k, v in event.items() if v is not None}


def pull(events_path, host: str, since_minutes: int = 15) -> dict:
    """Read recent logons from the local Security channel into the store."""
    result = _run_ps(since_minutes)
    if "error" in result:
        result.setdefault("written", 0)
        return result
    rows = result["events"]

    from pathlib import Path
    events = Path(events_path)

    existing = set()
    if events.exists():
        for ln in events.read_text(encoding="utf-8", errors="replace").splitlines():
            if ln.strip():
                try:
                    existing.add(hashlib.sha256(
                        json.dumps(json.loads(ln), ensure_ascii=False,
                                   sort_keys=True).encode()).hexdigest())
                except json.JSONDecodeError:
                    continue

    written = 0
    events.parent.mkdir(parents=True, exist_ok=True)
    with events.open("a", encoding="utf-8") as out:
        for row in rows:
            try:
                event = normalize_logon(row, host=host)
                payload = json.dumps(event, ensure_ascii=False, sort_keys=True)
            except (TypeError, ValueError):
                continue
            digest = hashlib.sha256(payload.encode()).hexdigest()
            if digest in existing:
                continue
            out.write(payload + "\n")
            existing.add(digest)
            written += 1
    return {"since_minutes": since_minutes, "logons_seen": len(rows),
            "written": written, "store": str(events)}
