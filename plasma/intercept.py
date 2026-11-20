"""Plasma intercept: deterministic policy at Windows' native gates.

An interceptor is not another sensor. It sees an action at the boundary and
can allow, deny, or record a would-be denial. Plasma does not ship a kernel
driver; this module brokers typed rules into enforcement points Windows
already owns:

* ``acl``      — NTFS deny + failure audit on canary files.
* ``firewall`` — Windows Firewall outbound block for a destination.
* ``gateway``  — synchronous MCP tool-call policy.
* ``audit``    — shadow evaluation over the event store (Phase 0).

Every apply is dry-run first, plan-gated, journaled and reversible. The
model may propose rules; only the plan/approval path can apply them.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import time
from pathlib import Path

from . import agentstate, killswitch

RULES_FILE = "intercept-rules.json"
JOURNAL_FILE = "intercept-journal.jsonl"
BACKUP_DIR = "intercept-backups"

POINTS = frozenset({
    "file_write", "file_delete", "file_read", "process_exec",
    "network_connect", "dns_query", "credential_access", "agent_tool_call",
})
ACTIONS = frozenset({"audit", "allow", "deny", "require_approval"})
BACKENDS = frozenset({"auto", "acl", "firewall", "gateway"})
MODES = frozenset({"shadow", "enforce"})
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_ACTION_RANK = {"deny": 3, "require_approval": 2, "allow": 1, "audit": 0}
_MATCH_KEYS = frozenset({
    "path_prefix", "process", "user", "host", "dest_ip", "dest_port",
    "technique", "event_id", "tool", "tenant",
})


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _rules_path(root) -> Path:
    return Path(root) / RULES_FILE


def _journal_path(root) -> Path:
    return Path(root) / JOURNAL_FILE


def _load_rules(root) -> list[dict]:
    path = _rules_path(root)
    if not path.exists():
        return []
    try:
        blob = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"intercept rule registry unreadable: {exc}") from exc
    rules = blob.get("rules") if isinstance(blob, dict) else None
    if not isinstance(rules, list):
        raise ValueError("intercept rule registry has no 'rules' array")  # noqa: TRY004
    return [_normalize_rule(r) for r in rules]


def _save_rules(root, rules: list[dict]) -> None:
    agentstate.write_json(_rules_path(root), {"rules": rules})


def _normalize_rule(rule) -> dict:
    if not isinstance(rule, dict):
        raise ValueError("a rule must be an object")  # noqa: TRY004
    rule_id = str(rule.get("id") or "").strip()
    if not _ID_RE.match(rule_id):
        raise ValueError(f"invalid rule id: {rule_id!r}")
    point = str(rule.get("point") or "").strip().lower()
    if point not in POINTS:
        raise ValueError(f"invalid point: {point!r}")
    action = str(rule.get("action") or "audit").strip().lower()
    if action not in ACTIONS:
        raise ValueError(f"invalid action: {action!r}")
    backend = str(rule.get("backend") or "auto").strip().lower()
    if backend not in BACKENDS:
        raise ValueError(f"invalid backend: {backend!r}")
    mode = str(rule.get("mode") or "shadow").strip().lower()
    if mode not in MODES:
        raise ValueError(f"invalid mode: {mode!r}")
    match = rule.get("match") or {}
    if not isinstance(match, dict):
        raise ValueError("rule match must be an object")  # noqa: TRY004
    clean_match = {}
    for key, value in match.items():
        key = str(key)
        if key not in _MATCH_KEYS:
            raise ValueError(f"unsupported match field: {key!r}")
        if key == "dest_port" or key == "event_id":
            try:
                clean_match[key] = int(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{key} must be an integer") from exc
        elif key == "path_prefix":
            text = str(value).strip()
            if not text or len(text) > 4096:
                raise ValueError("path_prefix must be 1..4096 characters")
            clean_match[key] = text
        else:
            text = str(value).strip()
            if not text or len(text) > 260:
                raise ValueError(f"{key} must be 1..260 characters")
            clean_match[key] = text
    try:
        priority = int(rule.get("priority", 0))
    except (TypeError, ValueError) as exc:
        raise ValueError("priority must be an integer") from exc
    try:
        ttl = int(rule.get("ttl_seconds", 0))
    except (TypeError, ValueError) as exc:
        raise ValueError("ttl_seconds must be an integer") from exc
    if not 0 <= ttl <= 30 * 24 * 3600:
        raise ValueError("ttl_seconds must be 0..2592000")
    reason = str(rule.get("reason") or "")[:300]
    return {
        "id": rule_id, "point": point, "action": action, "backend": backend,
        "mode": mode, "match": clean_match, "priority": priority,
        "ttl_seconds": ttl, "reason": reason,
    }


def add_rule(root, rule) -> dict:
    normalized = _normalize_rule(rule)
    rules = _load_rules(root)
    if any(r["id"] == normalized["id"] for r in rules):
        raise ValueError(f"rule {normalized['id']} already exists")
    rules.append(normalized)
    _save_rules(root, rules)
    return normalized


def remove_rule(root, rule_id: str) -> dict:
    rules = _load_rules(root)
    keep = [r for r in rules if r["id"] != rule_id]
    if len(keep) == len(rules):
        return {"error": f"no rule {rule_id}"}
    _save_rules(root, keep)
    return {"removed": rule_id, "remaining": len(keep)}


def list_rules(root) -> dict:
    rules = _load_rules(root)
    return {"count": len(rules), "rules": rules}


# ---------------------------------------------------------------------------
# Shadow evaluation
# ---------------------------------------------------------------------------

def event_point(event: dict) -> str | None:
    kind = str(event.get("kind") or "").lower()
    eid = event.get("event_id")
    technique = str(event.get("technique") or "").upper()
    if kind == "process":
        return "process_exec"
    if kind == "network":
        return "network_connect"
    if kind == "dns":
        return "dns_query"
    if kind == "file":
        if str(eid) in ("23", "26"):
            return "file_delete"
        return "file_write"
    if kind == "alert":
        if technique.startswith("T1003") or str(eid) == "10":
            return "credential_access"
        if event.get("file_path"):
            return "file_write"
    return None


def _base_name(value) -> str:
    return str(value or "").replace("\\", "/").rsplit("/", 1)[-1].lower()


def _matches(rule: dict, event: dict) -> bool:
    for key, expected in (rule.get("match") or {}).items():
        value = event.get("file_path") if key == "path_prefix" else event.get(key)
        if key == "path_prefix":
            if not value or not str(value).lower().startswith(str(expected).lower()):
                return False
        elif key == "process":
            if _base_name(value) != _base_name(expected):
                return False
        elif key in ("dest_port", "event_id"):
            try:
                if int(value) != int(expected):
                    return False
            except (TypeError, ValueError):
                return False
        elif key == "dest_ip":
            if str(value or "").lower() != str(expected).lower():
                return False
        else:
            if str(value or "").strip().lower() != str(expected).strip().lower():
                return False
    return True


def decide(rules: list[dict], event: dict) -> dict:
    point = event.get("point") or event_point(event)
    candidates = [r for r in rules
                  if r["point"] == point and _matches(r, event)]
    if not candidates:
        return {"allowed": True, "action": "allow", "rule": None,
                "point": point, "reason": "no matching intercept rule",
                "would_block": False, "shadow": False,
                "approval_required": False}
    winner = max(candidates,
                 key=lambda r: (int(r.get("priority", 0)),
                                _ACTION_RANK.get(r["action"], 0)))
    action = winner["action"]
    shadow = winner.get("mode") == "shadow"
    would_block = action in ("deny", "require_approval")
    allowed = action not in ("deny", "require_approval") or shadow
    return {
        "allowed": allowed,
        "action": action,
        "rule": winner.get("id"),
        "point": point,
        "reason": winner.get("reason") or f"rule {winner.get('id')}",
        "would_block": would_block,
        "shadow": shadow,
        "approval_required": action == "require_approval" and not shadow,
    }


def _tail_rows(path, max_rows: int = 5000, max_bytes: int = 4 << 20):
    path = Path(path)
    if not path.exists():
        return []
    try:
        size = path.stat().st_size
        start = max(0, size - max_bytes)
        with path.open("rb") as fh:
            fh.seek(start)
            blob = fh.read()
        if start:
            cut = blob.find(b"\n")
            blob = blob[cut + 1:] if cut >= 0 else b""
        rows = []
        for line in blob.splitlines()[-max_rows:]:
            if not line.strip():
                continue
            try:
                row = json.loads(line.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
        return rows
    except OSError:
        return []


def evaluate_store(events_path, rules=None, max_rows: int = 5000) -> dict:
    rules = rules if rules is not None else []
    rules = [_normalize_rule(r) for r in rules]
    rows = _tail_rows(events_path, max_rows)
    decisions = []
    would_block = 0
    for row in rows:
        decision = decide(rules, row)
        if decision["rule"]:
            would_block += 1 if decision["would_block"] else 0
            decisions.append({
                "ts": row.get("ts"), "host": row.get("host"),
                "kind": row.get("kind"), "event_id": row.get("event_id"),
                "process": row.get("process"), "file_path": row.get("file_path"),
                "dest_ip": row.get("dest_ip"), "dns_query": row.get("dns_query"),
                **decision,
            })
    return {"checked": len(rows), "matched": len(decisions),
            "would_block": would_block, "decisions": decisions[-500:]}


def evaluate_agent_call(root, tool: str, args: dict, context: dict) -> dict:
    """Synchronous policy for the MCP tool-call boundary.

    A corrupt registry fails closed: an agent must not silently bypass a
    broken interception policy.
    """
    root = agentstate.base(root)
    try:
        rules = _load_rules(root)
    except ValueError as exc:
        return {"allowed": False, "action": "deny", "rule": None,
                "point": "agent_tool_call",
                "reason": f"intercept registry unreadable: {exc}",
                "would_block": True, "shadow": False,
                "approval_required": False}
    event = {
        "point": "agent_tool_call", "tool": tool,
        "host": context.get("host"), "tenant": context.get("tenant"),
        "user": context.get("agent"),
    }
    return decide(rules, event)


# ---------------------------------------------------------------------------
# Journal and plan gate
# ---------------------------------------------------------------------------

def _read_journal(root) -> list[dict]:
    path = _journal_path(root)
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


def _append_journal(root, entry: dict) -> dict:
    path = _journal_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with agentstate.lock(path.parent / ".intercept-journal.lock", stale=300):
        rows = _read_journal(root)
        entry["id"] = max((int(r.get("id") or 0) for r in rows), default=0) + 1
        entry.setdefault("ts", _now())
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def _check_plan(root, plan, control, digest):
    if plan is None:
        return {"error": "--apply requires --plan <id> from a prior dry-run"}
    try:
        plan_id = int(plan)
    except (TypeError, ValueError):
        return {"error": "--plan must be an integer"}
    rows = _read_journal(root)
    dry = next((r for r in rows if int(r.get("id") or 0) == plan_id), None)
    if dry is None:
        return {"error": f"--plan {plan_id}: no such journal entry"}
    if dry.get("control") != control or dry.get("status") != "dry-run":
        return {"error": f"--plan {plan_id} is not a dry-run of '{control}'"}
    if dry.get("payload_sha256") != digest:
        return {"error": f"--plan {plan_id} rendered a different payload; "
                         "re-run the dry-run"}
    if any(r.get("plan") == plan_id and r.get("status") == "applied"
           for r in rows):
        return {"error": f"--plan {plan_id} has already been used"}
    return {"ok": True}


def _claim_plan(root, plan, control, digest) -> dict:
    with agentstate.lock(_journal_path(root).parent / ".intercept-plan.lock",
                         stale=300):
        error = _check_plan(root, plan, control, digest)
        if "error" in error:
            return error
        return _append_journal(root, {
            "control": control, "status": "claimed", "plan": plan,
            "payload_sha256": digest, "ts": _now(),
        })


def _ps(script: str, timeout: int = 120) -> tuple[int, str]:
    exe = shutil.which("powershell.exe") or shutil.which("pwsh")
    if not exe:
        return 1, "powershell not available"
    try:
        proc = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
             "Bypass", "-Command", script],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)[:200]
    return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()


def _parse_json(rc, out):
    if rc != 0:
        return None, out[:300]
    try:
        return json.loads(out.splitlines()[-1]), None
    except (json.JSONDecodeError, IndexError):
        return None, out[:300]


def _q(value) -> str:
    return "'" + str(value).replace("'", "''") + "'"


# ---------------------------------------------------------------------------
# ACL backend: canary protection
# ---------------------------------------------------------------------------

_ACL_APPLY = r"""
$ErrorActionPreference='Stop'
$paths=@(__PATHS__)
$rights=[System.Security.AccessControl.FileSystemRights]::Write -bor `
        [System.Security.AccessControl.FileSystemRights]::Delete
$out=@()
foreach($p in $paths){
  try{
    if(-not (Test-Path -LiteralPath $p)){
      $out += [pscustomobject]@{path=$p; ok=$false; error='missing'}
      continue
    }
    $acl=Get-Acl -LiteralPath $p
    $before=$acl.Sddl
    $deny=New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList 'Everyone',$rights,'Deny'
    $audit=New-Object System.Security.AccessControl.FileSystemAuditRule -ArgumentList 'Everyone',$rights,'Failure'
    $acl.AddAccessRule($deny)
    $acl.AddAuditRule($audit)
    $audit_ok=$true
    try{
      Set-Acl -LiteralPath $p -AclObject $acl
    }catch{
      # A normal Administrator token can write the DACL but may not hold
      # SeSecurityPrivilege for the SACL. Deny protection must still work.
      if($_.Exception.Message -match 'SeSecurityPrivilege'){
        [void]$acl.RemoveAuditRule($audit)
        $audit_ok=$false
        Set-Acl -LiteralPath $p -AclObject $acl
      }else{ throw }
    }
    $after=(Get-Acl -LiteralPath $p).Sddl
    $out += [pscustomobject]@{path=$p; ok=$true; before=$before; after=$after; audit=$audit_ok}
  }catch{
    $out += [pscustomobject]@{path=$p; ok=$false; error=$_.Exception.Message}
  }
}
@($out) | ConvertTo-Json -Depth 4 -Compress
"""

_ACL_RESTORE = r"""
$ErrorActionPreference='Stop'
$items=ConvertFrom-Json __ITEMS__
$out=@()
foreach($i in $items){
  try{
    $p=$i.path
    $sddl=$i.sddl
    if(-not (Test-Path -LiteralPath $p)){
      $out += [pscustomobject]@{path=$p; ok=$false; error='missing'}
      continue
    }
    $sec=New-Object System.Security.AccessControl.FileSecurity
    $sec.SetSecurityDescriptorSddlForm($sddl)
    Set-Acl -LiteralPath $p -AclObject $sec
    $out += [pscustomobject]@{path=$p; ok=$true}
  }catch{
    $out += [pscustomobject]@{path=$p; ok=$false; error=$_.Exception.Message}
  }
}
@($out) | ConvertTo-Json -Depth 4 -Compress
"""


def canary_paths(root, prefix=None) -> list[str]:
    manifest = Path(root) / "canaries.json"
    try:
        blob = json.loads(manifest.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"canary manifest unreadable: {exc}") from exc
    paths = []
    for entry in blob.get("canaries", []):
        path = str(entry.get("path") or "")
        if not path:
            continue
        if prefix and not path.lower().startswith(str(prefix).lower()):
            continue
        paths.append(path)
    if not paths:
        raise ValueError("no canary paths matched")
    return paths


def _acl_apply_payload(paths) -> str:
    return _ACL_APPLY.replace("__PATHS__", ",".join(_q(p) for p in paths))


def _acl_restore_payload(items) -> str:
    obj = json.dumps(items, ensure_ascii=False)
    return _ACL_RESTORE.replace("__ITEMS__", _q(obj))


def protect_canary(root, apply=False, plan=None, reason=None,
                   prefix=None) -> dict:
    root = Path(root)
    paths = canary_paths(root, prefix)
    payload = _acl_apply_payload(paths)
    digest = hashlib.sha256(payload.encode()).hexdigest()
    if not apply:
        return _append_journal(root, {
            "control": "canary_acl", "status": "dry-run",
            "payload_sha256": digest, "reason": reason,
            "paths": paths, "preview": payload[:4000],
        })
    if killswitch.blocked(root, host=__import__("socket").gethostname(),
                          risk="high"):
        return {"error": "kill switch is engaged for this host — ACL "
                         "protection is blocked", "code": "KILLSWITCH"}
    claimed = _claim_plan(root, plan, "canary_acl", digest)
    if "error" in claimed:
        return claimed
    rc, out = _ps(payload, timeout=180)
    result, err = _parse_json(rc, out)
    if result is None:
        return {"error": "canary ACL apply failed", "detail": err,
                "code": "FAILED", "plan": claimed.get("id")}
    rows = result if isinstance(result, list) else [result]
    ok = [r for r in rows if r.get("ok")]
    failed = [r for r in rows if not r.get("ok")]
    undo = {"kind": "acl",
            "items": [{"path": r["path"], "sddl": r["before"]}
                      for r in ok if r.get("before")]}
    entry = _append_journal(root, {
        "control": "canary_acl", "status": "applied" if not failed else "partial",
        "payload_sha256": digest, "reason": reason, "plan": plan,
        "verification": {"ok": len(ok), "failed": failed},
        "undo": undo, "paths": paths,
    })
    if failed:
        return {"error": "some canary ACLs failed", "failed": failed,
                "applied": len(ok), "plan": claimed.get("id"),
                "journal": entry.get("id"), "code": "PARTIAL"}
    return entry


# ---------------------------------------------------------------------------
# Firewall backend
# ---------------------------------------------------------------------------

def _validate_ip(value) -> str:
    text = str(value or "").strip()
    if not _IPV4.match(text):
        raise ValueError(f"not an IPv4 address: {text!r}")
    octets = [int(o) for o in text.split(".")]
    if any(o > 255 for o in octets) or octets[0] in (0, 127) or \
            text == "255.255.255.255":
        raise ValueError(f"refusing loopback/unspecified address: {text!r}")
    return text


def _firewall_apply_payload(rule_id: str, ip: str) -> str:
    name = f"PlasmaIntercept-{rule_id}"
    return (
        "$ErrorActionPreference='Stop'\n"
        f"$n={_q(name)}\n"
        f"New-NetFirewallRule -DisplayName $n -Direction Outbound -Action Block "
        f"-RemoteAddress {_q(ip)} -Profile Any -ErrorAction Stop | Out-Null\n"
        f"$r=Get-NetFirewallRule -DisplayName $n -ErrorAction Stop\n"
        "[pscustomobject]@{applied=$true; name=$n; count=@($r).Count} "
        "| ConvertTo-Json -Compress"
    )


def _firewall_undo_payload(rule_id: str) -> str:
    name = f"PlasmaIntercept-{rule_id}"
    return (
        "$ErrorActionPreference='Stop'\n"
        f"Get-NetFirewallRule -DisplayName {_q(name)} -ErrorAction "
        "SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue\n"
        f"$left=@(Get-NetFirewallRule -DisplayName {_q(name)} -ErrorAction "
        "SilentlyContinue).Count\n"
        "[pscustomobject]@{removed=$true; remaining=$left} | ConvertTo-Json -Compress"
    )


def apply_rule(root, rule_id: str, apply=False, plan=None, reason=None) -> dict:
    root = Path(root)
    try:
        rules = _load_rules(root)
    except ValueError as exc:
        return {"error": str(exc), "code": "REFUSED"}
    rule = next((r for r in rules if r["id"] == rule_id), None)
    if rule is None:
        return {"error": f"no rule {rule_id}"}
    backend = rule["backend"]
    if backend == "auto":
        if rule["point"].startswith("file"):
            backend = "acl"
        elif rule["point"] == "network_connect":
            backend = "firewall"
        elif rule["point"] == "agent_tool_call":
            backend = "gateway"
        else:
            backend = None
    if backend is None:
        return {"error": f"no native backend for point {rule['point']!r}; "
                         "use `plasma prevent` for AppLocker/ASR controls",
                "code": "NO_BACKEND"}
    if backend == "gateway":
        return {"ok": True, "rule": rule_id, "backend": "gateway",
                "message": "gateway rules apply at the MCP boundary; "
                           "no host mutation is required"}
    if backend == "acl":
        prefix = rule["match"].get("path_prefix")
        return protect_canary(root, apply=apply, plan=plan,
                              reason=reason or rule.get("reason"),
                              prefix=prefix)
    if backend == "firewall":
        try:
            ip = _validate_ip(rule["match"].get("dest_ip"))
        except ValueError as exc:
            return {"error": str(exc), "code": "REFUSED"}
        payload = _firewall_apply_payload(rule_id, ip)
        digest = hashlib.sha256(payload.encode()).hexdigest()
        if not apply:
            return _append_journal(root, {
                "control": "firewall", "status": "dry-run",
                "rule": rule_id, "payload_sha256": digest, "reason": reason,
                "undo": {"kind": "firewall", "rule": rule_id},
                "preview": payload[:4000],
            })
        if killswitch.blocked(root, host=__import__("socket").gethostname(),
                              risk="high"):
            return {"error": "kill switch is engaged for this host — firewall "
                             "intercept is blocked", "code": "KILLSWITCH"}
        claimed = _claim_plan(root, plan, "firewall", digest)
        if "error" in claimed:
            return claimed
        rc, out = _ps(payload, timeout=120)
        result, err = _parse_json(rc, out)
        if result is None:
            return {"error": "firewall intercept apply failed", "detail": err,
                    "code": "FAILED"}
        return _append_journal(root, {
            "control": "firewall", "status": "applied", "rule": rule_id,
            "payload_sha256": digest, "reason": reason, "plan": plan,
            "verification": result, "undo": {"kind": "firewall", "rule": rule_id},
        })
    return {"error": f"backend {backend!r} is not an enforcing backend"}


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------

def rollback(root, entry_id: int, apply=False, plan=None, reason=None) -> dict:
    root = Path(root)
    rows = _read_journal(root)
    row = next((r for r in rows if int(r.get("id") or 0) == int(entry_id)), None)
    if row is None:
        return {"error": f"no intercept journal entry {entry_id}"}
    if row.get("status") not in ("applied", "partial"):
        return {"error": f"entry {entry_id} is {row.get('status')}, not applied"}
    undo = row.get("undo") or {}
    kind = undo.get("kind")
    if kind == "acl":
        items = undo.get("items") or []
        if not items:
            return {"error": "ACL undo has no saved SDDL"}
        payload = _acl_restore_payload(items)
        control = "rollback_acl"
    elif kind == "firewall":
        payload = _firewall_undo_payload(str(undo.get("rule") or ""))
        control = "rollback_firewall"
    else:
        return {"error": f"entry {entry_id} has no supported undo"}
    digest = hashlib.sha256(payload.encode()).hexdigest()
    if not apply:
        return _append_journal(root, {
            "control": control, "status": "dry-run", "target": entry_id,
            "payload_sha256": digest, "reason": reason,
            "preview": payload[:4000],
        })
    if killswitch.blocked(root, host=__import__("socket").gethostname(),
                          risk="high"):
        return {"error": "kill switch is engaged — rollback is blocked",
                "code": "KILLSWITCH"}
    claimed = _claim_plan(root, plan, control, digest)
    if "error" in claimed:
        return claimed
    rc, out = _ps(payload, timeout=180)
    result, err = _parse_json(rc, out)
    if result is None:
        return {"error": "intercept rollback failed", "detail": err,
                "code": "FAILED"}
    return _append_journal(root, {
        "control": control, "status": "applied", "target": entry_id,
        "payload_sha256": digest, "reason": reason, "plan": plan,
        "verification": result,
    })


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def status(root) -> dict:
    try:
        rules = _load_rules(root)
        rules_error = None
    except ValueError as exc:
        rules, rules_error = [], str(exc)
    rows = _read_journal(root)
    return {
        "rules": len(rules),
        "rules_error": rules_error,
        "by_point": {p: sum(1 for r in rules if r["point"] == p)
                     for p in sorted(POINTS)},
        "enforcing": sum(1 for r in rules if r["mode"] == "enforce"),
        "journal": {
            "total": len(rows),
            "dry_run": sum(1 for r in rows if r.get("status") == "dry-run"),
            "applied": sum(1 for r in rows if r.get("status") == "applied"),
            "partial": sum(1 for r in rows if r.get("status") == "partial"),
        },
        "registry": str(_rules_path(root)),
        "journal_path": str(_journal_path(root)),
    }
