"""Plasma enforce: policy-gated automatic response (Tier 0 prevention).

Detection without a decision is just a log line. This module turns a watch
sweep into a bounded set of *proposed* actions, then — only when policy says
so — executes them through the existing actuate layer, which keeps its own
dry-run-first and plan-gating guarantees.

Prevention here means **containment at response speed**, not inline blocking:
the first execution has already happened. Inline blocking lives in
``plasma.prevent`` (Windows enforcement points) or a kernel driver (out of
scope).

Guardrails, all enforced in code and recorded in the journal:

* **Off by default.** ``enforcement.enabled`` must be true and the mode is
  ``dry-run`` unless an operator sets ``enforce``.
* **Allowlisted actions only.** A finding cannot choose an action that is
  not in the policy's allow/approval lists.
* **Approval gate.** High/critical actions become pending requests; they
  never execute until a human runs ``enforce approve``.
* **Blast radius.** Minimum score, per-run cap, per-action+target cooldown.
* **Kill switch.** Actuate's kill switch still blocks execution.
* **Everything journaled** with the finding digest and the decision reasons.
"""

from __future__ import annotations

import calendar
import hashlib
import json
import time
from pathlib import Path

from . import actuate, agentstate, killswitch

DEFAULT_POLICY = {
    "enabled": False,
    "mode": "dry-run",                       # dry-run | enforce
    "min_score": 9,
    # Containment is evidence-first: capture host state (snapshot is a
    # read-only export) before the irreversible action. An operator can
    # remove snapshot to choose speed over forensics, or move kill_process
    # into require_approval to make every kill human-gated.
    "allowed_actions": ["snapshot", "kill_process"],
    "require_approval": ["isolate_host", "quarantine_file", "disable_user",
                         "remove_admin", "stop_service", "rotate_credential",
                         "delete_task", "disable_task", "remove_run_key",
                         "disable_wmi_sub", "block_ip"],
    "cooldown_minutes": 30,
    "max_actions_per_run": 2,
    "deny_techniques": [],
    "allow_techniques": [],
}

RISK = {
    "kill_process": "medium",
    "block_ip": "high",
    "isolate_host": "critical",
    "quarantine_file": "high",
    "disable_user": "high",
    "remove_admin": "high",
    "stop_service": "high",
    "delete_task": "medium",
    "disable_task": "medium",
    "remove_run_key": "medium",
    "disable_wmi_sub": "medium",
    "rotate_credential": "critical",
    "snapshot": "low",
}

# Techniques where killing the accessing process is the proportionate
# containment. Injection is the case the DTrace/gene rules exist for.
KILL_TECHNIQUES = {
    "T1055", "T1055.001", "T1055.002", "T1055.003", "T1055.004",
    "T1055.005", "T1055.008", "T1055.009", "T1055.011", "T1055.012",
    "T1055.013", "T1055.014",
    # Credential access by a specific process is equally time-critical.
    "T1003", "T1003.001", "T1003.002",
    # Token theft/manipulation used as a privilege-escalation primitive.
    "T1134", "T1134.001", "T1134.002", "T1134.003",
}


def journal_path(root) -> Path:
    return Path(root) / "enforce-journal.jsonl"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _read_journal(root) -> list[dict]:
    path = journal_path(root)
    rows = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _append_journal(root, entry: dict) -> dict:
    path = journal_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with agentstate.lock(path.parent / ".enforce-journal.lock", stale=300):
        rows = _read_journal(root)
        entry["id"] = max((int(r.get("id") or 0) for r in rows), default=0) + 1
        entry.setdefault("ts", _now())
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def load_policy(root) -> dict:
    """Merge the config's enforcement block over the safe defaults."""
    policy = dict(DEFAULT_POLICY)
    config_path = Path(root) / "config.json"
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            config = {}
        block = (config.get("enforcement") or {}) if isinstance(config, dict) else {}
        if isinstance(block, dict):
            for key, value in block.items():
                if key in DEFAULT_POLICY and value is not None:
                    policy[key] = value
    policy["enabled"] = bool(policy.get("enabled"))
    policy["mode"] = "enforce" if str(policy.get("mode")) == "enforce" else "dry-run"
    try:
        policy["min_score"] = max(0, min(10, int(policy.get("min_score", 9))))
    except (TypeError, ValueError):
        policy["min_score"] = 9
    for key in ("allowed_actions", "require_approval", "deny_techniques",
                "allow_techniques"):
        value = policy.get(key)
        policy[key] = [str(v) for v in value] if isinstance(value, (list, tuple)) else []
    try:
        policy["cooldown_minutes"] = max(0, int(policy.get("cooldown_minutes", 30)))
    except (TypeError, ValueError):
        policy["cooldown_minutes"] = 30
    try:
        policy["max_actions_per_run"] = max(1, min(10, int(policy.get("max_actions_per_run", 2))))
    except (TypeError, ValueError):
        policy["max_actions_per_run"] = 2
    return policy


def _target_for(finding: dict):
    """Extract the entity an action would touch, or None."""
    for key in ("pid", "dest_ip", "path", "user"):
        value = finding.get(key)
        if value not in (None, "", "-"):
            return str(value)
    return None


def _chain_pid(finding: dict):
    events = finding.get("events") or []
    for event in reversed(events):
        if isinstance(event, dict) and str(event.get("pid") or "").isdigit():
            return int(event["pid"])
    return None


def proposals(findings: list[dict], policy: dict) -> list[dict]:
    """Map findings to candidate actions. Pure: no I/O, no execution."""
    out: list[dict] = []
    known = set(actuate.ACTIONS)
    for finding in findings:
        ftype = str(finding.get("type") or "")
        score = int(finding.get("score") or 0)
        technique = str(finding.get("technique") or "").upper()
        action = target = None
        why = []

        if technique in KILL_TECHNIQUES and finding.get("pid"):
            action, target = "kill_process", str(finding["pid"])
            why.append(f"{technique} on pid {target}")
        elif ftype in ("chain_injection_chain", "chain_injection_apc_chain"):
            pid = _chain_pid(finding)
            if pid:
                action, target = "kill_process", str(pid)
                why.append(f"{ftype} image pid {pid}")
        elif ftype == "canary_tripped":
            action, target = "isolate_host", None
            why.append("canary tripped — impact behaviour on this host")

        if not action:
            continue
        if action not in known:
            continue
        risk = RISK.get(action, "high")
        allowed = action in policy["allowed_actions"]
        needs_approval = action in policy["require_approval"]
        reasons = list(why)
        if score < policy["min_score"]:
            reasons.append(f"score {score} below min {policy['min_score']}")
        if technique and technique in policy["deny_techniques"]:
            reasons.append(f"technique {technique} denied by policy")
        if policy["allow_techniques"] and technique and \
                technique not in policy["allow_techniques"]:
            reasons.append(f"technique {technique} not in allow list")
        if not allowed and not needs_approval:
            reasons.append(f"action {action} is not allowlisted")

        blocked = any(r.startswith(("score ", "technique ")) or
                      r.endswith("not allowlisted") or "denied by policy" in r
                      for r in reasons)
        out.append({
            "type": ftype, "score": score, "technique": technique or None,
            "action": action, "target": target, "risk": risk,
            "mode": "pending_approval" if (needs_approval or not allowed) else "auto",
            "eligible": not blocked and not needs_approval and allowed,
            "reasons": reasons or ["policy allows automatic containment"],
            "detail": str(finding.get("detail") or "")[:200],
        })
    return out


def _cooling_down(root, action: str, target, minutes: int) -> bool:
    if minutes <= 0:
        return False
    cutoff = time.time() - minutes * 60
    for row in reversed(_read_journal(root)):
        if row.get("action") != action:
            continue
        if str(row.get("target") or "") != str(target or ""):
            continue
        if row.get("status") not in ("applied", "pending_approval"):
            continue
        try:
            ts = time.strptime(str(row.get("ts")), "%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, TypeError):
            continue
        if calendar.timegm(ts) >= cutoff:
            return True
    return False


def _applied_ok(result: dict) -> bool:
    """Actuate sets ok/mode; tolerate older/mocked results without them."""
    if "ok" in result:
        return bool(result["ok"])
    if "mode" in result:
        return result["mode"] == "applied"
    return "error" not in result


def _capture(root, trigger: dict, policy: dict):
    """Take one host-state snapshot before irreversible containment."""
    reason = ("enforce: capture host state before containment for "
              f"{trigger['type']} score={trigger['score']}")
    entry = {
        "type": "capture", "action": "snapshot", "target": None,
        "score": trigger.get("score"), "technique": trigger.get("technique"),
        "risk": "low", "mode": "auto",
        "finding_digest": hashlib.sha256(
            json.dumps({"type": trigger["type"], "detail": trigger["detail"]},
                       sort_keys=True).encode()).hexdigest()[:16],
        "reasons": ["capture before kill_process"],
    }
    if "snapshot" not in policy["allowed_actions"]:
        entry["status"] = "skipped"
        entry["reason"] = "snapshot is not in allowed_actions"
        return _append_journal(root, entry), False
    dry = actuate.execute("snapshot", root=root, reason=reason, apply=False)
    if "error" in dry:
        entry["status"] = "refused"
        entry["reason"] = dry["error"]
        return _append_journal(root, entry), False
    applied = actuate.execute("snapshot", root=root, reason=reason,
                              apply=True, plan=dry["id"])
    if "error" in applied:
        entry["status"] = "failed"
        entry["reason"] = applied["error"]
        return _append_journal(root, entry), False
    if not _applied_ok(applied):
        entry["status"] = "failed"
        entry["reason"] = applied.get("failure") or "snapshot failed"
        return _append_journal(root, entry), False
    entry["status"] = "applied"
    entry["plan"] = dry["id"]
    entry["result"] = {k: applied.get(k) for k in
                       ("verification", "output_head") if k in applied}
    return _append_journal(root, entry), True


def run(root, findings: list[dict] | None = None, apply: bool | None = None,
        sweep=None) -> dict:
    """Propose containment for a set of findings; act only per policy.

    ``apply`` overrides the policy mode for this invocation (CLI ``--apply``),
    but the policy's enabled flag, allowlist, approval gate and blast radius
    still apply. With no findings, a live sweep is taken.
    """
    root = Path(root)
    policy = load_policy(root)
    if findings is None:
        if sweep is None:
            from . import watch
            sweep = watch.sweep(root)
        findings = sweep.get("findings", [])

    proposed = proposals(findings, policy)
    armed = policy["enabled"] and (policy["mode"] == "enforce" or apply is True)
    if apply is False:
        armed = False

    # Evidence first: a kill destroys the in-memory artifact that the
    # injection detection exists to surface. Take one host snapshot before
    # the first automatic containment in this run. Snapshot is a read-only
    # export, so it needs no approval and does not consume the action cap.
    capture = None
    capture_ok = False
    if armed:
        triggers = [p for p in proposed
                    if p["eligible"] and p["action"] == "kill_process"]
        if triggers:
            capture, capture_ok = _capture(root, triggers[0], policy)

    results = []
    actions_taken = 0
    for item in proposed:
        entry = dict(item)
        entry["finding_digest"] = hashlib.sha256(
            json.dumps({"type": item["type"], "detail": item["detail"]},
                       sort_keys=True).encode()).hexdigest()[:16]
        if not armed:
            entry["status"] = "dry-run"
            entry["reason"] = ("enforcement disabled" if not policy["enabled"]
                               else "policy mode is dry-run")
        elif item["mode"] == "pending_approval" or not item["eligible"]:
            existing = _pending_exists(root, item["action"], item["target"],
                                       entry["finding_digest"])
            if existing is not None:
                entry["status"] = "pending_approval"
                entry["duplicate_of"] = existing["id"]
                entry["reason"] = "already pending approval"
                results.append(entry)
                continue
            entry["status"] = "pending_approval"
        elif actions_taken >= policy["max_actions_per_run"]:
            entry["status"] = "skipped"
            entry["reason"] = "per-run action cap reached"
        elif _cooling_down(root, item["action"], item["target"],
                           policy["cooldown_minutes"]):
            entry["status"] = "skipped"
            entry["reason"] = f"cooldown ({policy['cooldown_minutes']} min)"
        else:
            outcome = actuate.execute(
                item["action"], root=root, target=item["target"],
                reason=f"enforce: {item['type']} score={item['score']} "
                       f"{item['technique'] or ''}".strip(),
                apply=False)
            if "error" in outcome:
                entry["status"] = "refused"
                entry["reason"] = outcome["error"]
            else:
                plan = outcome["id"]
                applied = actuate.execute(
                    item["action"], root=root, target=item["target"],
                    reason=f"enforce: {item['type']} score={item['score']} "
                           f"{item['technique'] or ''}".strip(),
                    apply=True, plan=plan)
                if "error" in applied:
                    entry["status"] = "refused"
                    entry["reason"] = applied["error"]
                elif not _applied_ok(applied):
                    entry["status"] = "failed"
                    entry["reason"] = applied.get("failure") or "action failed"
                    entry["plan"] = plan
                else:
                    entry["status"] = "applied"
                    entry["plan"] = plan
                    entry["result"] = {
                        k: applied.get(k) for k in
                        ("ok", "verification", "output", "action")
                        if k in applied}
                    actions_taken += 1
        if item["action"] == "kill_process" and capture is not None:
            entry["capture"] = capture.get("status")
        results.append(_append_journal(root, entry))

    return {
        "at": _now(),
        "policy": {"enabled": policy["enabled"], "mode": policy["mode"],
                   "min_score": policy["min_score"],
                   "max_actions_per_run": policy["max_actions_per_run"],
                   "armed": armed},
        "findings": len(findings),
        "proposed": len(proposed),
        "applied": sum(1 for r in results if r["status"] == "applied"),
        "pending": sum(1 for r in results if r["status"] == "pending_approval"),
        "dry_run": sum(1 for r in results if r["status"] == "dry-run"),
        "capture": capture,
        "capture_ok": capture_ok,
        "results": results,
    }


def _approved_ids(root) -> set:
    return {r.get("approved_from") for r in _read_journal(root)
            if r.get("status") == "approved"}


def _pending_exists(root, action, target, digest):
    approved = _approved_ids(root)
    for row in _read_journal(root):
        if (row.get("status") == "pending_approval"
                and row.get("id") not in approved
                and row.get("action") == action
                and str(row.get("target") or "") == str(target or "")
                and row.get("finding_digest") == digest):
            return row
    return None


def pending(root) -> dict:
    approved = _approved_ids(root)
    seen = set()
    rows = []
    for row in _read_journal(root):
        if row.get("status") != "pending_approval":
            continue
        if row.get("id") in approved:
            continue
        key = (row.get("action"), str(row.get("target") or ""),
               row.get("finding_digest"))
        if key in seen:
            continue
        seen.add(key)
        rows.append(row)
    return {"count": len(rows), "pending": rows}


def approve(root, entry_id: int, apply: bool = False) -> dict:
    """Execute one pending request through actuate's dry-run + plan gate."""
    root = Path(root)
    rows = _read_journal(root)
    row = next((r for r in rows if int(r.get("id") or 0) == int(entry_id)), None)
    if not row:
        return {"error": f"no enforcement entry {entry_id}"}
    if row.get("status") != "pending_approval":
        return {"error": f"entry {entry_id} is {row.get('status')}, not pending"}
    if entry_id in _approved_ids(root):
        return {"error": f"entry {entry_id} has already been approved"}
    policy = load_policy(root)
    action = row.get("action")
    if action not in policy["allowed_actions"] and \
            action not in policy["require_approval"]:
        return {"error": f"action {action} is no longer allowlisted by policy"}
    reason = f"enforce approval #{entry_id}: {row.get('type')} score={row.get('score')}"
    dry = actuate.execute(row["action"], root=root, target=row.get("target"),
                          reason=reason, apply=False)
    if "error" in dry:
        return {"error": dry["error"], "stage": "dry-run"}
    result = {"entry": entry_id, "action": row["action"],
              "target": row.get("target"), "plan": dry["id"],
              "payload": dry.get("payload")}
    if apply:
        done = actuate.execute(row["action"], root=root,
                               target=row.get("target"), reason=reason,
                               apply=True, plan=dry["id"])
        if "error" in done:
            return {"error": done["error"], "stage": "apply", **result}
        ok = _applied_ok(done)
        if ok:
            _append_journal(root, {
                "status": "approved", "approved_from": entry_id,
                "action": row["action"], "target": row.get("target"),
                "risk": row.get("risk"), "type": row.get("type"),
                "score": row.get("score"), "technique": row.get("technique"),
                "reasons": ["approved by operator"],
            })
        _append_journal(root, {
            "status": "applied" if ok else "failed", "action": row["action"],
            "target": row.get("target"), "risk": row.get("risk"),
            "type": row.get("type"), "score": row.get("score"),
            "technique": row.get("technique"),
            "approved_from": entry_id, "plan": dry["id"],
            "reasons": ["approved by operator"],
        })
        result["applied"] = bool(ok)
        result["result"] = {k: done.get(k) for k in
                            ("ok", "failure", "verification", "output")
                            if k in done}
    return result


def status(root) -> dict:
    policy = load_policy(root)
    rows = _read_journal(root)
    return {
        "policy": policy,
        "journal": str(journal_path(root)),
        "entries": len(rows),
        "applied": sum(1 for r in rows if r.get("status") == "applied"),
        "pending": sum(1 for r in rows if r.get("status") == "pending_approval"),
        "kill_switch": killswitch.blocked(Path(root), host=None, risk="medium"),
    }
