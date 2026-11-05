"""Plasma playbooks: named, reviewed SEQUENCES of actuate actions.

A playbook is a bigger allowlist, not a wider door: a fixed sequence of
existing allowlisted actions, applied as ONE plan-gated unit. Every step is
still an individual dry-run + plan-gated apply; the playbook simply binds
them together, aborts on the first failing step, and is reversible
step-by-step in reverse order.

    contain-user <user>   disable_user + snapshot
    isolate-box           isolate_host + snapshot
"""

from __future__ import annotations

from . import actuate

PLAYBOOKS = {
    "contain-user": {
        "description": "disable a local account, then snapshot host state",
        "steps": [
            {"action": "disable_user", "takes_target": True},
            {"action": "snapshot", "takes_target": False},
        ],
    },
    "isolate-box": {
        "description": "full isolation (management ports kept open), then snapshot",
        "steps": [
            {"action": "isolate_host", "takes_target": False},
            {"action": "snapshot", "takes_target": False},
        ],
    },
}


def actions() -> dict:
    return {name: spec["description"] for name, spec in PLAYBOOKS.items()}


def _journal(root, entry):
    # ids are assigned at journal time: the step dry-runs appended before the
    # playbook entry consume ids first (an early id would collide with them)
    if "id" not in entry:
        entry["id"] = actuate._next_id(root)
    return actuate._journal_append(root, entry)


def execute(root, name: str, target=None, reason=None, apply: bool = False,
            plan: int | None = None, timeout: int = 60) -> dict:
    """Dry-run by default (journals step dry-runs + a playbook entry).

    apply=True requires `plan`: the playbook dry-run entry id. Each step is
    applied through actuate's own plan gate; the playbook aborts on the
    first failing step and records exactly how far it got."""
    spec = PLAYBOOKS.get(name)
    if not spec:
        return {"error": f"unknown playbook '{name}'", "playbooks": actions()}
    if reason is None or not str(reason).strip():
        return {"error": "a --reason is mandatory for every playbook call"}
    target = str(target).strip() if target else None
    if any(s["takes_target"] for s in spec["steps"]) and not target:
        return {"error": f"playbook '{name}' requires a target"}

    if apply:
        if plan is None:
            return {"error": "--apply requires --plan <id> of the playbook dry-run"}
        rows = actuate.journal_read(root)
        dr = next((r for r in rows if r.get("id") == plan), None)
        if not dr or dr.get("mode") != "dry-run" or \
                dr.get("action") != f"playbook:{name}":
            return {"error": f"--plan {plan} is not a dry-run of playbook '{name}'"}
        if str(dr.get("target") or "") != str(target or ""):
            return {"error": f"--plan {plan} targeted '{dr.get('target')}', not '{target}'"}

    entry = {
        "action": f"playbook:{name}",
        "target": target, "reason": str(reason),
        "mode": "applied" if apply else "dry-run",
        "steps": [],
    }
    step_entries: list[dict] = []
    if apply:
        entry["plan"] = plan
        step_plans = dr.get("steps") or []

    if not apply:
        for spec_step in spec["steps"]:
            res = actuate.execute(
                spec_step["action"], root,
                target=target if spec_step["takes_target"] else None,
                reason=f"[{name}] {reason}", apply=False, timeout=timeout)
            if "error" in res:
                return {"error": f"step {spec_step['action']} refused: {res['error']}"}
            step_entries.append(res)
        entry["steps"] = [{"action": s["action"], "plan": s["id"]}
                          for s in step_entries]
        _journal(root, entry)
        entry["rendered"] = [{"action": s["action"], "payload": s.get("payload")}
                             for s in step_entries]
        return entry

    # apply: walk the journaled step plans in order
    for spec_step, planned in zip(spec["steps"], step_plans):
        step_id = planned["plan"]
        res = actuate.execute(
            spec_step["action"], root,
            target=target if spec_step["takes_target"] else None,
            reason=f"[{name}] {reason}", apply=True, plan=step_id, timeout=timeout)
        step_result = {
            "action": spec_step["action"], "plan": step_id,
            "applied_id": res.get("id"),
        }
        if "error" in res:
            step_result["error"] = res["error"]
            entry["steps"].append(step_result)
            entry["aborted_at"] = spec_step["action"]
            _journal(root, entry)
            return entry
        run = res.get("result") or {}
        ok = not run.get("error") and run.get("rc") in (0, None)
        step_result["ok"] = ok
        entry["steps"].append(step_result)
        if not ok:
            entry["aborted_at"] = spec_step["action"]
            _journal(root, entry)
            return entry
    _journal(root, entry)
    return entry


def undo(root, entry_id: int, apply: bool = False, timeout: int = 60) -> dict:
    """Reverse a playbook's succeeded steps, last-first, via actuate.undo."""
    rows = actuate.journal_read(root)
    match = next((r for r in rows if r.get("id") == entry_id), None)
    if not match:
        return {"error": f"no journal entry {entry_id}"}
    if not str(match.get("action", "")).startswith("playbook:"):
        return {"error": f"entry {entry_id} is not a playbook"}
    if match.get("mode") != "applied":
        return {"error": f"entry {entry_id} is '{match.get('mode')}', nothing to undo"}

    reversals = []
    rows_by_id = {r.get("id"): r for r in rows}
    for step in reversed(match.get("steps", [])):
        applied_id = step.get("applied_id")
        if not applied_id or step.get("ok") is False:
            continue
        applied = rows_by_id.get(applied_id) or {}
        if not applied.get("undoable") or not applied.get("undo"):
            reversals.append({"step": step["action"], "undoes": applied_id,
                              "skipped": "step is not undoable"})
            continue
        res = actuate.undo(root, applied_id, apply=apply, timeout=timeout)
        reversals.append({"step": step["action"], "undoes": applied_id,
                          "mode": res.get("mode"), "error": res.get("error")})
        if res.get("error"):
            break
    summary = {
        "id": actuate._next_id(root),
        "action": f"undo:{match['action']}", "undoes": entry_id,
        "target": match.get("target"),
        "reason": f"undo of playbook entry {entry_id}",
        "mode": "applied" if apply else "dry-run",
        "steps": reversals,
    }
    _journal(root, summary)
    return summary
