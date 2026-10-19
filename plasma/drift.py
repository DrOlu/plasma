"""Plasma drift: record observatory answers as baselines, score later runs.

rmagent-so lineage: the operational question is never "is this host clean"
but "what changed since I last looked, and does it matter". This module
stores named baselines (JSON) under <root>/baselines/ and diffs later
answers of the same question against them with deterministic rules.

Scored drift types (0-10, WHIDS-style criticality):
  canary_tripped   10  a canary account authenticated since baseline
  sensor_down      10  Sysmon/WHIDS left Running state
  admin_added       9  new local Administrator member
  new_persistence   9  new attackmap persistence entry
  blind_drift       8  audit coverage regressed (blind_count grew)
  new_service       8  new service install
  new_task          7  new scheduled task
  admin_removed     3  admin removed (informational, could be deliberate)
  peer_change       2  remote TCP peer set changed (informational)
"""

from __future__ import annotations

import json
import time
from pathlib import Path

BASELINES = "baselines"


def _base_path(root, name):
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
    return Path(root) / BASELINES / f"{safe}.json"


def record(root, name, answer):
    """Persist an observatory answer as the new baseline for `name`."""
    if "error" in answer:
        return {"error": f"refusing to baseline a failed answer: {answer['error']}"}
    path = _base_path(root, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    blob = {
        "question": name,
        "recorded_at": answer.get("_recorded_at") or _now(),
        "host": answer.get("host"),
        "answer": answer,
    }
    path.write_text(json.dumps(blob, ensure_ascii=False, indent=1), encoding="utf-8")
    return {"ok": True, "baseline": str(path), "question": name}


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load(root, name):
    path = _base_path(root, name)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def baselines(root):
    base = Path(root) / BASELINES
    if not base.exists():
        return []
    return sorted(p.stem for p in base.glob("*.json"))


# ---------------------------------------------------------------------------
# Scoring. Rules are deterministic and keyed by question name.
# ---------------------------------------------------------------------------

def _set_diff(field, base_answer, now_answer, getter=lambda x: x):
    before = {getter(v) for v in (base_answer.get(field) or [])}
    after = {getter(v) for v in (now_answer.get(field) or [])}
    return sorted(after - before), sorted(before - after)


def _score_attest(base, now):
    drift = []
    b_blind, n_blind = base.get("blind_count", 0), now.get("blind_count", 0)
    if n_blind > b_blind:
        new = [s for s in (now.get("blind_subcategories") or [])
               if s not in (base.get("blind_subcategories") or [])]
        drift.append({"type": "blind_drift", "score": 8, "detail": new})
    for svc in ("sysmon_service", "whids_service"):
        if base.get(svc) == "Running" and now.get(svc) != "Running":
            drift.append({"type": "sensor_down", "score": 10,
                          "detail": f"{svc}: {base.get(svc)} -> {now.get(svc)}"})
    return drift


def _score_sketch(base, now):
    drift = []
    added, removed = _set_diff("administrators", base, now)
    if added:
        drift.append({"type": "admin_added", "score": 9, "detail": added})
    if removed:
        drift.append({"type": "admin_removed", "score": 3, "detail": removed})

    def _svc(row):
        return row.get("name") if isinstance(row, dict) else str(row)

    base_svc = {_svc(r) for r in (base.get("services_installed_24h") or [])}
    new_svc = [_svc(r) for r in (now.get("services_installed_24h") or []) if _svc(r) not in base_svc]
    if new_svc:
        drift.append({"type": "new_service", "score": 8, "detail": new_svc})

    def _task(row):
        return row.get("task") if isinstance(row, dict) else str(row)

    base_tasks = {_task(r) for r in (base.get("tasks_created_24h") or [])}
    new_tasks = [_task(r) for r in (now.get("tasks_created_24h") or []) if _task(r) not in base_tasks]
    if new_tasks:
        drift.append({"type": "new_task", "score": 7, "detail": new_tasks})
    return drift


def _score_attackmap(base, now):
    added, _ = _set_diff("findings", base, now,
                         getter=lambda f: f.get("location") if isinstance(f, dict) else str(f))
    return ([{"type": "new_persistence", "score": 9, "detail": added}] if added else [])


def _score_canary(base, now):
    if now.get("hit_count", 0) > 0:
        return [{"type": "canary_tripped", "score": 10,
                 "detail": now.get("hits")[:5] if now.get("hits") else "hits present"}]
    return []


def _score_flowstats(base, now):
    added, removed = _set_diff("remote_peers", base, now,
                               getter=lambda p: p.get("remote") if isinstance(p, dict) else str(p))
    drift = []
    if added:
        drift.append({"type": "peer_change", "score": 2, "detail": {"new": added[:10]}})
    return drift


_SCORERS = {
    "attest": _score_attest,
    "sketch": _score_sketch,
    "attackmap": _score_attackmap,
    "canary": _score_canary,
    "flowstats": _score_flowstats,
}


def score(root, name, answer):
    """Diff `answer` against the stored baseline for `name`."""
    if "error" in answer:
        return {"error": f"cannot score a failed answer: {answer['error']}"}
    base_blob = load(root, name)
    if not base_blob:
        return {"error": f"no baseline for '{name}'",
                "hint": "run: plasma drift record --question " + name}
    scorer = _SCORERS.get(name)
    if not scorer:
        return {"error": f"no scoring rules for question '{name}'",
                "scored": sorted(_SCORERS)}
    drift = scorer(base_blob["answer"], answer)
    drift.sort(key=lambda d: -d.get("score", 0))
    top = max((d.get("score", 0) for d in drift), default=0)
    return {
        "question": name,
        "baseline_recorded_at": base_blob["recorded_at"],
        "scored_at": _now(),
        "drift": drift,
        "top_score": top,
        "verdict": ("clean" if top == 0 else
                    "investigate" if top < 8 else
                    "act now"),
    }
