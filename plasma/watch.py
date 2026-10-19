"""Plasma watch: periodic self-check sweep with notifications.

Not a standing collector — a sweep the operator (or Task Scheduler) runs
on demand or on a cadence:  health verdict + drift score + canary +
new-WHIDS-alert count, delivered through notify channels when something
crosses a threshold. `--once` for cron, `--loop N` for long-running.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from . import health, notify, observatory


def sweep(root, since_alerts: int = 25, drift_question: str = "attest") -> dict:
    root = Path(root)
    findings = []
    info = []

    # 1. health verdict
    hv = health.verdict(root)
    if hv["status"] != "ok":
        findings.append({"type": "health", "score": (10 if hv["status"] == "down" else 6),
                         "detail": f"health {hv['status']}: {', '.join(hv['failed'])}"})

    # 2. drift on a live observatory answer (attest = witness blindness + sensors)
    from . import drift
    try:
        answer = observatory.run_question(drift_question)
        result = drift.score(root, drift_question, answer)
        drift_rows = result.get("drift", [])
        for d in drift_rows:
            findings.append({"type": f"drift_{d['type']}", "score": d.get("score", 5),
                             "detail": str(d.get("detail"))[:200]})
        if not drift_rows and "no baseline" in str(result.get("error", "")):
            info.append(f"no {drift_question} baseline yet — run: "
                        f"plasma drift record --question {drift_question}")
    except Exception as exc:  # noqa: BLE001 — collector failures are data
        findings.append({"type": "sweep_error", "score": 5,
                         "detail": str(exc)[:160]})

    # 3. WHIDS alerts sitting on disk unpulled
    alerts_dir = Path(r"C:\Program Files\Whids\Logs\Alerts")
    alert_rows = 0
    if alerts_dir.is_dir():
        for f in alerts_dir.rglob("*"):
            if f.is_file():
                alert_rows += sum(1 for ln in f.read_text(errors="replace").splitlines() if ln.strip())
    if alert_rows > since_alerts:
        findings.append({"type": "unpulled_whids_alerts", "score": 6,
                         "detail": f"{alert_rows} alert rows on disk — run: plasma whids pull"})

    top = max((f["score"] for f in findings), default=0)
    return {"info": info, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "health": hv["status"], "findings": findings, "top_score": top,
            "verdict": ("clean" if top == 0 else
                        "investigate" if top < 8 else "act now")}


def watch_once(root, quiet_clean: bool = True) -> dict:
    result = sweep(root)
    should_notify = (not quiet_clean) or result["top_score"] > 0
    delivered = None
    if should_notify:
        title = f"Plasma watch: {result['verdict']} ({result['top_score']}/10)"
        body = "\n".join(f"- [{f['score']}] {f['type']}: {f['detail']}"
                         for f in result["findings"]) or "clean"
        delivered = notify.notify_all(root, title, body,
                                      min_score=1 if result["top_score"] else 99)
    result["notify"] = delivered
    state = Path(root) / "watch-state.json"
    state.write_text(json.dumps(result, indent=1, default=str) + "\n", encoding="utf-8")
    return result
