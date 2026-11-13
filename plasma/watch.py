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

    # 3. NEW WHIDS alert rows sitting on disk since the last sweep
    #    (whids.pull never truncates rotated files, so comparing against the
    #    absolute row count would re-fire forever; only growth is a finding)
    alerts_dir = Path(r"C:\Program Files\Whids\Logs\Alerts")
    alert_rows = 0
    if alerts_dir.is_dir():
        for f in alerts_dir.rglob("*"):
            if f.is_file():
                alert_rows += sum(1 for ln in f.read_text(errors="replace").splitlines() if ln.strip())
    alert_state_path = root / "watch-alerts-state.json"
    seen_alert_rows = 0
    if alert_state_path.exists():
        try:
            seen_alert_rows = int(json.loads(
                alert_state_path.read_text(encoding="utf-8-sig")).get("seen_alert_rows", 0))
        except (ValueError, json.JSONDecodeError):
            seen_alert_rows = 0
    new_alert_rows = max(0, alert_rows - seen_alert_rows)
    if new_alert_rows > since_alerts:
        findings.append({"type": "unpulled_whids_alerts", "score": 6,
                         "detail": f"{new_alert_rows} new alert rows since last sweep "
                                   f"— run: plasma whids pull"})
    try:
        alert_state_path.write_text(
            json.dumps({"seen_alert_rows": alert_rows}) + "\n", encoding="utf-8")
    except OSError:
        pass

    # 4. chain stories over the events tail (deterministic sequences —
    #    "this happened, then this": phish spawn, brute-force-success, ...)
    try:
        from . import chain as chain_mod
        store = root / "data" / "events.jsonl"
        if store.exists():
            cres = chain_mod.scan_store(store)
            for f in cres.get("findings", []):
                findings.append({"type": f["type"], "score": f["score"],
                                 "detail": str(f["detail"])[:200]})
    except Exception as exc:  # noqa: BLE001 — collector failures are data
        findings.append({"type": "chain_scan_error", "score": 5,
                         "detail": str(exc)[:160]})

    # 5. canary files — decoys whose only purpose is to be touched.
    #    A missing or modified canary is impact detection (T1486), score 10.
    try:
        from . import canary as canary_mod
        can = canary_mod.verify(root)
        for t in can.get("tripped", []):
            findings.append({
                "type": "canary_tripped", "score": 10,
                "detail": f"canary {t['reason']}: {t['path']}"[:200]})
    except Exception as exc:  # noqa: BLE001 — collector failures are data
        findings.append({"type": "canary_scan_error", "score": 5,
                         "detail": str(exc)[:160]})

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
        # throttle key = the loudest finding's type: at most one message per
        # finding-type per hour, even on a noisy day
        loudest = max(result["findings"], key=lambda f: f["score"], default=None)
        delivered = notify.notify_all(root, title, body,
                                      score=result["top_score"],
                                      throttle_key=loudest["type"] if loudest else None)
    result["notify"] = delivered
    state = Path(root) / "watch-state.json"
    state.write_text(json.dumps(result, indent=1, default=str) + "\n", encoding="utf-8")
    return result
