"""Plasma health: is this node's Plasma stack actually alive?

Born from field evidence: WS1's WHIDS sat in StartPending for hours while
looking installed. Deterministic checks, one JSON verdict:

  ok       — everything expected is running
  degraded — running, but coverage gaps exist (minimal mode, blind audit)
  down     — a sensor that should be running is not

The sensor list comes from the install-time decision recorded in
config.json — a minimal-mode node is not "down" for lacking WHIDS.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path


def _ps(script: str, timeout: int = 60) -> str:
    exe = "powershell.exe"
    try:
        proc = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", script],
                              capture_output=True, text=True, timeout=timeout)
        return (proc.stdout or "").strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _service_state(name: str) -> str:
    out = _ps(f"(Get-Service {name} -ErrorAction SilentlyContinue).Status")
    return out or "Absent"


def _newest_event_age_minutes(channel: str) -> float | None:
    out = _ps(
        "$e = Get-WinEvent -FilterHashtable @{LogName='" + channel +
        "'} -MaxEvents 1 -ErrorAction SilentlyContinue; "
        "if ($e) { [math]::Round(((Get-Date) - $e.TimeCreated).TotalMinutes, 1) }")
    try:
        return float(out)
    except (TypeError, ValueError):
        return None


# module flag so tests (and non-Windows desks) can gate endpoint checks
IS_WINDOWS = os.name == "nt"


def checks(root) -> list[dict]:
    root = Path(root)
    results = []

    config = {}
    cfg_path = root / "config.json"
    if cfg_path.exists():
        try:
            # utf-8-sig: PowerShell-written configs may carry a BOM
            config = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError:
            results.append({"check": "config", "ok": False,
                            "detail": "config.json unparsable"})
    sensors = config.get("sensors", {})
    degraded_mode = bool(config.get("degraded"))

    # store writable
    ev = Path(config.get("events_path", root / "data" / "events.jsonl"))
    try:
        ev.parent.mkdir(parents=True, exist_ok=True)
        probe = ev.with_suffix(".health-probe")
        probe.write_text("", encoding="utf-8")
        probe.unlink()
        results.append({"check": "events_store", "ok": True, "detail": str(ev)})
    except OSError as exc:
        results.append({"check": "events_store", "ok": False, "detail": str(exc)[:120]})

    # Windows-only sensor checks: a desk on macOS/Linux manages fleets
    # remotely and must not report endpoint sensors as down.
    is_windows = IS_WINDOWS

    # WHIDS: only demanded when the install decision activated it
    whids_status = sensors.get("whids", {}).get("status", "skipped")
    if whids_status in ("active", "installing") and not is_windows:
        results.append({"check": "whids_service", "ok": True,
                        "detail": "windows node — sensor checks run on the endpoint"})
    elif whids_status in ("active", "installing"):
        state = _service_state("Whids")
        ok = state == "Running"
        results.append({"check": "whids_service", "ok": ok,
                        "detail": f"service {state}"})
        if ok:
            age = _newest_event_age_minutes("Microsoft-Windows-Sysmon/Operational")
            if age is None:
                results.append({"check": "sysmon_feed", "ok": False,
                                "detail": "no Sysmon events readable"})
            else:
                results.append({"check": "sysmon_feed", "ok": age <= 60,
                                "detail": f"newest Sysmon event {age} min old"})
    else:
        results.append({"check": "whids_service", "ok": True,
                        "detail": f"not active on this node ({whids_status}) — "
                                  "identity + tap carry detection"})

    # Sysmon itself, whenever WHIDS is expected to be alive
    if is_windows and whids_status in ("active", "installing"):
        state = _service_state("Sysmon64")
        if state == "Absent":
            state = _service_state("Sysmon")
        results.append({"check": "sysmon_service", "ok": state == "Running",
                        "detail": f"service {state}"})

    # tap sidecar present? (windows endpoints only)
    if is_windows:
        from .cli import _locate_tap_exe
        results.append({"check": "tap_sidecar", "ok": _locate_tap_exe() is not None,
                        "detail": "materialized on demand"})

    if degraded_mode:
        results.append({"check": "install_mode", "ok": True,
                        "detail": "MINIMAL mode — expected reduced coverage"})
    return results


def verdict(root) -> dict:
    results = checks(root)
    hard_fail = [c for c in results if not c["ok"] and c["check"] != "install_mode"]
    status = ("ok" if not hard_fail else
              "down" if any(c["check"] in ("whids_service", "sysmon_service",
                                           "sysmon_feed") for c in hard_fail) else
              "degraded")
    return {"status": status, "checks": results,
            "failed": [c["check"] for c in hard_fail],
            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
