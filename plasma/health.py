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
from datetime import datetime, timezone
from pathlib import Path


def _ps(script: str, timeout: int = 60) -> str:
    exe = "powershell.exe"
    try:
        proc = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", script],
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
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
        "if ($e) { [math]::Round(((Get-Date) - $e.TimeCreated).TotalMinutes, 1)"
        ".ToString([System.Globalization.CultureInfo]::InvariantCulture) }")
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
        detail = f"service {state}"
        if state in ("StartPending", "Stopping"):
            detail = (f"service {state} (hung at init — "
                      f"run: plasma whids diagnose)")
        results.append({"check": "whids_service", "ok": ok, "detail": detail})
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

    # sensor-of-sensors: is the diary still being written? A perfectly
    # healthy service writing an empty store is not healthy — that is the
    # "installed but blind" failure this project exists to make visible.
    heartbeat_checked = False
    if ev.exists() and ev.stat().st_size > 0:
        heartbeat_checked = True
        age_min = _store_age_minutes(ev)
        if age_min is None:
            results.append({"check": "sensor_heartbeat", "ok": False,
                            "detail": "newest store row has no parsable ts"})
        else:
            results.append({"check": "sensor_heartbeat", "ok": age_min <= 1440,
                            "detail": f"newest event {int(age_min)} min old"})
    if is_windows and whids_status in ("active", "installing") \
            and not heartbeat_checked and ev.exists():
        results.append({"check": "sensor_heartbeat", "ok": False,
                        "detail": "events store is empty — sensors are running "
                                  "but have not written anything"})

    # rdp hardening drift (windows endpoints): the lockout-incident checks —
    # RDP must stay enabled and on a sane security layer
    if is_windows:
        state = _ps(
            "$t = Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' "
            "-Name fDenyTSConnections -ErrorAction SilentlyContinue;"
            "$k = Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
            "-ErrorAction SilentlyContinue;"
            "'deny=' + $t.fDenyTSConnections + ';layer=' + $k.SecurityLayer + "
           "';cert=' + [bool]$k.SSLCertificateSHA1Hash")
        parsed = dict(p.split("=", 1) for p in state.split(";") if "=" in p)
        deny, layer = parsed.get("deny", "?"), parsed.get("layer", "?")
        ok = deny == "0" and layer in ("1", "2")
        results.append({"check": "rdp_hardening_drift", "ok": ok,
                        "detail": f"fDenyTSConnections={deny} SecurityLayer={layer}"
                                  + ("" if ok else " — RDP drifted from the healthy posture")})

    if degraded_mode:
        results.append({"check": "install_mode", "ok": True,
                        "detail": "MINIMAL mode — expected reduced coverage"})
    return results


def _store_age_minutes(events_path) -> float | None:
    """Age in minutes of the newest parsable ts line in the store.

    Reads a bounded tail (up to 256 KB) instead of the whole diary: health
    is called on a cadence and must not become O(store size).
    """
    try:
        path = Path(events_path)
        with path.open("rb") as fh:
            fh.seek(0, 2)
            end = fh.tell()
            fh.seek(max(0, end - (256 << 10)))
            blob = fh.read().decode("utf-8", "replace")
        lines = [ln for ln in blob.splitlines() if ln.strip().startswith("{")]
        row = None
        for line in reversed(lines):
            try:
                row = json.loads(line)
                break
            except json.JSONDecodeError:
                continue
        if row is None:
            return None
        ts = datetime.fromisoformat(str(row.get("ts", "")).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - ts).total_seconds() / 60
    except (OSError, ValueError, json.JSONDecodeError):
        return None


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
