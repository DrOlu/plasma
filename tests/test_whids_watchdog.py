"""WHIDS watchdog: heal a hung StartPending or a stopped service.

WHIDS 1.7.0 can sit in StartPending forever (or stop after a manual
restart). SCM failure actions only cover crashes, so the installer
registers a SYSTEM task that runs `whids ensure` every two minutes.
"""

import json

from plasma import whids
from plasma.cli import _register_whids_watchdog


def _patch(monkeypatch, states):
    seq = iter(states)
    monkeypatch.setattr(whids, "_whids_service_name", lambda: "Whids")
    monkeypatch.setattr(whids, "_service_state", lambda name=None: next(seq))
    monkeypatch.setattr("time.sleep", lambda seconds: None)
    calls = []
    monkeypatch.setattr(whids, "_ps",
                        lambda script, timeout=60: calls.append(script) or (0, ""))
    # never write the real watchdog log from a test
    monkeypatch.setattr(whids, "_watchdog_log", lambda root, result: None)
    return calls


def test_ensure_running_is_a_noop(monkeypatch):
    calls = _patch(monkeypatch, ["Running"])
    res = whids.ensure()
    assert res["ok"] is True and res["actions"] == []
    assert calls == []


def test_ensure_heals_a_stopped_service(monkeypatch):
    calls = _patch(monkeypatch, ["Stopped", "Running"])
    res = whids.ensure()
    assert res["ok"] is True and res["state"] == "Running"
    assert any("Stop-Service" in c for c in calls)
    assert any("Start-Service" in c for c in calls)


def test_ensure_force_stops_a_hung_startpending(monkeypatch):
    """A hung StartPending never responds to Start-Service: stop first."""
    calls = _patch(monkeypatch, ["StartPending", "Stopped", "Running"])
    res = whids.ensure()
    assert res["ok"] is True
    assert any("Stop-Service" in c and "-Force" in c for c in calls)
    assert any("Start-Service" in c for c in calls)


def test_ensure_reports_failure(monkeypatch):
    _patch(monkeypatch, ["Stopped", "Stopped"])
    res = whids.ensure()
    assert res["ok"] is False and res["state"] == "Stopped"


def test_ensure_logs_only_when_it_acts(tmp_path, monkeypatch):
    real_log = whids._watchdog_log
    _patch(monkeypatch, ["Stopped", "Running"])
    monkeypatch.setattr(whids, "_watchdog_log", real_log)
    whids.ensure(root=tmp_path)
    log = tmp_path / "logs" / "whids-watchdog.log"
    assert log.exists()
    row = json.loads(log.read_text().strip())
    assert row["ok"] is True and row["actions"]


def test_watchdog_task_registration(monkeypatch):
    seen = []
    monkeypatch.setattr(whids, "_ps",
                        lambda script, timeout=60: seen.append(script) or (0, ""))
    res = _register_whids_watchdog(r"C:\ProgramData\Plasma\bin\plasma.exe",
                                   r"C:\ProgramData\Plasma")
    assert res["ok"] is True and res["task"] == "PlasmaWhidsWatchdog"
    script = seen[0]
    assert "PlasmaWhidsWatchdog" in script
    assert "whids ensure" in script
    assert "SYSTEM" in script
    assert "RepetitionInterval" in script
