"""Boot-time task triggers and the health check that surfaces drift."""
from __future__ import annotations

from plasma import canary_shield, cli, health, whids


def _capture(monkeypatch):
    seen = []
    monkeypatch.setattr(whids, "_ps",
                        lambda script, timeout=60: seen.append(script) or (0, ""))
    return seen


def test_watch_task_starts_at_boot_and_catches_up(monkeypatch, tmp_path):
    seen = _capture(monkeypatch)
    result = cli._register_watch(tmp_path / "plasma.exe", tmp_path / "Plasma")
    assert result["ok"] is True
    script = seen[0]
    assert "-AtStartup" in script
    assert "StartWhenAvailable" in script
    assert "RestartCount 3" in script
    assert "ExecutionTimeLimit" in script
    assert "MultipleInstances IgnoreNew" in script
    assert "-Trigger @($t,$b)" in script


def test_watchdog_starts_at_boot_and_catches_up(monkeypatch, tmp_path):
    seen = _capture(monkeypatch)
    result = cli._register_whids_watchdog(tmp_path / "plasma.exe",
                                           tmp_path / "Plasma")
    assert result["ok"] is True
    script = seen[0]
    assert "-AtStartup" in script
    assert "StartWhenAvailable" in script
    assert "RestartCount 3" in script
    assert "-Trigger @($t,$b)" in script


def test_update_task_stays_in_its_maintenance_window(monkeypatch, tmp_path):
    seen = _capture(monkeypatch)
    result = cli._register_update(tmp_path / "plasma.exe", tmp_path / "Plasma")
    assert result["ok"] is True
    script = seen[0]
    assert "New-ScheduledTaskTrigger -Daily" in script
    assert "-AtStartup" not in script
    assert "StartWhenAvailable" not in script
    assert "ExecutionTimeLimit" in script
    assert "MultipleInstances IgnoreNew" in script


def test_shield_task_starts_at_boot_and_catches_up():
    script = canary_shield._task_script(
        r"C:\ProgramData\Plasma", r"C:\ProgramData\Plasma\bin\plasma.exe")
    assert "-AtStartup" in script
    assert "StartWhenAvailable" in script
    assert "RestartCount 3" in script
    assert "-Trigger @($t,$b)" in script


def test_health_reads_boot_trigger_state(monkeypatch):
    monkeypatch.setattr(
        health, "_ps",
        lambda script, timeout=60: '[{"name":"PlasmaWatch","boot":true,'
                                   '"state":"Ready"}]')
    assert health._task_boot_state() == [
        {"name": "PlasmaWatch", "boot": True, "state": "Ready"}]


def test_health_handles_unreadable_task_state(monkeypatch):
    monkeypatch.setattr(health, "_ps", lambda script, timeout=60: "not json")
    assert health._task_boot_state() == []
