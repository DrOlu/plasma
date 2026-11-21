"""Active canary shield: includes, matching, kill decisions and plan gate."""
from __future__ import annotations

import json
from pathlib import Path

from plasma import canary, canary_shield, cli


def _root(tmp_path):
    root = tmp_path / "plasma"
    (root / "tools").mkdir(parents=True)
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "plasma.exe").write_bytes(b"stub")
    (root / "tools" / "plasma-sysmon-baseline.xml").write_text(
        cli.sysmon_baseline_config())
    canary.deploy(root, randomize=False, subdir="Finance")
    return root


def _event(pid=1234, image=r"C:\Tools\evil.exe", target=None,
           target_object=None, eid=11, record=1):
    return {
        "record_id": record, "ts": "2026-11-20T10:00:00Z",
        "event_id": eid, "image": image, "process_id": pid,
        "target": target, "target_object": target_object, "user": "CORP\\olu",
    }


def _manifest_path(root):
    return json.loads((root / "canaries.json").read_text())["canaries"][0]["path"]


def test_shield_config_adds_only_canary_conditions(tmp_path):
    root = _root(tmp_path)
    name = Path(_manifest_path(root)).name
    cfg = canary_shield.shield_config(root)
    assert "FileCreate" in cfg["xml"] and 'onmatch="include"' in cfg["xml"]
    assert f"\\{name}" in cfg["xml"]
    assert cfg["canaries"] == 8
    assert cfg["file_conditions"] == 8


def test_registry_canary_is_added_to_registry_include(tmp_path, monkeypatch):
    root = _root(tmp_path)
    monkeypatch.setattr(canary_shield, "_ps",
                        lambda s, timeout=120: (0, '{"ok":true}'))
    out = canary_shield.registry_deploy(root, hive="HKCU", count=1)
    assert out["ok"] is True
    cfg = canary_shield.shield_config(root)
    assert "RegistryEvent" in cfg["xml"] and 'onmatch="include"' in cfg["xml"]
    assert "PlasmaDecoy\\" in cfg["xml"]
    assert cfg["registry_conditions"] == 1


def test_sweep_kills_matching_process(tmp_path, monkeypatch):
    root = _root(tmp_path)
    target = _manifest_path(root)
    monkeypatch.setattr(canary_shield, "IS_WINDOWS", True)
    monkeypatch.setattr(canary_shield, "IS_WINDOWS", True)
    monkeypatch.setattr(canary_shield, "_ps_json", lambda s, timeout=120: (
        {"events": [_event(target=target)], "error": None}, None))
    monkeypatch.setattr(canary_shield, "_live_process",
                        lambda pid: {"id": pid, "name": "evil",
                                     "path": r"C:\Tools\evil.exe",
                                     "start": "2026-11-20T09:59:00Z"})
    killed = {}
    monkeypatch.setattr(canary_shield, "_kill",
                        lambda pid: (killed.update(pid=pid) or {"ok": True}))
    out = canary_shield.sweep(root, apply=True, reason="test", since_minutes=5)
    assert out["killed"] == 1
    assert killed["pid"] == 1234
    assert (root / "canary-shield-journal.jsonl").exists()


def test_sweep_skips_trusted_explorer(tmp_path, monkeypatch):
    root = _root(tmp_path)
    target = _manifest_path(root)
    monkeypatch.setattr(canary_shield, "IS_WINDOWS", True)
    monkeypatch.setattr(canary_shield, "_ps_json", lambda s, timeout=120: (
        {"events": [_event(image=r"C:\Windows\explorer.exe", target=target)],
         "error": None}, None))
    out = canary_shield.sweep(root, apply=True, reason="test")
    assert out["killed"] == 0
    assert out["skips"][0]["reason"] == "trusted process"


def test_sweep_refuses_protected_process(tmp_path, monkeypatch):
    root = _root(tmp_path)
    target = _manifest_path(root)
    monkeypatch.setattr(canary_shield, "IS_WINDOWS", True)
    monkeypatch.setattr(canary_shield, "_ps_json", lambda s, timeout=120: (
        {"events": [_event(image=r"C:\Windows\System32\lsass.exe",
                           target=target)], "error": None}, None))
    out = canary_shield.sweep(root, apply=True, reason="test")
    assert out["killed"] == 0
    assert out["skips"][0]["reason"] == "protected process"


def test_sweep_dry_run_does_not_kill(tmp_path, monkeypatch):
    root = _root(tmp_path)
    target = _manifest_path(root)
    monkeypatch.setattr(canary_shield, "IS_WINDOWS", True)
    monkeypatch.setattr(canary_shield, "IS_WINDOWS", True)
    monkeypatch.setattr(canary_shield, "_ps_json", lambda s, timeout=120: (
        {"events": [_event(target=target)], "error": None}, None))
    monkeypatch.setattr(canary_shield, "_live_process",
                        lambda pid: {"id": pid, "name": "evil"})
    out = canary_shield.sweep(root, apply=False, reason=None)
    assert out["killed"] == 0 and out["dry_run"] is True


def test_sweep_ignores_read_like_events(tmp_path, monkeypatch):
    root = _root(tmp_path)
    target = _manifest_path(root)
    monkeypatch.setattr(canary_shield, "IS_WINDOWS", True)
    monkeypatch.setattr(canary_shield, "_ps_json", lambda s, timeout=120: (
        {"events": [_event(target=target, eid=1)], "error": None}, None))
    out = canary_shield.sweep(root, apply=True, reason="test")
    assert out["matched"] == 0 and out["killed"] == 0


def test_install_requires_plan_and_reason(tmp_path, monkeypatch):
    root = _root(tmp_path)
    dry = canary_shield.install(root)
    assert dry["dry_run"] is True and dry["plan"] == 1
    missing_reason = canary_shield.install(root, apply=True, plan=dry["plan"])
    assert missing_reason["code"] == "REFUSED"
    missing_plan = canary_shield.install(root, apply=True, reason="pilot")
    assert missing_plan["code"] == "REFUSED"


def test_install_apply_writes_config_and_task(tmp_path, monkeypatch):
    root = _root(tmp_path)
    sysroot = tmp_path / "Windows"
    sysroot.mkdir()
    (sysroot / "Sysmon64.exe").write_bytes(b"stub")
    monkeypatch.setenv("SystemRoot", str(sysroot))
    monkeypatch.setattr(canary_shield, "_ps",
                        lambda s, timeout=120: (0, '{"ok":true}'))
    dry = canary_shield.install(root)
    done = canary_shield.install(root, apply=True, plan=dry["plan"],
                                 reason="pilot")
    assert done["installed"] is True
    xml = (root / "tools" / "plasma-sysmon-baseline.xml").read_text()
    assert "FileCreate" in xml and 'onmatch="include"' in xml
    assert (root / "tools" / "plasma-sysmon-pre-shield.xml").exists()


def test_install_without_canaries_is_refused(tmp_path):
    root = tmp_path / "empty"
    (root / "tools").mkdir(parents=True)
    out = canary_shield.install(root)
    assert out["code"] == "NO_CANARIES"


def test_task_action_quotes_root_path(tmp_path):
    root = tmp_path / "plasma root"
    script = canary_shield._task_script(root)
    assert '--root \"' in script
    assert '-Argument' in script and "scheduled canary shield" in script


def test_install_without_existing_config_still_has_a_backup(tmp_path, monkeypatch):
    root = tmp_path / "plasma"
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "plasma.exe").write_bytes(b"stub")
    (root / "tools").mkdir()
    canary.deploy(root, randomize=False, subdir="Finance")
    sysroot = tmp_path / "Windows"
    sysroot.mkdir()
    (sysroot / "Sysmon64.exe").write_bytes(b"stub")
    monkeypatch.setenv("SystemRoot", str(sysroot))
    monkeypatch.setattr(canary_shield, "_ps",
                        lambda s, timeout=120: (0, '{"ok":true}'))
    dry = canary_shield.install(root)
    canary_shield.install(root, apply=True, plan=dry["plan"], reason="pilot")
    backup = root / "tools" / "plasma-sysmon-pre-shield.xml"
    assert backup.exists()
    assert '<FileCreate onmatch="exclude"' in backup.read_text()
