"""Named-pipe canaries: registry, task, listener decisions and events."""
from __future__ import annotations

import json

from plasma import canary_pipe, canary_shield


def _root(tmp_path):
    root = tmp_path / "plasma"
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "plasma.exe").write_bytes(b"stub")
    return root


def test_deploy_list_remove(tmp_path):
    root = _root(tmp_path)
    out = canary_pipe.deploy(root, count=2)
    assert out["ok"] and len(out["created"]) == 2
    rows = canary_pipe.list_pipes(root)
    assert rows["count"] == 2
    removed = canary_pipe.remove(root, rows["pipes"][0]["id"])
    assert removed["remaining"] == 1


def test_install_requires_pipes_plan_and_reason(tmp_path):
    root = _root(tmp_path)
    assert canary_pipe.install(root)["code"] == "NO_PIPES"
    canary_pipe.deploy(root)
    dry = canary_pipe.install(root)
    assert dry["dry_run"] is True and dry["plan"] == 1
    assert canary_pipe.install(root, apply=True, plan=dry["plan"])["code"] == \
        "REFUSED"
    assert canary_pipe.install(root, apply=True, reason="pilot")["code"] == \
        "REFUSED"


def test_task_script_quotes_root(tmp_path):
    root = tmp_path / "plasma root"
    script = canary_pipe._task_script(root, tmp_path / "plasma.exe")
    assert '--root \"' in script
    assert "PlasmaCanaryPipe" in script
    assert "-AtStartup" in script


def test_install_apply_registers_task(tmp_path, monkeypatch):
    root = _root(tmp_path)
    canary_pipe.deploy(root)
    monkeypatch.setattr(canary_shield, "_ps",
                        lambda s, timeout=120: (0, '{"ok":true}'))
    dry = canary_pipe.install(root)
    done = canary_pipe.install(root, apply=True, plan=dry["plan"],
                               reason="pilot")
    assert done["installed"] is True
    assert done["task"] == "PlasmaCanaryPipe"


def test_handle_client_kills_unknown_pipe_client(tmp_path, monkeypatch):
    root = _root(tmp_path)
    entry = canary_pipe.deploy(root)["created"][0]
    monkeypatch.setattr(canary_shield, "_live_process",
                        lambda pid: {"id": pid, "name": "evil",
                                     "path": r"C:\Tools\evil.exe"})
    killed = []
    monkeypatch.setattr(canary_shield, "_kill",
                        lambda pid: (killed.append(pid) or {"ok": True}))
    out = canary_pipe._handle_client(root, entry, 1234, True, "drill", 5, [0])
    assert out["decision"] == "killed"
    assert killed == [1234]
    rows = [json.loads(l) for l in
            (root / "data/events.jsonl").read_text().splitlines()]
    assert rows[-1]["source"] == "canary"
    assert rows[-1]["action"] == "blocked"
    journal = [json.loads(l) for l in
               (root / "canary-pipe-journal.jsonl").read_text().splitlines()]
    assert journal[-1]["pipe"] == entry["name"]
    assert journal[-1]["decision"] == "killed"
    assert journal[-1]["pid"] == 1234
    assert journal[-1]["id"] == 1


def test_handle_client_skips_trusted_and_protected(tmp_path, monkeypatch):
    root = _root(tmp_path)
    entry = canary_pipe.deploy(root)["created"][0]
    monkeypatch.setattr(canary_shield, "_kill",
                        lambda pid: {"ok": True})
    monkeypatch.setattr(canary_shield, "_live_process",
                        lambda pid: {"id": pid, "name": "explorer",
                                     "path": r"C:\Windows\explorer.exe"})
    trusted = canary_pipe._handle_client(root, entry, 1, True, "drill", 5, [0])
    assert "trusted" in trusted["decision"]
    monkeypatch.setattr(canary_shield, "_live_process",
                        lambda pid: {"id": pid, "name": "lsass",
                                     "path": r"C:\Windows\System32\lsass.exe"})
    protected = canary_pipe._handle_client(root, entry, 2, True, "drill", 5, [0])
    assert "protected" in protected["decision"]


def test_handle_client_dry_run_does_not_kill(tmp_path, monkeypatch):
    root = _root(tmp_path)
    entry = canary_pipe.deploy(root)["created"][0]
    monkeypatch.setattr(canary_shield, "_live_process",
                        lambda pid: {"id": pid, "name": "evil",
                                     "path": r"C:\Tools\evil.exe"})
    called = []
    monkeypatch.setattr(canary_shield, "_kill",
                        lambda pid: called.append(pid) or {"ok": True})
    out = canary_pipe._handle_client(root, entry, 3, False, None, 5, [0])
    assert out["decision"] == "dry-run"
    assert called == []


def test_serve_unsupported_without_windows(tmp_path, monkeypatch):
    root = _root(tmp_path)
    canary_pipe.deploy(root)
    monkeypatch.setattr(canary_pipe, "_kernel32",
                        lambda: (_ for _ in ()).throw(OSError("no Windows")))
    rc = canary_pipe.serve(root)
    assert rc == 1


def test_status_reports_live_listener_counts(tmp_path):
    root = _root(tmp_path)
    canary_pipe.deploy(root)
    rows = canary_pipe.list_pipes(root)["pipes"]
    canary_pipe._write_state(root, rows, {"connections": 3}, [2], True)
    out = canary_pipe.status(root)
    assert out["pipes"] == 1
    assert out["last_connections"] == 3
    assert out["last_killed"] == 2


def test_install_and_uninstall_use_pipe_journal(tmp_path, monkeypatch):
    root = _root(tmp_path)
    canary_pipe.deploy(root)
    monkeypatch.setattr(canary_shield, "_ps",
                        lambda s, timeout=120: (0, '{"ok":true}'))
    dry = canary_pipe.install(root)
    canary_pipe.install(root, apply=True, plan=dry["plan"], reason="pilot")
    rows = [json.loads(l) for l in
            (root / "canary-pipe-journal.jsonl").read_text().splitlines()]
    assert rows[-1]["kind"] == "pipe-install"
    assert rows[-1]["status"] == "applied"
