"""DTrace integration: reviewed scripts, bounded runs, normalized rows."""
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from plasma import trace

REPO_SCRIPTS = Path(__file__).resolve().parent.parent / "sensors" / "dtrace"


# ---------------------------------------------------------------------------
# script library
# ---------------------------------------------------------------------------

def test_repo_scripts_load_with_metadata():
    scripts = trace.load_scripts()
    names = {s["name"] for s in scripts}
    assert {"syscall-errors", "process-create", "etw-kernel-process"} <= names
    for s in scripts:
        assert s["technique"].startswith("T")
        assert 0 <= s["score"] <= 10
        assert s["providers"]
        assert len(s["sha256"]) == 64


def test_scripts_are_safe_and_emit_the_marker():
    for path in sorted(REPO_SCRIPTS.glob("*.d")):
        text = path.read_text()
        assert trace.MARKER in text
        assert "system(" not in text
        assert "-w" not in text


def test_predicates_are_terminated():
    """A predicate line must close with '/'; process-create shipped without
    it and the Windows compiler rejected the script (field-found on WS1)."""
    for path in sorted(REPO_SCRIPTS.glob("*.d")):
        for number, line in enumerate(path.read_text().splitlines(), 1):
            text = line.strip()
            if text.startswith("/") and not text.startswith("/*"):
                assert text.endswith("/"), f"{path.name}:{number}: {text}"


def test_scripts_emit_pid_and_tid():
    """DTrace 2.0 can read pid; tid is kept for thread-level correlation.
    (The old Sun D 1.13.1 preview raised 'invalid user access' for pid.)"""
    for path in sorted(REPO_SCRIPTS.glob("*.d")):
        text = path.read_text()
        assert "\\\"pid\\\"" in text, path.name
        assert "\\\"tid\\\"" in text, path.name
        assert "pid," in text, path.name


def test_validate_rejects_system_call():
    with pytest.raises(trace.ScriptError, match="system"):
        trace.validate_script('syscall:::entry { system("cmd /c calc"); }', "x")


def test_validate_rejects_missing_marker():
    with pytest.raises(trace.ScriptError, match="prefixed"):
        trace.validate_script("syscall:::entry { printf(\"nope\\n\"); }", "x")


def test_validate_rejects_unknown_provider():
    with pytest.raises(trace.ScriptError, match="provider"):
        trace.validate_script('mock:::entry { printf("plasma|{}"); }', "x")


def test_validate_rejects_bad_score():
    text = '/* score: eleven */\nsyscall:::entry { printf("plasma|{}"); }\n'
    with pytest.raises(trace.ScriptError, match="score"):
        trace.validate_script(text, "x")


def test_validate_accepts_the_shipped_shape():
    text = ('/* name: t */\n/* technique: T1059 */\n/* score: 5 */\n'
            'syscall:::entry { printf("plasma|{\\"pid\\":%d}\\n", pid); }\n')
    info = trace.validate_script(text, "t")
    assert info["name"] == "t" and info["score"] == 5
    assert info["providers"] == ["syscall"]


# ---------------------------------------------------------------------------
# output parsing + normalization
# ---------------------------------------------------------------------------

def test_parse_output_ignores_noise_and_bad_json():
    text = (
        "dtrace: description matched 1 probe\n"
        "CPU ID FUNCTION:NAME\n"
        'plasma|{"probe":"syscall_error","pid":42,"comm":"cmd.exe"}\n'
        "plasma|not json\n"
        'leading noise plasma|{"probe":"x","pid":7,"comm":"a.exe"}\n'
    )
    rows = trace.parse_output(text)
    assert [r["pid"] for r in rows] == [42, 7]


def test_parse_output_caps_rows():
    text = "\n".join(f'plasma|{{"n":{i}}}' for i in range(100))
    assert len(trace.parse_output(text, max_rows=10)) == 10


def test_normalize_tid_only_row():
    """Windows DTrace cannot read pid; tid is carried in the description."""
    info = {"name": "syscall-errors", "score": 6, "technique": "T1106"}
    ev = trace.normalize({"probe": "syscall_error", "tid": 42,
                          "comm": "cmd.exe", "func": "NtOpenFile"},
                         info, "HOST1")
    assert ev.get("pid") is None
    assert "tid" in ev["description"] and "42" in ev["description"]


def test_normalize_contract():
    info = {"name": "syscall-errors", "score": 6, "technique": "T1106"}
    ev = trace.normalize({"probe": "syscall_error", "pid": 42,
                          "comm": "cmd.exe", "func": "NtOpenFile",
                          "status": "0xC0000022"}, info, "HOST1")
    assert ev["kind"] == "trace" and ev["source"] == "dtrace"
    assert ev["host"] == "HOST1" and ev["pid"] == 42
    assert ev["process"] == "cmd.exe"
    assert ev["score"] == 0.6 and ev["severity"] == "medium"
    assert ev["technique"] == "T1106"
    assert "syscall_error" in ev["description"]
    assert "NtOpenFile" in ev["description"]


# ---------------------------------------------------------------------------
# check / selftest / provision (mocked host)
# ---------------------------------------------------------------------------

def test_scripts_dir_resolves_frozen_bundle(tmp_path, monkeypatch):
    """v1.5.0 omitted sensors/dtrace from the bundle, so installed nodes
    could not list, selftest or run a single script."""
    scripts = tmp_path / "embedded" / "sensors" / "dtrace"
    scripts.mkdir(parents=True)
    (scripts / "probe.d").write_text(
        '/* name: probe */\n/* technique: T1059 */\n/* score: 5 */\n'
        'syscall:::entry { printf("plasma|{\\"pid\\":%d}\\n", pid); }\n')
    monkeypatch.setattr("sys._MEIPASS", str(tmp_path), raising=False)
    monkeypatch.chdir(tmp_path)
    assert trace._scripts_dir() == scripts
    assert trace.load_scripts()[0]["name"] == "probe"


def test_find_dtrace_falls_back_to_install_dir(tmp_path, monkeypatch):
    """Microsoft.DTrace's MSI does not touch PATH; WS2 had it installed at
    C:\\Program Files\\DTrace\\dtrace.EXE and `trace check` said missing."""
    monkeypatch.setattr(trace.shutil, "which", lambda name: None)
    monkeypatch.setenv("ProgramFiles", str(tmp_path))
    (tmp_path / "DTrace").mkdir()
    exe = tmp_path / "DTrace" / "dtrace.exe"
    exe.write_text("")
    assert trace.find_dtrace() == str(exe)


def test_check_missing_dtrace(monkeypatch):
    monkeypatch.setattr(trace, "find_dtrace", lambda: None)
    res = trace.check()
    assert res["available"] is False
    assert "Server 2025" in res["hint"]


def test_check_enabled(monkeypatch):
    monkeypatch.setattr(trace.shutil, "which", lambda name: "/usr/bin/dtrace")
    calls = []

    def fake_ps(script, timeout=60):
        calls.append(script)
        if "-V" in script:
            return "dtrace: version 2.0"
        return "dtrace on"
    monkeypatch.setattr(trace, "_run_ps", fake_ps)
    res = trace.check()
    assert res["available"] and res["enabled"] is True
    assert "2.0" in res["version"]


def test_check_parses_bcdedit_yes(monkeypatch):
    """bcdedit /enum prints 'dtrace Yes' (WS1 after provision)."""
    monkeypatch.setattr(trace, "find_dtrace", lambda: "/usr/bin/dtrace")
    monkeypatch.setattr(trace, "_run_ps",
                        lambda s, timeout=60: "dtrace   Yes" if "bcdedit" in s else "dtrace: v2.0.0")
    res = trace.check()
    assert res["available"] and res["enabled"] is True
    assert res["hint"] is None


def test_check_parses_bcdedit_no(monkeypatch):
    monkeypatch.setattr(trace, "find_dtrace", lambda: "/usr/bin/dtrace")
    monkeypatch.setattr(trace, "_run_ps",
                        lambda s, timeout=60: "dtrace   No" if "bcdedit" in s else "v2")
    res = trace.check()
    assert res["enabled"] is False and "provision" in res["hint"]


def test_check_installed_not_enabled(monkeypatch):
    monkeypatch.setattr(trace.shutil, "which", lambda name: "/usr/bin/dtrace")
    monkeypatch.setattr(trace, "_run_ps",
                        lambda s, timeout=60: "dtrace off" if "bcdedit" in s else "")
    res = trace.check()
    assert res["available"] and res["enabled"] is False
    assert "provision" in res["hint"]


def test_check_absent_boot_setting_hint(monkeypatch):
    monkeypatch.setattr(trace.shutil, "which", lambda name: "/usr/bin/dtrace")
    monkeypatch.setattr(trace, "_run_ps",
                        lambda s, timeout=60: "" if "bcdedit" in s else "v2")
    res = trace.check()
    assert res["enabled"] is False
    assert "absent" in res["hint"] and "provision" in res["hint"]


def test_selftest_reports_per_script(tmp_path, monkeypatch):
    scripts = tmp_path / "sensors" / "dtrace"
    scripts.mkdir(parents=True)
    (scripts / "a.d").write_text(
        '/* name: a */\n/* technique: T1059 */\n/* score: 5 */\n'
        'syscall:::entry { printf("plasma|{\\"pid\\":%d}\\n", pid); }\n')
    monkeypatch.setattr(trace.shutil, "which", lambda name: "/usr/bin/dtrace")

    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
    monkeypatch.setattr(trace.subprocess, "run", fake_run)
    res = trace.selftest(tmp_path)
    assert res["ok"] is True
    assert res["scripts"][0]["script"] == "a"


def test_provision_already_ready(monkeypatch):
    monkeypatch.setattr(trace, "check",
                        lambda: {"available": True, "enabled": True,
                                 "version": "dtrace: v2.0.0"})
    res = trace.provision()
    assert res["ok"] is True and res.get("already")


def test_provision_enables_and_requires_restart(monkeypatch):
    monkeypatch.setattr(trace, "check",
                        lambda: {"available": True, "enabled": False,
                                 "version": "dtrace: v2.0.0"})
    seen = []
    monkeypatch.setattr(trace, "_run_ps",
                        lambda s, timeout=60: seen.append(s) or "ok")
    res = trace.provision()
    assert res["ok"] and res["reboot_required"] is True
    assert any("bcdedit" in s for s in seen)


def test_provision_winget_path(monkeypatch):
    states = [{"available": False, "enabled": False},
              {"available": True, "enabled": False,
               "version": "dtrace: v2.0.0"}]
    monkeypatch.setattr(trace, "check", lambda: states.pop(0))
    monkeypatch.setattr(trace.shutil, "which",
                        lambda name: "/usr/bin/winget" if name == "winget" else None)
    runs = []

    def fake_run(cmd, **kw):
        runs.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="installed", stderr="")
    monkeypatch.setattr(trace.subprocess, "run", fake_run)
    monkeypatch.setattr(trace, "_run_ps", lambda s, timeout=60: "ok")
    res = trace.provision()
    assert res["ok"]
    assert any("winget" in " ".join(map(str, r)) for r in runs)


def test_provision_without_winget_uses_msi(monkeypatch):
    """Server 2022 has no winget; provision downloads the official MSI."""
    states = [{"available": False, "enabled": False},
              {"available": True, "enabled": False,
               "version": "dtrace: v2.0.0"}]
    monkeypatch.setattr(trace, "check", lambda: states.pop(0))
    monkeypatch.setattr(trace.shutil, "which", lambda name: None)
    seen = []
    monkeypatch.setattr(trace, "_install_msi",
                        lambda d: seen.append(str(d)) or {"ok": True, "rc": 0})
    monkeypatch.setattr(trace, "_run_ps", lambda s, timeout=60: "ok")
    res = trace.provision()
    assert res["ok"] and seen
    assert any(a["action"] == "install DTrace 2.0 MSI" for a in res["actions"])


def test_provision_upgrades_v1_via_msi(monkeypatch):
    """A Sun D 1.13.1 install is upgraded, not treated as ready."""
    states = [{"available": True, "enabled": True,
               "version": "dtrace: Sun D 1.13.1"},
              {"available": True, "enabled": True,
               "version": "dtrace: v2.0.0"}]
    monkeypatch.setattr(trace, "check", lambda: states.pop(0))
    monkeypatch.setattr(trace.shutil, "which", lambda name: None)
    monkeypatch.setattr(trace, "_install_msi", lambda d: {"ok": True, "rc": 0})
    monkeypatch.setattr(trace, "_run_ps", lambda s, timeout=60: "ok")
    res = trace.provision()
    assert res["ok"] and res["reboot_required"] is True
    assert any(a["action"] == "install DTrace 2.0 MSI" for a in res["actions"])


def test_provision_msi_failure_reports_manual(monkeypatch):
    monkeypatch.setattr(trace, "check",
                        lambda: {"available": False, "enabled": False})
    monkeypatch.setattr(trace.shutil, "which", lambda name: None)
    monkeypatch.setattr(trace, "_install_msi",
                        lambda d: {"ok": False, "error": "download failed"})
    res = trace.provision()
    assert res["ok"] is False
    assert "download.microsoft.com" in res["manual"]


# ---------------------------------------------------------------------------
# bounded run (mocked process)
# ---------------------------------------------------------------------------

class _FakeProc:
    def __init__(self, stdout, timeout_once=False):
        self._stdout = stdout
        self._timeout_once = timeout_once
        self.killed = False

    def communicate(self, timeout=None):
        if self._timeout_once:
            self._timeout_once = False
            raise subprocess.TimeoutExpired("dtrace", timeout)
        return self._stdout, ""

    def kill(self):
        self.killed = True


def _patch_run(monkeypatch, proc):
    monkeypatch.setattr(trace.shutil, "which", lambda name: "/usr/bin/dtrace")
    monkeypatch.setattr(trace.subprocess, "Popen",
                        lambda *a, **k: proc)


def test_run_normalizes_writes_and_dedupes(tmp_path, monkeypatch):
    out = ('dtrace: matched\n'
           'plasma|{"probe":"syscall_error","pid":42,"comm":"cmd.exe"}\n'
           'plasma|{"probe":"syscall_error","pid":43,"comm":"powershell.exe"}\n')
    _patch_run(monkeypatch, _FakeProc(out))
    events = tmp_path / "events.jsonl"
    raw = tmp_path / "capture.jsonl"
    res = trace.run("syscall-errors", events, seconds=2, out=raw, host="H1")
    assert res["rows"] == 2 and res["written"] == 2
    lines = events.read_text().strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["kind"] == "trace"
    assert raw.exists() and len(raw.read_text().strip().splitlines()) == 2

    # a second identical run adds nothing (content-hash dedupe)
    _patch_run(monkeypatch, _FakeProc(out))
    res2 = trace.run("syscall-errors", events, seconds=2, host="H1")
    assert res2["written"] == 0


def test_run_kills_after_window(tmp_path, monkeypatch):
    proc = _FakeProc('plasma|{"pid":1,"comm":"a.exe","probe":"x"}\n',
                     timeout_once=True)
    _patch_run(monkeypatch, proc)
    res = trace.run("syscall-errors", tmp_path / "e.jsonl", seconds=1)
    assert res["killed"] is True and proc.killed
    assert res["rows"] == 1


def test_run_rejects_unknown_script(tmp_path, monkeypatch):
    monkeypatch.setattr(trace.shutil, "which", lambda name: "/usr/bin/dtrace")
    res = trace.run("nope", tmp_path / "e.jsonl")
    assert "error" in res and "unknown script" in res["error"]


def test_run_rejects_bad_window(tmp_path, monkeypatch):
    monkeypatch.setattr(trace.shutil, "which", lambda name: "/usr/bin/dtrace")
    res = trace.run("syscall-errors", tmp_path / "e.jsonl", seconds=999)
    assert "error" in res


def test_run_without_dtrace(tmp_path, monkeypatch):
    monkeypatch.setattr(trace, "find_dtrace", lambda: None)
    res = trace.run("syscall-errors", tmp_path / "e.jsonl")
    assert "error" in res and "not installed" in res["error"]
