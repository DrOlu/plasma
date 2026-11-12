"""Update-path trust: Authenticode signer pinning before executing an update."""
import subprocess
from types import SimpleNamespace

import pytest

from plasma import cli, update

THUMB = "BC67B990A783702D0C4761D557A58F9AD4534A68"


def _fake_ps(stdout, rc=0):
    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, rc, stdout=stdout, stderr="")
    return fake_run


@pytest.fixture()
def exe(tmp_path):
    p = tmp_path / "plasma-staged.exe"
    p.write_bytes(b"MZ fake")
    return p


def test_signer_match_ok(exe, monkeypatch):
    monkeypatch.setattr(update.shutil, "which", lambda name: "/usr/bin/pwsh")
    monkeypatch.setattr(subprocess, "run",
                        _fake_ps("BC:67:B9:90:A7:83:70:2D:0C:47:61:D5:57:A5:8F:9A:D4:53:4A:68|Valid"))
    res = update.verify_authenticode(exe)
    assert res["ok"] is True
    assert res["status"] == "Valid"


def test_signer_mismatch_refused(exe, monkeypatch):
    monkeypatch.setattr(update.shutil, "which", lambda name: "/usr/bin/pwsh")
    monkeypatch.setattr(subprocess, "run", _fake_ps("DEADBEEF|Valid"))
    res = update.verify_authenticode(exe)
    assert res["ok"] is False
    assert "mismatch" in res["error"]
    assert res["signer"] == "DEADBEEF"
    assert THUMB in res["expected"]


def test_unsigned_exe_refused(exe, monkeypatch):
    monkeypatch.setattr(update.shutil, "which", lambda name: "/usr/bin/pwsh")
    monkeypatch.setattr(subprocess, "run", _fake_ps("NOSIG|NotSigned"))
    res = update.verify_authenticode(exe)
    assert res["ok"] is False
    assert "unsigned" in res["error"]


def test_no_powershell_is_data(exe, monkeypatch):
    monkeypatch.setattr(update.shutil, "which", lambda name: None)
    res = update.verify_authenticode(exe)
    assert res["ok"] is False and "powershell" in res["error"]


def test_env_override_rotates_pins(exe, monkeypatch):
    monkeypatch.setenv("PLASMA_SIGNER_THUMBPRINTS", "AA:BB:CC")
    monkeypatch.setattr(update.shutil, "which", lambda name: "/usr/bin/pwsh")
    monkeypatch.setattr(subprocess, "run", _fake_ps("AABBCC|Valid"))
    assert update.verify_authenticode(exe)["ok"] is True


def test_missing_file(exe, monkeypatch):
    res = update.verify_authenticode(exe.with_name("gone.exe"))
    assert res["ok"] is False and "missing" in res["error"]


def test_apply_refuses_unverified_signer(tmp_path, monkeypatch):
    """The downloaded exe must never be executed on a signer mismatch."""
    monkeypatch.setenv("PLASMA_GH_TOKEN", "tok")
    monkeypatch.setattr(update, "download_and_verify",
                        lambda repo, tag, token, dest: {"ok": True, "tag": "v9.9.9"})
    monkeypatch.setattr(update, "verify_authenticode",
                        lambda p: {"ok": False, "error": "signer thumbprint mismatch"})
    calls = []
    monkeypatch.setattr(cli.subprocess, "run",
                        lambda *a, **k: calls.append(a) or
                        SimpleNamespace(returncode=0, stdout="", stderr=""))
    args = SimpleNamespace(repo="DrOlu/plasma", token_env="PLASMA_GH_TOKEN",
                           root=str(tmp_path), bin=None, allow_unsigned=False)
    assert cli.cmd_update_apply(args) == 2
    assert calls == [], "the staged installer must not run on a bad signature"


def test_apply_dev_override_executes(tmp_path, monkeypatch):
    monkeypatch.setenv("PLASMA_GH_TOKEN", "tok")
    monkeypatch.setattr(update, "download_and_verify",
                        lambda repo, tag, token, dest: {"ok": True, "tag": "v9.9.9"})
    monkeypatch.setattr(update, "verify_authenticode",
                        lambda p: {"ok": False, "error": "unsigned"})
    monkeypatch.setattr(update, "rotate_bin",
                        lambda new, bin_: {"ok": True, "bin": str(bin_)})
    calls = []
    monkeypatch.setattr(cli.subprocess, "run",
                        lambda *a, **k: calls.append(a) or
                        SimpleNamespace(returncode=0, stdout="installed", stderr=""))
    args = SimpleNamespace(repo="DrOlu/plasma", token_env="PLASMA_GH_TOKEN",
                           root=str(tmp_path), bin=None, allow_unsigned=True)
    assert cli.cmd_update_apply(args) == 0
    assert calls and "install" in calls[0][0]


def test_anonymous_api_fetch_has_no_authorization(monkeypatch):
    seen = {}

    class FakeResp:
        status = 200

        def read(self):
            return b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=60):
        seen["headers"] = req.headers
        return FakeResp()

    monkeypatch.setattr(update.urllib.request, "urlopen", fake_urlopen)
    update._gh("https://api.github.com/x", "")
    assert not any(k.lower() == "authorization" for k in seen["headers"])
    update._gh("https://api.github.com/x", "tok")
    assert any(k.lower() == "authorization" for k in seen["headers"])
