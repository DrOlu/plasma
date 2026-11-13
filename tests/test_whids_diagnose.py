"""WHIDS init-hang diagnosis: data, not guesses."""
import json
import subprocess

from plasma import whids


def _fake_run(payload):
    def fake(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(payload), stderr="")
    return fake


def test_diagnose_reports_hang_and_unreadable_channel(tmp_path, monkeypatch):
    root = tmp_path / "Whids"
    (root / "Logs").mkdir(parents=True)
    (root / "config.toml").write_text("channels = []\n")
    (root / "Logs" / "whids.log").write_text("start\nstill starting\n")
    exe = tmp_path / "whids.exe"
    exe.write_bytes(b"MZ")

    monkeypatch.setattr(whids, "_whids_service_name", lambda: "Whids")
    monkeypatch.setattr(whids.subprocess, "run", _fake_run({
        "state": "StartPending",
        "startMode": "Auto",
        "pathName": f'"{exe}" -c config.toml',
        "hang": True,
        "channels": [
            {"log": "Microsoft-Windows-Sysmon/Operational", "enabled": True,
             "records": 120},
            {"log": "Security", "enabled": False, "records": 0},
        ],
        "serviceErrors": ["2026-11-12 id=7009: timeout"],
    }))
    res = whids.diagnose(root)
    assert res["service_state"] == "StartPending"
    assert res["config_present"] is True
    assert res["binary_present"] is True
    assert any("StartPending" in f for f in res["findings"])
    assert any("Security" in f for f in res["findings"])
    assert res["log_tail"][-1] == "still starting"


def test_diagnose_missing_config_and_binary(tmp_path, monkeypatch):
    root = tmp_path / "Whids"
    root.mkdir()
    monkeypatch.setattr(whids, "_whids_service_name", lambda: "Whids")
    monkeypatch.setattr(whids.subprocess, "run", _fake_run({
        "state": "Stopped", "startMode": "Auto",
        "pathName": '"C:\\Program Files\\Whids\\missing.exe"',
        "hang": False, "channels": [], "serviceErrors": [],
    }))
    res = whids.diagnose(root)
    findings = " ".join(res["findings"])
    assert "config.toml missing" in findings
    assert "binary path does not exist" in findings


def test_diagnose_probe_failure_is_data(tmp_path, monkeypatch):
    monkeypatch.setattr(whids, "_whids_service_name", lambda: "Whids")

    def boom(cmd, **kw):
        raise OSError("no powershell")
    monkeypatch.setattr(whids.subprocess, "run", boom)
    res = whids.diagnose(tmp_path)
    assert any("service probe failed" in f for f in res["findings"])


def test_diagnose_without_service(tmp_path, monkeypatch):
    monkeypatch.setattr(whids, "_whids_service_name", lambda: None)
    res = whids.diagnose(tmp_path)
    assert res["service"] is None
    assert res["findings"]
