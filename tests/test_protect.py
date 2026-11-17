"""Measured protection posture: armed by default, narrow and reversible."""

import json

from plasma import cli, enforce, protect


def test_measured_default_is_armed():
    assert enforce.DEFAULT_POLICY["enabled"] is True
    assert enforce.DEFAULT_POLICY["mode"] == "enforce"
    assert enforce.DEFAULT_POLICY["min_score"] == 9
    assert enforce.DEFAULT_POLICY["allowed_actions"] == ["snapshot", "kill_process"]
    assert "isolate_host" in enforce.DEFAULT_POLICY["require_approval"]
    assert "disable_user" in enforce.DEFAULT_POLICY["require_approval"]
    assert "remove_admin" in enforce.DEFAULT_POLICY["require_approval"]
    assert enforce.DEFAULT_POLICY["watch_task"] == "PlasmaWatch"
    assert enforce.DEFAULT_POLICY["watch_every_minutes"] == 5


def test_load_policy_defaults_to_measured(tmp_path):
    policy = enforce.load_policy(tmp_path)
    assert policy["enabled"] is True
    assert policy["mode"] == "enforce"
    assert policy["allowed_actions"] == ["snapshot", "kill_process"]


def test_load_policy_preserves_custom_operator_block(tmp_path):
    (tmp_path / "config.json").write_text(json.dumps({
        "enforcement": {
            "enabled": False, "mode": "dry-run", "min_score": 9,
            "allowed_actions": ["snapshot"], "require_approval": [],
            "cooldown_minutes": 30, "max_actions_per_run": 2,
        }
    }))
    policy = enforce.load_policy(tmp_path)
    assert policy["enabled"] is False
    assert policy["mode"] == "dry-run"
    assert policy["allowed_actions"] == ["snapshot"]


def test_migrate_legacy_default():
    assert protect.migrate_enforcement(protect.LEGACY_ENFORCEMENT) == \
        protect.MEASURED_ENFORCEMENT


def test_migrate_old_config_without_watch_keys():
    old = {k: protect.LEGACY_ENFORCEMENT[k] for k in protect.LEGACY_KEYS}
    assert protect.migrate_enforcement(old) == protect.MEASURED_ENFORCEMENT


def test_migrate_missing_and_empty():
    assert protect.migrate_enforcement(None) == protect.MEASURED_ENFORCEMENT
    assert protect.migrate_enforcement({}) == protect.MEASURED_ENFORCEMENT


def test_migrate_custom_preserved():
    custom = dict(protect.LEGACY_ENFORCEMENT)
    custom["enabled"] = False
    custom["allowed_actions"] = ["snapshot"]
    result = protect.migrate_enforcement(custom)
    assert result["enabled"] is False
    assert result["allowed_actions"] == ["snapshot"]
    assert result["require_approval"] == ["isolate_host"]


def test_arm_writes_measured_policy(tmp_path):
    result = protect.arm(tmp_path)
    assert result["ok"] is True and result["armed"] is True
    config = json.loads((tmp_path / "config.json").read_text())
    assert config["enforcement"]["enabled"] is True
    assert config["enforcement"]["mode"] == "enforce"
    assert config["enforcement"]["allowed_actions"] == ["snapshot", "kill_process"]


def test_arm_is_idempotent(tmp_path):
    first = protect.arm(tmp_path)
    second = protect.arm(tmp_path)
    assert first["policy"] == second["policy"]
    config = json.loads((tmp_path / "config.json").read_text())
    assert config["enforcement"]["enabled"] is True


def test_disarm_writes_dry_run(tmp_path):
    protect.arm(tmp_path)
    result = protect.disarm(tmp_path, reason="test")
    assert result["ok"] is True and result["armed"] is False
    config = json.loads((tmp_path / "config.json").read_text())
    assert config["enforcement"]["enabled"] is False
    assert config["enforcement"]["mode"] == "dry-run"


def test_status_shape(tmp_path):
    result = protect.status(tmp_path)
    assert result["ok"] is True
    assert result["armed"] is True
    assert result["detection"]["enabled"] is True
    assert result["containment"]["allowed_actions"] == ["snapshot", "kill_process"]
    assert "isolate_host" in result["containment"]["require_approval"]
    assert result["containment"]["watch_task"] == "PlasmaWatch"


def test_protected_lists():
    protected = protect.protected()
    assert "winrm" in protected["services"]
    assert "termservice" in protected["services"]
    assert "whids" in protected["services"]
    assert "sysmon" in protected["services"]
    assert "lsass.exe" in protected["processes"]
    assert "administrator" in protected["accounts"]
    assert "system" in protected["accounts"]
    assert protected["paths"]


def test_proposals_score_floor_and_isolation():
    policy = dict(enforce.DEFAULT_POLICY)
    high = enforce.proposals([{
        "type": "injection", "score": 9, "technique": "T1055",
        "pid": 4242, "detail": "remote thread",
    }], policy)
    assert high and high[0]["action"] == "kill_process"
    assert high[0]["eligible"] is True

    low = enforce.proposals([{
        "type": "injection", "score": 8, "technique": "T1055",
        "pid": 4242, "detail": "remote thread",
    }], policy)
    assert low and low[0]["eligible"] is False
    assert any("score 8 below min 9" in r for r in low[0]["reasons"])

    canary = enforce.proposals([{
        "type": "canary_tripped", "score": 9, "detail": "impact",
    }], policy)
    assert canary and canary[0]["action"] == "isolate_host"
    assert canary[0]["mode"] == "pending_approval"
    assert canary[0]["eligible"] is False


def test_run_measured_policy_snapshot_then_kill(tmp_path, monkeypatch):
    calls = []

    def fake_execute(action, root=None, target=None, reason=None, apply=False,
                     plan=None, timeout=60):
        calls.append((action, target, apply, plan))
        if action == "snapshot":
            return ({"id": 1, "mode": "applied", "ok": True}
                    if apply else {"id": 1, "mode": "dry-run"})
        if action == "kill_process":
            return ({"id": 2, "mode": "applied", "ok": True}
                    if apply else {"id": 2, "mode": "dry-run"})
        return {"error": "unexpected action"}

    monkeypatch.setattr(enforce.actuate, "execute", fake_execute)
    result = enforce.run(tmp_path, findings=[{
        "type": "injection_chain", "score": 9, "technique": "T1055",
        "pid": 4242, "detail": "remote thread",
    }], apply=True)
    assert result["applied"] == 1
    assert result["capture_ok"] is True
    assert result["capture"]["status"] == "applied"
    assert calls[0][0] == "snapshot" and calls[0][2] is False
    assert calls[1][0] == "snapshot" and calls[1][2] is True
    assert calls[2][0] == "kill_process" and calls[2][2] is False
    assert calls[3][0] == "kill_process" and calls[3][2] is True


def test_run_isolation_stays_pending(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(enforce.actuate, "execute",
                        lambda *a, **k: calls.append((a, k)) or {"error": "should not run"})
    result = enforce.run(tmp_path, findings=[{
        "type": "canary_tripped", "score": 9, "detail": "impact",
    }], apply=True)
    assert result["applied"] == 0
    assert result["pending"] == 1
    assert calls == []


def test_cli_protect_status_arm_disarm(tmp_path, capsys):
    assert cli.main(["protect", "status", "--root", str(tmp_path)]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["armed"] is True

    assert cli.main(["protect", "disarm", "--root", str(tmp_path)]) == 0
    disarmed = json.loads(capsys.readouterr().out)
    assert disarmed["armed"] is False

    assert cli.main(["protect", "arm", "--root", str(tmp_path)]) == 0
    armed = json.loads(capsys.readouterr().out)
    assert armed["armed"] is True


def test_install_parser_has_autoprotect_switch():
    parser = cli.build_parser()
    default = parser.parse_args(["install", "--dry-run"])
    assert default.no_autoprotect is False
    opted_out = parser.parse_args(["install", "--dry-run", "--no-autoprotect"])
    assert opted_out.no_autoprotect is True
