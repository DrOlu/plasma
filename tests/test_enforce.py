"""Tier 0 containment: proposals, policy gates, approvals, cooldowns."""
import json

import pytest

from plasma import enforce


def injection_finding(pid=4321, score=9, technique="T1055.001"):
    return {"type": "whids_high_criticality", "score": score,
            "detail": "dll injection", "pid": pid, "user": "CORP\\olu",
            "process": "loader.exe", "technique": technique}


def chain_finding(pid=99, score=9):
    return {"type": "chain_injection_chain", "score": score,
            "detail": "rwx then remote thread",
            "events": [{"process": "loader.exe", "pid": None},
                       {"process": "loader.exe", "pid": pid}]}


def canary_finding():
    return {"type": "canary_tripped", "score": 10,
            "detail": "canary modified: C:\\Decoys\\payroll.xlsx",
            "path": "C:\\Decoys\\payroll.xlsx", "reason": "modified"}


def policy(**over):
    base = dict(enforce.DEFAULT_POLICY)
    base["enabled"] = True
    base["mode"] = "enforce"
    base.update(over)
    return base


def test_default_policy_is_off_and_dry_run():
    assert enforce.DEFAULT_POLICY["enabled"] is False
    assert enforce.DEFAULT_POLICY["mode"] == "dry-run"


def test_injection_proposes_kill_and_is_auto_eligible():
    out = enforce.proposals([injection_finding()], policy())
    assert len(out) == 1
    p = out[0]
    assert p["action"] == "kill_process" and p["target"] == "4321"
    assert p["eligible"] is True and p["mode"] == "auto"


def test_chain_injection_uses_the_last_pid():
    out = enforce.proposals([chain_finding(pid=99)], policy())
    assert out[0]["action"] == "kill_process" and out[0]["target"] == "99"


def test_canary_requires_approval_by_default():
    out = enforce.proposals([canary_finding()], policy())
    assert out[0]["action"] == "isolate_host"
    assert out[0]["mode"] == "pending_approval"
    assert out[0]["eligible"] is False


def test_score_threshold_and_technique_deny_block_eligibility():
    low = enforce.proposals([injection_finding(score=7)], policy())
    assert low[0]["eligible"] is False
    denied = enforce.proposals([injection_finding()],
                               policy(deny_techniques=["T1055.001"]))
    assert denied[0]["eligible"] is False
    assert any("denied" in r for r in denied[0]["reasons"])


def test_action_not_in_any_list_is_not_proposed_for_execution():
    out = enforce.proposals([injection_finding()],
                            policy(allowed_actions=[], require_approval=[]))
    assert out[0]["eligible"] is False
    assert any("not allowlisted" in r for r in out[0]["reasons"])


def test_run_with_policy_off_journals_dry_run(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(enforce.actuate, "execute",
                        lambda *a, **k: calls.append(k) or {"id": 1})
    out = enforce.run(tmp_path, findings=[injection_finding()])
    assert out["applied"] == 0 and out["dry_run"] == 1
    assert calls == []
    rows = enforce._read_journal(tmp_path)
    assert rows[0]["status"] == "dry-run"


def test_armed_run_applies_through_dry_run_plan(tmp_path, monkeypatch):
    calls = []

    def fake(action, root, target=None, reason=None, apply=False, plan=None):
        calls.append({"action": action, "target": target, "apply": apply,
                      "plan": plan})
        return {"id": 7} if not apply else {"id": 7, "verification": "ok"}

    monkeypatch.setattr(enforce.actuate, "execute", fake)
    cfg = {"enforcement": {"enabled": True, "mode": "enforce"}}
    (tmp_path / "config.json").write_text(json.dumps(cfg))
    out = enforce.run(tmp_path, findings=[injection_finding()])
    assert out["applied"] == 1
    assert out["capture"]["status"] == "applied"
    assert calls == [
        {"action": "snapshot", "target": None, "apply": False, "plan": None},
        {"action": "snapshot", "target": None, "apply": True, "plan": 7},
        {"action": "kill_process", "target": "4321", "apply": False, "plan": None},
        {"action": "kill_process", "target": "4321", "apply": True, "plan": 7},
    ]
    rows = enforce._read_journal(tmp_path)
    assert [r["status"] for r in rows] == ["applied", "applied"]
    assert rows[0]["type"] == "capture" and rows[1]["plan"] == 7


def test_per_run_cap_and_cooldown(tmp_path, monkeypatch):
    def fake(action, root, target=None, reason=None, apply=False, plan=None):
        return {"id": 1} if not apply else {"id": 1}

    monkeypatch.setattr(enforce.actuate, "execute", fake)
    (tmp_path / "config.json").write_text(json.dumps(
        {"enforcement": {"enabled": True, "mode": "enforce"}}))
    findings = [injection_finding(pid=1), injection_finding(pid=2),
                injection_finding(pid=3)]
    out = enforce.run(tmp_path, findings=findings)
    assert out["applied"] == 2                       # max_actions_per_run=2
    later = enforce.run(tmp_path, findings=[injection_finding(pid=1)], apply=True)
    statuses = [r["status"] for r in later["results"]]
    assert "skipped" in statuses


def test_approval_flow(tmp_path, monkeypatch):
    calls = []

    def fake(action, root, target=None, reason=None, apply=False, plan=None):
        calls.append(apply)
        return {"id": 11, "payload": "x"} if not apply else {"id": 11}

    monkeypatch.setattr(enforce.actuate, "execute", fake)
    cfg = {"enforcement": {"enabled": True, "mode": "enforce"}}
    (tmp_path / "config.json").write_text(json.dumps(cfg))
    out = enforce.run(tmp_path, findings=[canary_finding()])
    assert out["pending"] == 1 and out["applied"] == 0
    entry = enforce.pending(tmp_path)["pending"][0]
    res = enforce.approve(tmp_path, entry["id"], apply=True)
    assert res["applied"] is True and calls == [False, True]


def test_config_invalid_values_fall_back(tmp_path):
    (tmp_path / "config.json").write_text(json.dumps(
        {"enforcement": {"mode": "nonsense", "min_score": 99,
                         "allowed_actions": "kill_process"}}))
    p = enforce.load_policy(tmp_path)
    assert p["mode"] == "dry-run" and p["min_score"] == 10
    assert p["allowed_actions"] == []


def test_default_policy_captures_before_it_kills():
    """Kill is the only irreversible mutating action; capture comes first."""
    assert enforce.DEFAULT_POLICY["allowed_actions"] == ["snapshot",
                                                        "kill_process"]
    assert "kill_process" not in enforce.DEFAULT_POLICY["require_approval"]


def test_capture_runs_once_for_multiple_kills(tmp_path, monkeypatch):
    calls = []

    def fake(action, root, target=None, reason=None, apply=False, plan=None):
        calls.append((action, apply))
        return {"id": 1} if not apply else {"id": 1}

    monkeypatch.setattr(enforce.actuate, "execute", fake)
    (tmp_path / "config.json").write_text(json.dumps(
        {"enforcement": {"enabled": True, "mode": "enforce"}}))
    enforce.run(tmp_path, findings=[injection_finding(pid=1),
                                    injection_finding(pid=2)])
    assert [c for c in calls if c[0] == "snapshot"] == [
        ("snapshot", False), ("snapshot", True)]


def test_capture_failure_does_not_block_containment(tmp_path, monkeypatch):
    def fake(action, root, target=None, reason=None, apply=False, plan=None):
        if action == "snapshot" and apply:
            return {"error": "snapshot failed"}
        return {"id": 1} if not apply else {"id": 1}

    monkeypatch.setattr(enforce.actuate, "execute", fake)
    (tmp_path / "config.json").write_text(json.dumps(
        {"enforcement": {"enabled": True, "mode": "enforce"}}))
    out = enforce.run(tmp_path, findings=[injection_finding()])
    assert out["capture"]["status"] == "failed"
    assert out["applied"] == 1
    assert out["results"][0]["capture"] == "failed"


def test_capture_is_skipped_when_not_allowlisted(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(enforce.actuate, "execute",
                        lambda *a, **k: calls.append(a[0]) or {"id": 1})
    (tmp_path / "config.json").write_text(json.dumps(
        {"enforcement": {"enabled": True, "mode": "enforce",
                         "allowed_actions": ["kill_process"]}}))
    out = enforce.run(tmp_path, findings=[injection_finding()])
    assert out["capture"]["status"] == "skipped"
    assert calls == ["kill_process", "kill_process"]
