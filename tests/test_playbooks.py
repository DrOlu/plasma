"""Playbooks: plan-gated sequences of allowlisted actions, abort + undo."""
import json

import pytest

from plasma import actuate, playbooks


@pytest.fixture()
def mock_run(monkeypatch):
    """Canned _run responder: everything succeeds; return the calls list."""
    calls = []

    def fake_run(payload, timeout=60):
        calls.append(payload)
        return {"rc": 0, "output": "ok", "output_head": "ok"}

    monkeypatch.setattr(actuate, "_run", fake_run)
    return calls


def _root(tmp_path):
    return tmp_path / "plasma"


def test_actions_listing():
    actions = playbooks.actions()
    assert "contain-user" in actions and "isolate-box" in actions


def test_playbook_requires_target_when_steps_need_one(tmp_path, mock_run):
    res = playbooks.execute(_root(tmp_path), "contain-user", reason="x")
    assert "error" in res and "target" in res["error"]


def test_playbook_dry_run_journals_step_plans_and_never_runs(tmp_path, mock_run):
    root = _root(tmp_path)
    dry = playbooks.execute(root, "contain-user", target="bob", reason="insider")
    assert dry["mode"] == "dry-run"
    assert [s["action"] for s in dry["steps"]] == ["disable_user", "snapshot"]
    assert all("plan" in s for s in dry["steps"])
    assert dry["rendered"][0]["payload"].startswith("Disable-LocalUser")
    assert mock_run == []                      # nothing executed
    # journal: two step dry-runs + the playbook dry-run
    modes = [(r["action"], r["mode"]) for r in actuate.journal_read(root)]
    assert modes == [("disable_user", "dry-run"), ("snapshot", "dry-run"),
                     ("playbook:contain-user", "dry-run")]


def test_playbook_apply_requires_plan(tmp_path, mock_run):
    res = playbooks.execute(_root(tmp_path), "contain-user", target="bob",
                            reason="x", apply=True)
    assert "error" in res and "--plan" in res["error"]
    assert mock_run == []


def test_playbook_apply_refuses_wrong_target(tmp_path, mock_run):
    root = _root(tmp_path)
    dry = playbooks.execute(root, "contain-user", target="bob", reason="x")
    res = playbooks.execute(root, "contain-user", target="alice",
                            reason="x", apply=True, plan=dry["id"])
    assert "error" in res and "target" in res["error"]
    assert mock_run == []


def test_playbook_apply_runs_steps_in_order(tmp_path, mock_run):
    root = _root(tmp_path)
    dry = playbooks.execute(root, "contain-user", target="bob", reason="insider")
    applied = playbooks.execute(root, "contain-user", target="bob",
                                reason="insider", apply=True, plan=dry["id"])
    assert applied["mode"] == "applied"
    assert all(s.get("ok") for s in applied["steps"])
    # disable_user payload ran before snapshot payload
    assert mock_run[0].startswith("Disable-LocalUser")
    assert "snapshot-" in mock_run[2]
    # journal: 3 dry-runs + 2 step applies + playbook applied
    rows = actuate.journal_read(root)
    assert [r["mode"] for r in rows][-3:] == ["applied", "applied", "applied"]
    assert rows[-1]["action"] == "playbook:contain-user"
    assert rows[-1]["plan"] == dry["id"]


def test_playbook_aborts_on_failing_step(tmp_path, monkeypatch):
    root = _root(tmp_path)
    calls = []

    def fake_run(payload, timeout=60):
        calls.append(payload)
        if "Get-ScheduledTask" in payload or "Export-ScheduledTask" in payload \
                or "$out.host" in payload or "auditpol" in payload:
            return {"rc": 1, "output": "", "output_head": "",
                    "stderr": "snapshot refused"}
        return {"rc": 0, "output": "False", "output_head": "False"}

    monkeypatch.setattr(actuate, "_run", fake_run)
    dry = playbooks.execute(root, "contain-user", target="bob", reason="x")
    applied = playbooks.execute(root, "contain-user", target="bob",
                                reason="x", apply=True, plan=dry["id"])
    assert applied["aborted_at"] == "snapshot"
    assert applied["steps"][0]["ok"] is True          # disable_user ran
    assert applied["steps"][1]["ok"] is False
    journal = actuate.journal_read(root)
    assert any(r.get("aborted_at") == "snapshot" for r in journal)


def test_playbook_undo_reverses_succeeded_steps_last_first(tmp_path, mock_run):
    root = _root(tmp_path)
    dry = playbooks.execute(root, "contain-user", target="bob", reason="x")
    applied = playbooks.execute(root, "contain-user", target="bob",
                                reason="x", apply=True, plan=dry["id"])
    n_calls = len(mock_run)
    undone = playbooks.undo(root, applied["id"], apply=True)
    assert undone["mode"] == "applied"
    # reverse order: snapshot (latest step, not undoable) is skipped first...
    assert undone["steps"][0]["step"] == "snapshot"
    assert undone["steps"][0].get("skipped") == "step is not undoable"
    # ...then disable_user's enable actually runs
    assert undone["steps"][1]["step"] == "disable_user"
    assert mock_run[n_calls].startswith("Enable-LocalUser")
    # summary journaled
    journal = actuate.journal_read(root)
    assert journal[-1]["action"] == "undo:playbook:contain-user"


def test_playbook_undo_refuses_dry_run_entries(tmp_path, mock_run):
    root = _root(tmp_path)
    dry = playbooks.execute(root, "contain-user", target="bob", reason="x")
    res = playbooks.undo(root, dry["id"], apply=True)
    assert "error" in res


def test_playbook_undo_of_plain_action_refused(tmp_path, mock_run):
    root = _root(tmp_path)
    plain = actuate.execute("block_ip", root, target="1.2.3.4", reason="x")
    res = playbooks.undo(root, plain["id"])
    assert "error" in res and "not a playbook" in res["error"]
