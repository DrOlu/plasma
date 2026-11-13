"""Regression tests for the implicit state machines formalised in 1.7.2."""

import json
from pathlib import Path

import pytest

from plasma import (actuate, canary, ledger, mcp, playbooks, policy,
                    statemachine, tenants, update)


def _run_ok(payload, timeout=60):
    return {"rc": 0, "output": "ok", "output_head": "ok"}


# ---------------------------------------------------------------------------
# generic machine
# ---------------------------------------------------------------------------

def test_update_machine_allows_and_rejects_transitions(tmp_path):
    sm = statemachine.UPDATE_MACHINE
    assert sm.allows("idle", "staged")
    assert not sm.allows("idle", "installed")
    state = statemachine.load(tmp_path, sm)["state"]
    assert state == "idle"
    statemachine.transition(tmp_path, sm, "staged", "download")
    statemachine.transition(tmp_path, sm, "verified", "signature")
    data = statemachine.load(tmp_path, sm)
    assert data["state"] == "verified"
    assert [h["to"] for h in data["history"]] == ["staged", "verified"]
    with pytest.raises(statemachine.StateError):
        statemachine.transition(tmp_path, sm, "idle")


def test_reset_records_history(tmp_path):
    sm = statemachine.UPDATE_MACHINE
    statemachine.transition(tmp_path, sm, "staged")
    statemachine.reset(tmp_path, sm, "new run")
    data = statemachine.load(tmp_path, sm)
    assert data["state"] == "idle" and data["history"][-1]["to"] == "idle"


# ---------------------------------------------------------------------------
# actuate: plan single-use and undo gating
# ---------------------------------------------------------------------------

def test_actuate_plan_is_single_use(tmp_path, monkeypatch):
    monkeypatch.setattr(actuate, "_run", _run_ok)
    dry = actuate.execute("disable_user", tmp_path, target="bob", reason="drill")
    first = actuate.execute("disable_user", tmp_path, target="bob",
                            reason="drill", apply=True, plan=dry["id"])
    assert first["mode"] == "applied"
    second = actuate.execute("disable_user", tmp_path, target="bob",
                             reason="drill", apply=True, plan=dry["id"])
    assert "already been used" in second["error"]


def test_actuate_undo_requires_dry_run(tmp_path, monkeypatch):
    monkeypatch.setattr(actuate, "_run", _run_ok)
    dry = actuate.execute("disable_user", tmp_path, target="bob", reason="drill")
    applied = actuate.execute("disable_user", tmp_path, target="bob",
                              reason="drill", apply=True, plan=dry["id"])
    res = actuate.undo(tmp_path, applied["id"], apply=True)
    assert "requires --plan" in res["error"]
    undo_dry = actuate.undo(tmp_path, applied["id"])
    assert undo_dry["action"] == "undo" and undo_dry["payload_sha256"]
    done = actuate.undo(tmp_path, applied["id"], apply=True, plan=undo_dry["id"])
    assert done["mode"] == "applied" and done["result"]["rc"] == 0
    again = actuate.undo(tmp_path, applied["id"], apply=True, plan=undo_dry["id"])
    assert "already been undone" in again["error"]


def test_actuate_undo_plan_must_match_payload(tmp_path, monkeypatch):
    monkeypatch.setattr(actuate, "_run", _run_ok)
    dry = actuate.execute("disable_user", tmp_path, target="bob", reason="drill")
    applied = actuate.execute("disable_user", tmp_path, target="bob",
                              reason="drill", apply=True, plan=dry["id"])
    undo_dry = actuate.undo(tmp_path, applied["id"])
    # Tamper the journaled dry-run digest: the apply must refuse.
    path = actuate.journal_path(tmp_path)
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    for row in rows:
        if row.get("id") == undo_dry["id"]:
            row["payload_sha256"] = "0" * 64
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    res = actuate.undo(tmp_path, applied["id"], apply=True, plan=undo_dry["id"])
    assert "different undo payload" in res["error"]


# ---------------------------------------------------------------------------
# playbooks: plan single-use and undo dry-run gate
# ---------------------------------------------------------------------------

def test_playbook_plan_is_single_use(tmp_path, monkeypatch):
    monkeypatch.setattr(actuate, "_run", _run_ok)
    dry = playbooks.execute(tmp_path, "contain-user", target="bob", reason="drill")
    first = playbooks.execute(tmp_path, "contain-user", target="bob",
                              reason="drill", apply=True, plan=dry["id"])
    assert first["mode"] == "applied"
    second = playbooks.execute(tmp_path, "contain-user", target="bob",
                               reason="drill", apply=True, plan=dry["id"])
    assert "already been used" in second["error"]


def test_playbook_undo_requires_dry_run_and_is_single_use(tmp_path, monkeypatch):
    monkeypatch.setattr(actuate, "_run", _run_ok)
    dry = playbooks.execute(tmp_path, "contain-user", target="bob", reason="drill")
    applied = playbooks.execute(tmp_path, "contain-user", target="bob",
                                reason="drill", apply=True, plan=dry["id"])
    res = playbooks.undo(tmp_path, applied["id"], apply=True)
    assert "requires --plan" in res["error"]
    undo_dry = playbooks.undo(tmp_path, applied["id"])
    assert any(step.get("plan") for step in undo_dry["steps"])
    done = playbooks.undo(tmp_path, applied["id"], apply=True,
                          plan=undo_dry["id"])
    assert done["mode"] == "applied"
    again = playbooks.undo(tmp_path, applied["id"], apply=True,
                           plan=undo_dry["id"])
    assert "already been undone" in again["error"]


# ---------------------------------------------------------------------------
# approvals: atomic single use
# ---------------------------------------------------------------------------

def _pending(tmp_path):
    args = {"user": "alice"}
    p = dict(policy.DEFAULT_POLICY, autonomy="supervised")
    d = policy.evaluate("contain_user", args, {"scopes": ["*"]}, p)
    row = ledger.record(tmp_path, tool="contain_user", args=args, decision=d,
                        context={"scopes": ["*"]})
    ledger.approve(tmp_path, row["seq"], "ciso", "ok")
    return row


def test_approval_consumes_once(tmp_path):
    row = _pending(tmp_path)
    first = ledger.consume_approval(tmp_path, row["seq"], "contain_user",
                                    row["args_sha256"])
    assert first is not None and first["kind"] == "approval_use"
    second = ledger.consume_approval(tmp_path, row["seq"], "contain_user",
                                     row["args_sha256"])
    assert second is None
    assert ledger.find_approval(tmp_path, row["seq"], "contain_user",
                                row["args_sha256"]) is None
    assert ledger.pending_approvals(tmp_path) == []


def test_approval_bound_to_action(tmp_path):
    row = _pending(tmp_path)
    assert ledger.consume_approval(tmp_path, row["seq"], "contain_user",
                                   "0" * 64) is None
    assert ledger.consume_approval(tmp_path, row["seq"], "isolate_host",
                                   row["args_sha256"]) is None


def test_mcp_reusing_approval_is_refused(tmp_path):
    first = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "isolate_host",
                                   "arguments": {"host": "WS1"}}}, root=tmp_path)
    payload = json.loads(first["result"]["content"][0]["text"])
    ledger.approve(tmp_path, payload["approval_id"], "ciso", "ok")
    ok = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                     "params": {"name": "isolate_host",
                                "arguments": {"host": "WS1"},
                                "approval_id": payload["approval_id"]}},
                    root=tmp_path)
    assert json.loads(ok["result"]["content"][0]["text"])["ok"] is True
    reused = mcp.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                         "params": {"name": "isolate_host",
                                    "arguments": {"host": "WS1"},
                                    "approval_id": payload["approval_id"]}},
                        root=tmp_path)
    assert json.loads(reused["result"]["content"][0]["text"])["code"] == "APPROVAL_INVALID"


# ---------------------------------------------------------------------------
# tenant ownership
# ---------------------------------------------------------------------------

def test_tenant_host_ownership_is_exclusive(tmp_path):
    tenants.add(tmp_path, "acme", "Acme", ["WS1", "WS2"])
    tenants.add(tmp_path, "beta", "Beta", ["WS1"])
    acme = next(t for t in tenants.list_tenants(tmp_path) if t["id"] == "acme")
    beta = next(t for t in tenants.list_tenants(tmp_path) if t["id"] == "beta")
    assert "WS1" not in acme["hosts"] and acme["hosts"] == ["WS2"]
    assert beta["hosts"] == ["WS1"]
    assert tenants.resolve(tmp_path, "WS1") == "beta"
    assert tenants.allows(tmp_path, "acme", "WS1") is False


# ---------------------------------------------------------------------------
# atomic bin rotation and canary manifest
# ---------------------------------------------------------------------------

def test_rotate_bin_recovers_and_replaces_atomically(tmp_path):
    bin_exe = tmp_path / "plasma.exe"
    bin_exe.write_text("old")
    new = tmp_path / "staged.exe"
    new.write_text("new")
    result = update.rotate_bin(new, bin_exe)
    assert result["ok"] is True
    assert bin_exe.read_text() == "new"
    assert (tmp_path / "plasma.exe.old").read_text() == "old"
    assert not (tmp_path / "plasma.exe.new").exists()


def test_rotate_bin_recovers_missing_bin(tmp_path):
    bin_exe = tmp_path / "plasma.exe"
    (tmp_path / "plasma.exe.old").write_text("old")
    new = tmp_path / "staged.exe"
    new.write_text("new")
    result = update.rotate_bin(new, bin_exe)
    assert result["ok"] is True
    assert bin_exe.read_text() == "new"


def test_canary_deploy_dedupes_and_writes_valid_manifest(tmp_path):
    first = canary.deploy(tmp_path, extra_dirs=[tmp_path / "shared"])
    second = canary.deploy(tmp_path, extra_dirs=[tmp_path / "shared"])
    manifest = json.loads(canary.manifest_path(tmp_path).read_text())
    paths = [c["path"] for c in manifest["canaries"]]
    assert len(paths) == len(set(paths))
    assert first["deployed"] == second["deployed"]
    assert canary.verify(tmp_path)["intact"] == len(paths)