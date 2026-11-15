"""Regression tests for the holistic review: failure states, locks, defaults."""
import json

import pytest

from plasma import actuate, enforce, mcp, policy, prevent, rings, statemachine, tools, update


def test_failed_payload_is_not_journaled_as_applied(tmp_path, monkeypatch):
    calls = {"n": 0}

    def fake_run(payload, timeout=60):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"rc": 1, "output": "", "stderr": "boom"}
        return {"rc": 0, "output": "True"}

    monkeypatch.setattr(actuate, "_run", fake_run)
    dry = actuate.execute("disable_user", tmp_path, target="bob", reason="x")
    applied = actuate.execute("disable_user", tmp_path, target="bob",
                              reason="x", apply=True, plan=dry["id"])
    assert applied["mode"] == "failed" and applied["ok"] is False
    assert "boom" in applied["failure"]
    # a failed action can still be undone (it may have partially applied)
    undo_dry = actuate.undo(tmp_path, applied["id"])
    assert "payload" in undo_dry
    undone = actuate.undo(tmp_path, applied["id"], apply=True,
                          plan=undo_dry["id"])
    assert undone["mode"] == "applied" and undone["ok"] is True


def test_update_honours_the_requested_tag(monkeypatch, tmp_path):
    seen = {}

    def fake_gh(url, token, timeout=60, accept="json"):
        seen["url"] = url
        return json.dumps({"tag_name": "v2.0.0", "assets": []}).encode()

    monkeypatch.setattr(update, "_gh", fake_gh)
    res = update.download_and_verify("r/p", "v1.0.0", "", tmp_path / "x.exe")
    assert "/releases/tags/v1.0.0" in seen["url"]
    assert res["ok"] is False and res["error"] == "release tag mismatch"


def test_rings_are_case_insensitive(tmp_path):
    rings.assign(tmp_path, "WS1", "canary")
    assert rings.allows(tmp_path, "ws1", "canary") is True
    rings.remove_host(tmp_path, "ws1")
    assert rings.allows(tmp_path, "WS1", "canary") is False


def test_malformed_policy_numbers_do_not_crash_the_decision():
    p = dict(policy.DEFAULT_POLICY)
    p["max_hosts_per_action"] = "not-a-number"
    p["max_actions_per_minute"] = "also-bad"
    d = policy.evaluate("isolate_host", {"hosts": ["a", "b"]},
                        {"scopes": ["*"]}, p)
    assert d["code"] == "denied"          # default cap 1, two hosts


def test_no_scopes_means_no_authority():
    d = policy.evaluate("read_events", {}, {}, policy.DEFAULT_POLICY)
    assert d["code"] == "denied"
    assert "scope" in " ".join(d["reasons"])


def test_mcp_defaults_to_read_only_scopes(tmp_path, monkeypatch):
    monkeypatch.delenv("PLASMA_SCOPES", raising=False)
    read = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "read_events",
                                  "arguments": {"limit": 1}}}, root=tmp_path)
    assert json.loads(read["result"]["content"][0]["text"])["ok"] is True
    import socket
    write = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                        "params": {"name": "isolate_host",
                                   "arguments": {"host": socket.gethostname()}}},
                       root=tmp_path)
    payload = json.loads(write["result"]["content"][0]["text"])
    assert payload["code"] == "DENIED"
    assert "scope" in " ".join(payload["reasons"])


def test_tool_array_item_length_is_enforced():
    with pytest.raises(tools.ToolError, match="too long"):
        tools.validate_args("deploy_canary", {"extra_dirs": ["x" * 300]})


def test_prevent_refuses_to_apply_the_same_plan_twice(tmp_path):
    dry = prevent.lsa(root=tmp_path)
    prevent._append_journal(tmp_path, {
        "control": "lsa", "status": "applied", "plan": dry["id"],
        "payload_sha256": dry["payload_sha256"]})
    again = prevent._append_journal(tmp_path, {
        "control": "lsa", "status": "applied", "plan": dry["id"],
        "payload_sha256": dry["payload_sha256"]})
    assert again["code"] == "REFUSED"


def test_enforce_approval_rechecks_policy(tmp_path):
    (tmp_path / "config.json").write_text(json.dumps(
        {"enforcement": {"enabled": True, "mode": "enforce"}}))
    out = enforce.run(tmp_path, findings=[{
        "type": "canary_tripped", "score": 10, "detail": "x",
        "path": "C:\\Decoys\\x", "reason": "modified"}])
    entry = enforce.pending(tmp_path)["pending"][0]
    (tmp_path / "config.json").write_text(json.dumps(
        {"enforcement": {"enabled": True, "mode": "enforce",
                         "allowed_actions": [], "require_approval": []}}))
    res = enforce.approve(tmp_path, entry["id"], apply=True)
    assert "no longer allowlisted" in res["error"]


def test_state_machine_transition_is_locked_and_persisted(tmp_path):
    m = statemachine.UPDATE_MACHINE
    statemachine.transition(tmp_path, m, "staged", "test")
    data = statemachine.load(tmp_path, m)
    assert data["state"] == "staged"
    assert data["history"][-1]["to"] == "staged"
    with pytest.raises(statemachine.StateError):
        statemachine.transition(tmp_path, m, "rotated")


def test_enforce_pending_is_deduped_and_consumed(tmp_path, monkeypatch):
    (tmp_path / "config.json").write_text(json.dumps(
        {"enforcement": {"enabled": True, "mode": "enforce"}}))
    finding = {"type": "canary_tripped", "score": 10, "detail": "x",
               "path": "C:\\Decoys\\x", "reason": "modified"}
    enforce.run(tmp_path, findings=[finding])
    enforce.run(tmp_path, findings=[finding])
    pending = enforce.pending(tmp_path)["pending"]
    assert len(pending) == 1
    entry = pending[0]

    def fake(action, root, target=None, reason=None, apply=False, plan=None):
        return ({"id": 1, "payload": "x"} if not apply
                else {"id": 1, "ok": True, "mode": "applied"})

    monkeypatch.setattr(enforce.actuate, "execute", fake)
    res = enforce.approve(tmp_path, entry["id"], apply=True)
    assert res["applied"] is True
    assert enforce.pending(tmp_path)["count"] == 0
    again = enforce.approve(tmp_path, entry["id"], apply=True)
    assert "already been approved" in again["error"]


def test_killswitch_fails_closed_on_corrupt_state(tmp_path):
    from plasma import killswitch
    (tmp_path / "killswitch.json").write_text("{not json")
    assert killswitch.blocked(tmp_path, host="WS1") is True
    assert killswitch.status(tmp_path)["global"] is True


def test_manifest_rejects_path_traversal(tmp_path):
    from plasma import manifest
    (tmp_path / "manifest.json").write_text(json.dumps({
        "files": {"../outside": "0" * 64}, "version": "x"}))
    res = manifest.verify_manifest(tmp_path)
    assert res["ok"] is False
    assert "../outside" in res["invalid"]


def test_trace_rejects_whitespace_bypass(tmp_path):
    from plasma import trace
    text = ('/* name: x */\n/* technique: T1 */\n/* score: 5 */\n'
            'syscall:::entry\n{ system ("cmd"); printf("plasma|{}"); }\n')
    with pytest.raises(trace.ScriptError, match="destructive"):
        trace.validate_script(text, "x")


def test_wmi_capture_and_removal_use_the_same_bounded_set():
    payload, _, _ = actuate._build_disable_wmi_sub()
    assert "Select-Object -First 200" in payload
    assert "$binds | Remove-CimInstance" in payload
    assert "$binds = @(Get-CimInstance" in payload


def test_applocker_rejects_control_characters():
    with pytest.raises(ValueError):
        prevent.applocker_xml("audit", ["C:\\Apps\\bad\npath"])


def test_playbook_undo_marks_failure(tmp_path, monkeypatch):
    from plasma import playbooks
    root = tmp_path
    (root / "data").mkdir()
    (root / "data" / "events.jsonl").write_text("")

    def fake_run(payload, timeout=60):
        return {"rc": 0, "output": "True", "output_head": "True"}

    monkeypatch.setattr(actuate, "_run", fake_run)
    dry = playbooks.execute(root, "contain-user", target="bob", reason="x")
    applied = playbooks.execute(root, "contain-user", target="bob",
                                reason="x", apply=True, plan=dry["id"])
    undo_dry = playbooks.undo(root, applied["id"])
    monkeypatch.setattr(actuate, "_run",
                        lambda payload, timeout=60: {"rc": 1, "stderr": "no"})
    undone = playbooks.undo(root, applied["id"], apply=True,
                            plan=undo_dry["id"])
    assert undone["mode"] == "failed"


def test_watchdog_task_escapes_quotes(monkeypatch, tmp_path):
    from plasma import cli
    seen = {}
    monkeypatch.setattr(cli.whids, "_ps",
                        lambda script, timeout=120: (seen.update(script=script) or (0, "ok")))
    cli._register_whids_watchdog(tmp_path / "plasma.exe", tmp_path / "o'brien")
    assert "o''brien" in seen["script"]


def test_update_apply_forwards_the_tag(monkeypatch, tmp_path):
    from plasma import cli
    seen = {}
    monkeypatch.setattr(cli.updater, "download_and_verify",
                        lambda repo, tag, token, dest: (seen.update(tag=tag) or
                                                        {"ok": False, "error": "stop"}))
    args = type("A", (), {"repo": "r/p", "token_env": "NOPE", "root": str(tmp_path),
                          "ring": None, "tag": "v1.2.3", "bin": None,
                          "allow_unsigned": False})()
    assert cli.cmd_update_apply(args) == 1
    assert seen["tag"] == "v1.2.3"


def test_lock_is_released_and_reacquirable(tmp_path):
    from plasma import agentstate
    lock = tmp_path / "x.lock"
    with agentstate.lock(lock):
        assert lock.exists()
    assert not lock.exists()
    with agentstate.lock(lock):
        pass


def test_stale_lock_is_reclaimed(tmp_path):
    import os
    import time
    from plasma import agentstate
    lock = tmp_path / "x.lock"
    lock.write_text("dead:0")
    old = time.time() - 400
    os.utime(lock, (old, old))
    with agentstate.lock(lock, timeout=2, stale=300):
        assert lock.exists()
