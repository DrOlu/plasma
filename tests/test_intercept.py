"""Intercept phases 0-3: shadow, ACL, agent gateway and native broker."""
from __future__ import annotations

import json

import pytest

from plasma import cli, intercept, mcp


def _root(tmp_path):
    root = tmp_path / "plasma"
    root.mkdir(parents=True)
    return root


def _rule(rule_id="r1", point="file_write", action="deny", backend="acl",
          mode="shadow", match=None, **over):
    rule = {
        "id": rule_id, "point": point, "action": action,
        "backend": backend, "mode": mode, "match": match or {},
        "priority": 0, "ttl_seconds": 0, "reason": "test",
    }
    rule.update(over)
    return rule


def _manifest(root, paths):
    (root / "canaries.json").write_text(json.dumps({
        "canaries": [{"path": str(p), "sha256": "0" * 64, "size": 1}
                     for p in paths]
    }))


def _event(**over):
    row = {
        "ts": "2026-11-19T10:00:00Z", "host": "WS1",
        "source": "sysmon", "kind": "process", "event_id": 1,
        "severity": "info", "process": "powershell.exe", "user": "CORP\\olu",
    }
    row.update(over)
    return row


# ---------------------------------------------------------------------------
# Phase 0: shadow evaluation
# ---------------------------------------------------------------------------

def test_rule_validation_and_registry(tmp_path):
    root = _root(tmp_path)
    rule = intercept.add_rule(root, _rule())
    assert rule["id"] == "r1"
    assert intercept.list_rules(root)["count"] == 1
    with pytest.raises(ValueError):
        intercept.add_rule(root, _rule())
    with pytest.raises(ValueError):
        intercept.add_rule(root, _rule(rule_id="bad", point="kernel"))
    with pytest.raises(ValueError):
        intercept.add_rule(root, _rule(rule_id="bad", match={"nope": "x"}))
    assert intercept.remove_rule(root, "r1")["remaining"] == 0


def test_shadow_evaluation_matches_process_file_and_network(tmp_path):
    rules = [
        _rule("proc", point="process_exec", backend="auto",
              match={"process": "powershell.exe"}),
        _rule("file", point="file_write", backend="acl",
              match={"path_prefix": "D:\\Finance"}),
        _rule("net", point="network_connect", backend="firewall",
              match={"dest_ip": "203.0.113.9", "dest_port": 4444}),
    ]
    store = tmp_path / "events.jsonl"
    store.write_text("\n".join(json.dumps(r) for r in [
        _event(),
        _event(kind="file", event_id=11, file_path="D:\\Finance\\x.xlsx"),
        _event(kind="network", event_id=3, dest_ip="203.0.113.9",
               dest_port=4444),
        _event(process="notepad.exe"),
    ]) + "\n")
    result = intercept.evaluate_store(store, rules)
    assert result["checked"] == 4
    assert result["matched"] == 3
    assert result["would_block"] == 3
    assert {d["rule"] for d in result["decisions"]} == {"proc", "file", "net"}
    assert all(d["shadow"] is True and d["allowed"] is True
               for d in result["decisions"])


def test_enforce_rule_blocks_and_allow_has_lower_precedence(tmp_path):
    deny = _rule("deny", point="process_exec", action="deny",
                 mode="enforce", match={"process": "powershell.exe"},
                 priority=1)
    allow = _rule("allow", point="process_exec", action="allow",
                  mode="enforce", match={"process": "powershell.exe"},
                  priority=0)
    decision = intercept.decide([deny, allow], _event())
    assert decision["allowed"] is False
    assert decision["rule"] == "deny"


# ---------------------------------------------------------------------------
# Phase 2: agent tool-call gateway
# ---------------------------------------------------------------------------

def test_agent_gateway_denies_before_handler(tmp_path, monkeypatch):
    root = _root(tmp_path)
    intercept.add_rule(root, _rule(
        "no-isolate", point="agent_tool_call", action="deny",
        backend="gateway", mode="enforce", match={"tool": "isolate_host"}))
    called = []
    monkeypatch.setattr(mcp, "_handler_isolate",
                        lambda *a, **k: called.append(True) or {"ok": True})
    response = mcp.handle({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "isolate_host", "arguments": {"host": "WS1"}},
    }, root=root)
    body = json.loads(response["result"]["content"][0]["text"])
    assert body["code"] == "INTERCEPTED"
    assert body["rule"] == "no-isolate"
    assert called == []


def test_agent_gateway_shadow_allows_and_audits(tmp_path):
    root = _root(tmp_path)
    intercept.add_rule(root, _rule(
        "shadow-read", point="agent_tool_call", action="deny",
        backend="gateway", mode="shadow", match={"tool": "read_events"}))
    (root / "data").mkdir()
    (root / "data" / "events.jsonl").write_text("")
    response = mcp.handle({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "read_events", "arguments": {"limit": 1}},
    }, root=root)
    body = json.loads(response["result"]["content"][0]["text"])
    assert body.get("ok") is True
    journal = root / "ledger" / "ledger.jsonl"
    assert journal.exists()


# ---------------------------------------------------------------------------
# Phase 1/3: ACL and firewall backends
# ---------------------------------------------------------------------------

def test_canary_acl_dry_run_apply_and_rollback(tmp_path, monkeypatch):
    root = _root(tmp_path)
    p1, p2 = root / "one.xlsx", root / "two.docx"
    p1.write_bytes(b"one")
    p2.write_bytes(b"two")
    _manifest(root, [p1, p2])
    monkeypatch.setattr(intercept.killswitch, "blocked",
                        lambda *a, **k: None)
    dry = intercept.protect_canary(root, reason="test")
    assert dry["status"] == "dry-run" and dry["id"]
    applied_payload = json.dumps([
        {"path": str(p1), "ok": True, "before": "D:AI(A;ID;FA;;;SY)",
         "after": "D:AI(A;ID;FA;;;SY)(D;;WD;;;WD)"},
        {"path": str(p2), "ok": True, "before": "D:AI(A;ID;FA;;;SY)",
         "after": "D:AI(A;ID;FA;;;SY)(D;;WD;;;WD)"},
    ])
    seen = []

    def fake_ps(script, timeout=120):
        seen.append(script)
        return 0, applied_payload

    monkeypatch.setattr(intercept, "_ps", fake_ps)
    applied = intercept.protect_canary(root, apply=True, plan=dry["id"],
                                       reason="test")
    assert applied["status"] == "applied"
    assert len(applied["undo"]["items"]) == 2
    assert seen and "FileSystemAccessRule" in seen[0]

    dry_rollback = intercept.rollback(root, applied["id"], reason="undo")
    assert dry_rollback["status"] == "dry-run"
    monkeypatch.setattr(intercept, "_ps",
                        lambda script, timeout=120: (0, json.dumps([
                            {"path": str(p1), "ok": True},
                            {"path": str(p2), "ok": True}])))
    undone = intercept.rollback(root, applied["id"], apply=True,
                                plan=dry_rollback["id"], reason="undo")
    assert undone["status"] == "applied"


def test_firewall_rule_dry_run_apply_rollback(tmp_path, monkeypatch):
    root = _root(tmp_path)
    rule = intercept.add_rule(root, _rule(
        "block-test-net", point="network_connect", action="deny",
        backend="firewall", mode="enforce", match={"dest_ip": "203.0.113.9"}))
    monkeypatch.setattr(intercept.killswitch, "blocked",
                        lambda *a, **k: None)
    monkeypatch.setattr(intercept, "_ps",
                        lambda script, timeout=120: (0, json.dumps({
                            "applied": True, "name": "PlasmaIntercept-block-test-net",
                            "count": 1})))
    dry = intercept.apply_rule(root, rule["id"])
    assert dry["status"] == "dry-run"
    applied = intercept.apply_rule(root, rule["id"], apply=True,
                                   plan=dry["id"])
    assert applied["status"] == "applied"
    monkeypatch.setattr(intercept, "_ps",
                        lambda script, timeout=120: (0, json.dumps({
                            "removed": True, "remaining": 0})))
    dry_rollback = intercept.rollback(root, applied["id"])
    undone = intercept.rollback(root, applied["id"], apply=True,
                                plan=dry_rollback["id"])
    assert undone["status"] == "applied"


def test_apply_requires_a_seen_plan(tmp_path):
    root = _root(tmp_path)
    rule = intercept.add_rule(root, _rule(
        "gate", point="network_connect", action="deny",
        backend="firewall", match={"dest_ip": "203.0.113.9"}))
    result = intercept.apply_rule(root, rule["id"], apply=True, plan=None)
    assert "error" in result
    assert "--plan" in result["error"]


def test_firewall_rejects_loopback(tmp_path):
    root = _root(tmp_path)
    rule = intercept.add_rule(root, _rule(
        "loop", point="network_connect", action="deny",
        backend="firewall", match={"dest_ip": "127.0.0.1"}))
    result = intercept.apply_rule(root, rule["id"])
    assert "error" in result


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------

def test_intercept_cli_status_rules_and_evaluate(tmp_path, capsys):
    root = _root(tmp_path)
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps(_rule()))
    assert cli.main(["intercept", "rules", "add", "--root", str(root),
                     "--file", str(rules)]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["ok"] is True
    assert cli.main(["intercept", "status", "--root", str(root)]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["rules"] == 1
    store = tmp_path / "events.jsonl"
    store.write_text(json.dumps(_event(kind="file", event_id=11,
                                       file_path="D:\\Finance\\x")) + "\n")
    assert cli.main(["intercept", "evaluate", "--root", str(root),
                     "--events", str(store)]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["would_block"] == 1
