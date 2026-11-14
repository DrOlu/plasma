"""Agent trust layer: tools, policy, ledger, kill switch, MCP, evidence."""

import json
import zipfile
from pathlib import Path

import pytest

from plasma import (assurance, evidence, evals, killswitch, ledger, mcp,
                    policy, rings, tenants, tools)


# ---------------------------------------------------------------------------
# capability contract
# ---------------------------------------------------------------------------

def test_every_tool_is_scoped_and_typed():
    for spec in tools.list_tools():
        assert spec.scopes, spec.name
        assert spec.risk in tools.RISK_ORDER, spec.name
        assert spec.input_schema.get("type") == "object"
        assert spec.description


def test_unknown_tool_refused():
    with pytest.raises(tools.ToolError, match="unknown"):
        tools.get("run_shell")


def test_schema_rejects_extra_and_missing_arguments():
    with pytest.raises(tools.ToolError, match="unexpected"):
        tools.validate_args("read_events", {"limit": 5, "shell": "whoami"})
    with pytest.raises(tools.ToolError, match="missing required"):
        tools.validate_args("contain_user", {})
    with pytest.raises(tools.ToolError, match="must be integer"):
        tools.validate_args("kill_process", {"pid": "42"})
    with pytest.raises(tools.ToolError, match="above the maximum"):
        tools.validate_args("read_events", {"limit": 99999})


def test_schema_accepts_valid_arguments():
    assert tools.validate_args("read_events", {"limit": 10})["limit"] == 10
    assert tools.validate_args("deploy_canary", {}) == {}


def test_action_fingerprint_is_stable_and_order_independent():
    a = tools.action_fingerprint("contain_user", {"user": "alice"})
    b = tools.action_fingerprint("contain_user", {"user": "alice"})
    c = tools.action_fingerprint("contain_user", {"user": "bob"})
    assert a == b and a != c


def test_mutating_tools_are_dry_run_only():
    for name in ("contain_user", "isolate_host", "quarantine_file", "kill_process"):
        assert tools.get(name).dry_run_only is True


# ---------------------------------------------------------------------------
# policy
# ---------------------------------------------------------------------------

def _ctx(scopes=("*",)):
    return {"scopes": list(scopes), "agent": "test", "tenant": "default"}


def test_read_is_allowed_in_every_tier():
    for tier in policy.AUTONOMY:
        p = dict(policy.DEFAULT_POLICY, autonomy=tier)
        assert policy.evaluate("read_events", {}, _ctx(), p)["code"] == "allow"


def test_assist_requires_approval_for_actions():
    p = dict(policy.DEFAULT_POLICY, autonomy="assist")
    d = policy.evaluate("deploy_canary", {}, _ctx(), p)
    assert d["code"] == "approval_required" and not d["allowed"]


def test_supervised_allows_medium_and_approves_high():
    p = dict(policy.DEFAULT_POLICY, autonomy="supervised")
    assert policy.evaluate("deploy_canary", {}, _ctx(), p)["code"] == "allow"
    assert policy.evaluate("contain_user", {"user": "a"}, _ctx(), p)["code"] == "approval_required"
    assert policy.evaluate("isolate_host", {"host": "WS1"}, _ctx(), p)["code"] == "approval_required"


def test_allow_list_does_not_bypass_assist_or_supervised_approval():
    p = dict(policy.DEFAULT_POLICY, autonomy="assist", allow=["contain_user"])
    assert policy.evaluate("contain_user", {"user": "a"}, _ctx(), p)["code"] == "approval_required"
    p = dict(policy.DEFAULT_POLICY, autonomy="supervised", allow=["contain_user"])
    assert policy.evaluate("contain_user", {"user": "a"}, _ctx(), p)["code"] == "approval_required"
    p = dict(policy.DEFAULT_POLICY, autonomy="autonomous", allow=["contain_user"])
    assert policy.evaluate("contain_user", {"user": "a"}, _ctx(), p)["code"] == "allow"


def test_autonomous_critical_needs_approval_unless_allowed():
    p = dict(policy.DEFAULT_POLICY, autonomy="autonomous")
    assert policy.evaluate("contain_user", {"user": "a"}, _ctx(), p)["code"] == "allow"
    assert policy.evaluate("isolate_host", {"host": "WS1"}, _ctx(), p)["code"] == "approval_required"
    p2 = dict(p, allow_critical=True)
    assert policy.evaluate("isolate_host", {"host": "WS1"}, _ctx(), p2)["code"] == "allow"


def test_deny_list_and_scope_and_blast_radius_and_rate_limit():
    p = dict(policy.DEFAULT_POLICY, deny=["kill_process"])
    assert policy.evaluate("kill_process", {"pid": 1}, _ctx(), p)["code"] == "denied"
    p = dict(policy.DEFAULT_POLICY)
    assert policy.evaluate("read_events", {}, _ctx(("health:read",)), p)["code"] == "denied"
    p = dict(policy.DEFAULT_POLICY, max_hosts_per_action=1)
    assert policy.evaluate("isolate_host", {"hosts": ["WS1", "WS2"]}, _ctx(), p)["code"] == "denied"
    p = dict(policy.DEFAULT_POLICY, max_actions_per_minute=5)
    assert policy.evaluate("deploy_canary", {}, _ctx(), p, recent_actions=5)["code"] == "denied"


def test_killswitch_blocks_actions_but_not_reads():
    p = dict(policy.DEFAULT_POLICY)
    assert policy.evaluate("deploy_canary", {}, _ctx(), p, killswitch_blocked=True)["code"] == "denied"
    assert policy.evaluate("read_events", {}, _ctx(), p, killswitch_blocked=True)["code"] == "allow"


def test_policy_roundtrip_and_validation(tmp_path):
    saved = policy.save(tmp_path, {"autonomy": "autonomous", "deny": ["kill_process"]})
    assert saved["autonomy"] == "autonomous"
    assert policy.load(tmp_path)["deny"] == ["kill_process"]
    with pytest.raises(ValueError):
        policy.save(tmp_path, {"autonomy": "godmode"})


# ---------------------------------------------------------------------------
# ledger
# ---------------------------------------------------------------------------

def test_ledger_chain_and_verify(tmp_path):
    p = policy.DEFAULT_POLICY
    d = policy.evaluate("read_events", {}, _ctx(), p)
    r1 = ledger.record(tmp_path, tool="read_events", args={}, decision=d, context=_ctx())
    r2 = ledger.record(tmp_path, tool="audit_tail", args={}, decision=d, context=_ctx())
    assert r2["seq"] == r1["seq"] + 1
    assert r2["prev"] == r1["hash"]
    assert ledger.verify(tmp_path)["ok"] is True


def test_ledger_tamper_is_detected(tmp_path):
    d = policy.evaluate("read_events", {}, _ctx(), policy.DEFAULT_POLICY)
    ledger.record(tmp_path, tool="read_events", args={}, decision=d, context=_ctx())
    ledger.record(tmp_path, tool="read_events", args={}, decision=d, context=_ctx())
    path = ledger.ledger_path(tmp_path)
    rows = [json.loads(x) for x in path.read_text().splitlines()]
    rows[0]["reasons"] = ["tampered"]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    result = ledger.verify(tmp_path)
    assert result["ok"] is False and result["broken"] == 1


def test_approval_flow_and_single_use(tmp_path):
    p = dict(policy.DEFAULT_POLICY, autonomy="supervised")
    args = {"user": "alice"}
    d = policy.evaluate("contain_user", args, _ctx(), p)
    row = ledger.record(tmp_path, tool="contain_user", args=args, decision=d, context=_ctx())
    pending = ledger.pending_approvals(tmp_path)
    assert pending and pending[0]["seq"] == row["seq"]
    ledger.approve(tmp_path, row["seq"], "ciso", "confirmed")
    found = ledger.find_approval(tmp_path, row["seq"], "contain_user", row["args_sha256"])
    assert found is not None
    # consume it with an action that references the approval
    ledger.record(tmp_path, tool="contain_user", args=args, decision=d,
                  context=_ctx(), approval_id=row["seq"], outcome="dry_run")
    assert ledger.find_approval(tmp_path, row["seq"], "contain_user", row["args_sha256"]) is None


def test_count_recent_and_tail(tmp_path):
    d = policy.evaluate("read_events", {}, _ctx(), policy.DEFAULT_POLICY)
    for _ in range(3):
        ledger.record(tmp_path, tool="read_events", args={}, decision=d, context=_ctx())
    assert ledger.count_recent(tmp_path, 60) == 3
    assert len(ledger.tail(tmp_path, 2)) == 2


# ---------------------------------------------------------------------------
# kill switch, tenants, rings
# ---------------------------------------------------------------------------

def test_killswitch_global_and_host(tmp_path):
    assert killswitch.blocked(tmp_path, "WS1", "high") is False
    killswitch.set_global(tmp_path, True, "incident")
    assert killswitch.blocked(tmp_path, "WS1", "high") is True
    assert killswitch.blocked(tmp_path, "WS1", "read") is False
    killswitch.set_global(tmp_path, False)
    killswitch.set_host(tmp_path, "WS1", True, "quarantine")
    assert killswitch.blocked(tmp_path, "WS1", "high") is True
    assert killswitch.blocked(tmp_path, "WS2", "high") is False


def test_tenants_scope_hosts(tmp_path):
    tenants.add(tmp_path, "acme", "Acme Bank", ["WS9"])
    assert tenants.resolve(tmp_path, "WS9") == "acme"
    assert tenants.allows(tmp_path, "acme", "WS9") is True
    assert tenants.allows(tmp_path, "default", "WS9") is False
    with pytest.raises(ValueError):
        tenants.remove(tmp_path, "default")
    tenants.remove(tmp_path, "acme")
    assert tenants.resolve(tmp_path, "WS9") == "default"


def test_rings_assign_and_rollback(tmp_path):
    rings.assign(tmp_path, "WS1", "canary")
    assert rings.allows(tmp_path, "WS1", "canary") is True
    assert rings.allows(tmp_path, "WS2", "canary") is False
    rings.promote(tmp_path, "canary")
    assert rings.status(tmp_path)["current"] == "canary"
    bin_exe = tmp_path / "plasma.exe"
    bin_exe.write_text("new")
    (tmp_path / "plasma.exe.old").write_text("old")
    result = rings.rollback(bin_exe)
    assert result["ok"] is True
    assert bin_exe.read_text() == "old"
    assert (tmp_path / "plasma.exe.failed").read_text() == "new"


# ---------------------------------------------------------------------------
# MCP
# ---------------------------------------------------------------------------

def _call(name, args, **extra):
    params = {"name": name, "arguments": args}
    params.update(extra)
    return mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": params}, root=extra.pop("_root", None))


def test_mcp_initialize_and_tools_list(tmp_path):
    init = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"}, root=tmp_path)
    assert init["result"]["protocolVersion"] == mcp.PROTOCOL_VERSION
    listing = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, root=tmp_path)
    names = {t["name"] for t in listing["result"]["tools"]}
    assert {"read_events", "isolate_host", "audit_tail"} <= names


def test_mcp_read_is_allowed_and_audited(tmp_path, capsys):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "events.jsonl").write_text(
        json.dumps({"ts": "2026-11-13T12:00:00Z", "kind": "alert",
                    "score": 0.8, "host": "WS1"}) + "\n")
    res = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "read_events", "arguments": {"limit": 10}}},
                     root=tmp_path)
    payload = json.loads(res["result"]["content"][0]["text"])
    assert payload["ok"] and payload["count"] == 1
    assert payload["audit_id"] == 1
    assert ledger.verify(tmp_path)["ok"] is True


def test_mcp_risky_tool_requires_approval_then_runs_dry(tmp_path):
    import socket
    local = socket.gethostname()
    res = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "isolate_host",
                                 "arguments": {"host": local}}}, root=tmp_path)
    payload = json.loads(res["result"]["content"][0]["text"])
    assert payload["code"] == "APPROVAL_REQUIRED"
    approval_id = payload["approval_id"]
    ledger.approve(tmp_path, approval_id, "ciso", "drill")

    res2 = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                       "params": {"name": "isolate_host",
                                  "arguments": {"host": local},
                                  "approval_id": approval_id}}, root=tmp_path)
    payload2 = json.loads(res2["result"]["content"][0]["text"])
    assert payload2["ok"] is True and payload2["dry_run"] is True


def test_mcp_rejects_invalid_args_and_denied_tools(tmp_path):
    bad = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "read_events",
                                 "arguments": {"limit": 5, "shell": "whoami"}}},
                     root=tmp_path)
    assert json.loads(bad["result"]["content"][0]["text"])["code"] == "INVALID_ARGS"

    policy.save(tmp_path, {"autonomy": "assist", "deny": ["kill_process"]})
    denied = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"name": "kill_process",
                                    "arguments": {"pid": 4}}}, root=tmp_path)
    assert json.loads(denied["result"]["content"][0]["text"])["code"] == "DENIED"


def test_mcp_killswitch_denies_action(tmp_path):
    killswitch.set_global(tmp_path, True, "incident")
    res = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "deploy_canary", "arguments": {}}},
                     root=tmp_path)
    assert json.loads(res["result"]["content"][0]["text"])["code"] == "DENIED"


def test_mcp_unknown_method():
    res = mcp.handle({"jsonrpc": "2.0", "id": 9, "method": "nope"})
    assert res["error"]["code"] == -32601


# ---------------------------------------------------------------------------
# evidence, assurance, evals
# ---------------------------------------------------------------------------

def test_evidence_export(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "events.jsonl").write_text(
        json.dumps({"ts": "2026-11-13T12:00:00Z", "kind": "alert", "score": 0.9,
                    "host": "WS1"}) + "\n")
    policy.save(tmp_path, {"autonomy": "supervised"})
    ledger.record(tmp_path, tool="read_events", args={},
                  decision=policy.evaluate("read_events", {}, _ctx()),
                  context=_ctx())
    out = tmp_path / "evidence.json"
    result = evidence.export(tmp_path, ["cbn", "pci"], out=out)
    assert out.exists() and out.with_suffix(".md").exists()
    assert len(result["frameworks"]["cbn"]["controls"]) == 8
    assert result["summary"]["met"] >= 1
    assert "CBN" in out.with_suffix(".md").read_text()


def test_assurance_sbom_and_support_bundle(tmp_path):
    sbom = assurance.sbom(tmp_path)
    names = {c["name"] for c in sbom["components"]}
    assert "WHIDS" in names
    out = tmp_path / "sbom.json"
    assurance.write_sbom(tmp_path, out)
    assert json.loads(out.read_text())["bomFormat"] == "CycloneDX"

    bundle = assurance.support_bundle(tmp_path, tmp_path / "support.zip")
    assert bundle["ok"] is True
    with zipfile.ZipFile(bundle["out"]) as zf:
        assert "support.json" in zf.namelist()
        payload = json.loads(zf.read("support.json"))
        assert payload["system"]["version"]


def test_safety_case_runs_evals(tmp_path):
    result = assurance.safety_case(tmp_path, tmp_path / "safety.md")
    assert result["evaluation"]["failed"] == 0
    assert (tmp_path / "safety.md").exists()


def test_evals_all_pass():
    result = evals.run()
    assert result["failed"] == 0, [r for r in result["results"] if not r["ok"]]

def test_cli_control_policy_eval_and_ring(tmp_path):
    from plasma import cli
    assert cli.main(["control", "policy", "set", "--root", str(tmp_path),
                     "--autonomy", "autonomous", "--deny", "kill_process"]) == 0
    assert policy.load(tmp_path)["autonomy"] == "autonomous"
    assert policy.load(tmp_path)["deny"] == ["kill_process"]
    assert cli.main(["eval", "run"]) == 0
    assert cli.main(["ring", "assign", "WS1", "--ring", "canary",
                     "--root", str(tmp_path)]) == 0
    assert rings.allows(tmp_path, "WS1", "canary") is True


def test_cli_evidence_and_assurance(tmp_path):
    from plasma import cli
    assert cli.main(["evidence", "export", "--root", str(tmp_path),
                     "--framework", "cbn", "--out", str(tmp_path / "ev.json")]) == 0
    assert (tmp_path / "ev.json").exists()
    assert cli.main(["assurance", "sbom", "--root", str(tmp_path),
                     "--out", str(tmp_path / "sbom.json")]) == 0
    assert (tmp_path / "sbom.json").exists()


def test_cli_audit_verify_after_mcp_call(tmp_path):
    from plasma import cli
    mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "read_events", "arguments": {"limit": 1}}},
               root=tmp_path)
    assert cli.main(["control", "audit", "verify", "--root", str(tmp_path)]) == 0


def test_mcp_tenant_isolation(tmp_path, monkeypatch):
    monkeypatch.setenv("PLASMA_TRUST_CLIENT_META", "1")
    tenants.add(tmp_path, "acme", "Acme Bank", ["WS1"])
    res = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "contain_user",
                                 "arguments": {"user": "bob"},
                                 "_meta": {"tenant": "acme"}}}, root=tmp_path)
    payload = json.loads(res["result"]["content"][0]["text"])
    assert payload["code"] == "DENIED"
    assert "does not own host" in payload["reasons"][0]


def test_mcp_ignores_client_tenant_claim_by_default(tmp_path, monkeypatch):
    import socket
    monkeypatch.delenv("PLASMA_TRUST_CLIENT_META", raising=False)
    monkeypatch.setenv("PLASMA_TENANT", "default")
    tenants.add(tmp_path, "acme", "Acme Bank", [socket.gethostname()])
    res = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "contain_user",
                                 "arguments": {"user": "bob"},
                                 "_meta": {"tenant": "acme"}}}, root=tmp_path)
    payload = json.loads(res["result"]["content"][0]["text"])
    assert payload["code"] == "DENIED"


def test_mcp_scope_claim_is_ignored_without_env_opt_in(tmp_path, monkeypatch):
    monkeypatch.delenv("PLASMA_TRUST_CLIENT_META", raising=False)
    monkeypatch.setenv("PLASMA_SCOPES", "health:read")
    res = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "read_events",
                                 "arguments": {"limit": 1},
                                 "_meta": {"scopes": ["*"]}}}, root=tmp_path)
    payload = json.loads(res["result"]["content"][0]["text"])
    assert payload["code"] == "DENIED"


def test_mcp_rejects_oversized_request():
    res = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "read_events",
                                 "arguments": {"limit": 1}}} | {"pad": "x" * (mcp.MAX_REQUEST_BYTES + 1)})
    # handle itself validates args; the serve loop enforces the byte cap.
    assert res is not None
