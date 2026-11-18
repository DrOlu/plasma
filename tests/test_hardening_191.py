"""Regression tests for the 1.19.1 holistic review fixes."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from plasma import (
    actuate,
    autoupdate,
    coverage,
    deep,
    enforce,
    health,
    killswitch,
    ledger,
    policy,
    rings,
    serve,
    sigma,
    tap,
    tenants,
    trace,
    update,
)
from plasma import help as helpmod

# ---------------------------------------------------------------------------
# HTTP boundary
# ---------------------------------------------------------------------------

def test_http_rejects_leading_double_dash():
    with pytest.raises(serve.ServeError):
        serve._validate_argv(["--", "control", "killswitch", "on"])


def test_http_uses_parsed_command_path_not_string_scan():
    # manifest create is a positional action on a command whose path is just
    # "manifest"; the raw token scan misses it.
    assert serve.is_mutating(
        ["manifest", "--dir", "C:\\bundle", "create"],
        "manifest", SimpleNamespace(action="create"))
    assert not serve.is_mutating(
        ["manifest", "--dir", "C:\\bundle", "verify"],
        "manifest", SimpleNamespace(action="verify"))


def test_read_only_classifies_the_previously_missing_commands():
    for path in ("update auto", "protect arm", "protect disarm",
                 "sigma convert"):
        assert serve.is_mutating(path.split(), path)
    assert not serve.is_mutating(["update", "auto", "--check-only"],
                                 "update auto")
    assert not serve.is_mutating(["sigma", "convert", "--dry-run"],
                                 "sigma convert")
    assert not serve.is_mutating(["deep", "persistence"], "deep persistence")
    assert serve.is_mutating(["deep", "persistence", "--json-out", "x"],
                             "deep persistence")


def test_default_api_key_refused_on_non_loopback():
    with pytest.raises(serve.ServeError) as exc:
        serve.make_server(host="0.0.0.0", port=0,
                          api_key=serve.DEFAULT_API_KEY,
                          audit=False, quiet=True)
    assert exc.value.code == "insecure_key"


def test_audit_redacts_equals_and_abbreviated_prompt():
    assert serve._audit_argv(["ask", "--prompt=secret"]) == [
        "ask", "--prompt=<redacted>"]
    assert serve._audit_argv(["ask", "--prom", "secret"]) == [
        "ask", "--prom", "<redacted>"]
    assert serve._audit_argv(["ask", "--system=secret"]) == [
        "ask", "--system=<redacted>"]


def test_commands_root_has_openapi_required_fields():
    rows = serve._command_tree(__import__("plasma.cli", fromlist=["build_parser"]).build_parser())
    # The route adds these to root; the tree itself must at least expose the
    # metadata fields consumed by the API.
    assert rows[0]["path"] == []
    assert "options" in rows[0] and "positionals" in rows[0]


# ---------------------------------------------------------------------------
# Policy, ledger, tenants, kill switch
# ---------------------------------------------------------------------------

def test_policy_rejects_malformed_types_and_keeps_reads_available(tmp_path):
    policy.save(tmp_path, {"autonomy": "autonomous", "deny": "kill_process"})
    loaded = policy.load(tmp_path)
    assert loaded["deny"] == ["kill_process"]
    decision = policy.evaluate("kill_process", {"pid": 1}, context={
        "scopes": ["*"], "host": "HOST1"}, policy=loaded)
    assert decision["allowed"] is False
    # A malformed rate limit must not silently become zero/unlimited.
    weird = dict(loaded, max_actions_per_minute="oops")
    read = policy.evaluate("read_events", {}, context={"scopes": ["*"]},
                           policy=weird, recent_actions=10**6)
    assert read["allowed"] is True


def test_tenants_are_case_insensitive_and_fail_closed(tmp_path):
    tenants.add(tmp_path, "acme", "Acme", ["WS1"])
    assert tenants.resolve(tmp_path, "ws1") == "acme"
    assert tenants.allows(tmp_path, "acme", "WS1")
    (tmp_path / "tenants.json").write_text("[1, 2, 3]")
    assert tenants.resolve(tmp_path, "ws1") == "__invalid__"
    assert tenants.allows(tmp_path, "acme", "ws1") is False


def test_killswitch_structural_corruption_fails_closed(tmp_path):
    (tmp_path / "killswitch.json").write_text("[1, 2]")
    state = killswitch.status(tmp_path)
    assert state["global"] is True
    assert killswitch.blocked(tmp_path) is True


def test_denied_approval_is_terminal(tmp_path):
    d = policy.evaluate("kill_process", {"pid": 1}, context={"scopes": ["*"]},
                        policy=policy.DEFAULT_POLICY)
    row = ledger.record(tmp_path, tool="kill_process", args={"pid": 1},
                        decision=d, context={"scopes": ["*"]})
    ledger.approve(tmp_path, row["seq"], "alice", approve_action=False)
    assert ledger.pending_approvals(tmp_path) == []
    assert ledger.consume_approval(
        tmp_path, row["seq"], "kill_process",
        row["args_sha256"], tenant="default") is None


def test_ledger_detects_suffix_truncation(tmp_path):
    d = policy.evaluate("read_events", {}, policy=policy.DEFAULT_POLICY)
    ledger.record(tmp_path, tool="read_events", args={}, decision=d)
    ledger.record(tmp_path, tool="read_events", args={}, decision=d)
    path = ledger.ledger_path(tmp_path)
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n")
    assert ledger.verify(tmp_path)["ok"] is False


# ---------------------------------------------------------------------------
# Response plane
# ---------------------------------------------------------------------------

def test_protected_path_spellings_are_refused():
    for target in (
        r"C:\Windows\System32.\kernel32.dll",
        r"C:\Windows\System32 \kernel32.dll",
        r"C:\PROGRA~1\Whids\whids.exe",
    ):
        with pytest.raises((ValueError, PermissionError)):
            actuate._v_path(target)


def test_protected_plasma_tasks_are_refused():
    for task in ("PlasmaWatch", "PlasmaUpdate", "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag"):
        with pytest.raises(PermissionError):
            actuate._g_task(task)


def test_plan_ttl_rejects_an_old_dry_run(tmp_path):
    dry = actuate.execute("snapshot", tmp_path, reason="test")
    rows = actuate.journal_read(tmp_path)
    for row in rows:
        if row.get("id") == dry["id"]:
            row["ts"] = "2020-01-01T00:00:00+00:00"
    actuate._journal_append = actuate._journal_append  # keep API visible
    # Rewrite the journal with the old timestamp.
    path = actuate.journal_path(tmp_path)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    res = actuate.execute("snapshot", tmp_path, reason="test",
                          apply=True, plan=dry["id"])
    assert res["code"] == "REFUSED" and "older" in res["error"]


def test_enforce_does_not_queue_policy_denied_findings(tmp_path):
    (tmp_path / "config.json").write_text(json.dumps(
        {"enforcement": {"enabled": True, "mode": "enforce",
                         "min_score": 9}}))
    finding = {"type": "chain_injection_chain", "score": 3, "technique": "T1055",
               "pid": 7}
    out = enforce.run(tmp_path, findings=[finding])
    assert out["pending"] == 0
    assert out["results"][0]["status"] == "denied"


def test_enforce_approve_rechecks_policy(tmp_path):
    (tmp_path / "config.json").write_text(json.dumps(
        {"enforcement": {"enabled": True, "mode": "enforce"}}))
    out = enforce.run(tmp_path, findings=[{
        "type": "canary_tripped", "score": 10}])
    entry = out["results"][0]
    (tmp_path / "config.json").write_text(json.dumps(
        {"enforcement": {"enabled": False, "mode": "dry-run"}}))
    res = enforce.approve(tmp_path, entry["id"], apply=True)
    assert res["error"] and "disabled" in res["error"]


# ---------------------------------------------------------------------------
# Collection and data paths
# ---------------------------------------------------------------------------

def test_tap_normalization_redacts_script_and_command_line():
    event = tap.normalize_match({
        "rule": "r", "provider": "Microsoft-Windows-PowerShell",
        "event_id": 4104,
        "props": {"ScriptBlockText": "$x='password=hunter2'",
                  "CommandLine": "run --password hunter2"}})
    assert "hunter2" not in event["cmdline"]
    assert "hunter2" not in event["description"]


def test_whids_skips_malformed_rows_and_keeps_distinct_content(tmp_path):
    root = tmp_path / "whids"
    alerts = root / "Logs" / "Alerts" / "2026-01-01"
    alerts.mkdir(parents=True)
    rows = [
        {"Event": {"EventID": "bad"}},
        {"Event": {"EventID": 1, "SystemTime": "2026-01-01T00:00:00Z",
                   "GeneInfo": {"Criticality": 9, "Signature": ["Run key"],
                                "EventData": {"TargetObject": "Run\\A"}}}},
        {"Event": {"EventID": 1, "SystemTime": "2026-01-01T00:00:00Z",
                   "GeneInfo": {"Criticality": 9, "Signature": ["Run key"],
                                "EventData": {"TargetObject": "Run\\B"}}}},
    ]
    (alerts / "alerts.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n")
    out = tmp_path / "data" / "events.jsonl"
    result = __import__("plasma.whids", fromlist=["pull"]).pull(
        root, out, host="WS1")
    assert result["written"] == 2
    assert len(out.read_text().splitlines()) == 2


def test_deep_extracts_executable_from_command_lines():
    out = deep.normalize({"rows": [
        {"source": "run", "name": "evil", "path": r"C:\Users\bob\evil.exe --silent"},
    ], "signatures": {r"c:\users\bob\evil.exe": {"signed": False}}})
    assert out["items"][0]["suspect"] is True


def test_redaction_handles_quoted_and_mysql_secrets():
    from plasma.redact import redact_text
    assert "my secret value" not in redact_text('password = "my secret value"')
    assert "S3cr3t" not in redact_text("mysql -pS3cr3t db")


def test_health_survives_corrupt_config(tmp_path):
    (tmp_path / "config.json").write_text("[]")
    result = health.verdict(tmp_path)
    assert "checks" in result


def test_coverage_ignores_bad_criticality(tmp_path):
    import shutil
    sensors = tmp_path / "sensors"
    shutil.copytree("sensors", sensors)
    with (sensors / "plasma-sigma.gen").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"Tags": ["attack.t1055"],
                             "Meta": {"Criticality": "high"}}) + "\n")
    result = coverage.coverage(sensors)
    assert "error" not in result


def test_trace_validation_strips_comments_and_blocks_copyout():
    text = """/* plasma| */\nproc provider:foo:bar-* { }\n/* name: x */\n"""
    # A verified script with a comment-hidden system() must be refused.
    with pytest.raises(trace.ScriptError):
        trace.validate_script(text + "\nsystem/*x*/('calc');\n")
    with pytest.raises(trace.ScriptError):
        trace.validate_script(text + "\ncopyout('x', 1);\n")


def test_sigma_rejects_gene_quote_injection():
    with pytest.raises(sigma.SigmaError):
        sigma._regex("evil' ; $pwn: CommandLine ~= '.*", "re")


# ---------------------------------------------------------------------------
# Update and deployment
# ---------------------------------------------------------------------------

def test_update_rejects_hash_mismatch_even_with_pinned_signer(monkeypatch):
    class _Out:
        stdout = "ABC123|HashMismatch\n"
        returncode = 0
        stderr = ""
    monkeypatch.setattr(update.shutil, "which", lambda _: "/bin/powershell")
    monkeypatch.setattr(update.subprocess, "run", lambda *a, **k: _Out())
    tmp = Path(__file__).parent / "fixture.exe"
    tmp.write_bytes(b"x")
    try:
        res = update.verify_authenticode(tmp, expected={"ABC123"})
        assert res["ok"] is False and "HashMismatch" in res["error"]
    finally:
        tmp.unlink()


def test_update_orders_prereleases_and_four_part_versions():
    assert update.is_newer("1.19.0-rc2", "1.19.0")
    assert not update.is_newer("1.19.0", "1.19.0-rc2")
    assert update.is_newer("1.2.3", "1.2.3.1")


def test_autoupdate_string_booleans_are_not_truthy(tmp_path):
    (tmp_path / "config.json").write_text(json.dumps(
        {"update": {"auto": "false", "allow_unsigned": "false",
                    "notify": "false"}}))
    cfg = autoupdate.config(tmp_path)
    assert cfg["auto"] is False
    assert cfg["allow_unsigned"] is False
    assert cfg["notify"] is False


def test_broad_ring_default_when_only_canary_pilots_assigned(tmp_path):
    rings.assign(tmp_path, "WS1", "canary")
    assert rings.allows(tmp_path, "WS2", "broad") is True
    assert rings.allows(tmp_path, "WS2", "canary") is False


def test_rollback_prefers_newest_usable_backup(tmp_path):
    bin_exe = tmp_path / "plasma.exe"
    bin_exe.write_text("current")
    old = tmp_path / "plasma.exe.old"
    old.write_text("old")
    newer = tmp_path / "plasma.exe.old.123"
    newer.write_text("newer")
    # Make the unique backup newer.
    import os
    os.utime(old, (1, 1))
    os.utime(newer, (2, 2))
    res = rings.rollback(bin_exe)
    assert res["ok"] is True
    assert bin_exe.read_text() == "newer"


def test_help_catalog_matches_parser_and_examples_are_executable():
    parser = __import__("plasma.cli", fromlist=["build_parser"]).build_parser()
    catalog = helpmod.catalog(parser)
    rows = {row["command"]: row for row in catalog["commands"]}
    # The plan placeholder must be numeric, not an arbitrary hex string.
    for example in rows["actuate apply"]["examples"]:
        if "--plan" in example["command"]:
            assert "7f3a" not in example["command"]
    # sigma convert is a write by default in code; help must say so.
    assert "writes" in rows["sigma convert"]["description"].lower()
