"""Production-hardening tests for the 1.8.0 commercial release.

Each test pins a defect found during the pre-release review: credential
redaction, kill-switch enforcement outside MCP, plan/journal races, broken
WMI undo, quarantine TOCTOU, fail-closed isolation, fleet false positives,
chain user binding, watch alert surfacing, and edge cases in the collectors.
"""

import json
import os
import time
from pathlib import Path

import pytest

from plasma import (actuate, agentstate, canary, chain, deep, fleet, health,
                    identity, killswitch, ledger, mcp, playbooks, policy,
                    store, watch, whids)


def _ok_run(payload, timeout=60):
    return {"rc": 0, "output": "ok", "output_head": "ok"}


# ---------------------------------------------------------------------------
# actuate: secrets, kill switch, plans, quarantine, isolation, WMI
# ---------------------------------------------------------------------------

def test_rotate_credential_is_redacted_from_the_journal(tmp_path, monkeypatch):
    secret = "N3w!Passw0rd-For-Test"
    monkeypatch.setattr(actuate, "_run", lambda payload, timeout=60: {
        "rc": 0,
        "output": "NEW PASSWORD (shown once): " + secret,
        "output_head": "NEW PASSWORD (shown once): " + secret,
    })
    dry = actuate.execute("rotate_credential", tmp_path, target="bob", reason="rotation")
    applied = actuate.execute("rotate_credential", tmp_path, target="bob",
                              reason="rotation", apply=True, plan=dry["id"])
    assert applied["new_password"] == secret
    assert "shown once" in applied["secret_note"]
    raw = (tmp_path / "actuate-journal.jsonl").read_text()
    assert secret not in raw
    assert "redacted" in raw


def test_kill_switch_blocks_apply_but_allows_dry_run(tmp_path, monkeypatch):
    monkeypatch.setattr(actuate, "_run", _ok_run)
    dry = actuate.execute("disable_user", tmp_path, target="bob", reason="drill")
    killswitch.set_global(tmp_path, True, "containment pause")
    blocked = actuate.execute("disable_user", tmp_path, target="bob",
                              reason="drill", apply=True, plan=dry["id"])
    assert blocked["code"] == "KILLSWITCH"
    assert "kill switch" in blocked["error"]
    # planning still works while the switch is engaged
    assert "payload" in actuate.execute("disable_user", tmp_path, target="bob",
                                        reason="drill")


def test_kill_switch_host_match_is_case_insensitive(tmp_path):
    killswitch.set_host(tmp_path, "WS1", True, "pause")
    assert killswitch.blocked(tmp_path, host="ws1", risk="medium") is True


def test_quarantine_refuses_core_windows_paths(tmp_path):
    res = actuate.execute("quarantine_file", tmp_path,
                          target=r"C:\Windows\System32\cmd.exe", reason="x")
    assert res["code"] == "REFUSED"
    assert "protected path" in res["error"]


def test_quarantine_plan_is_hash_pinned_and_destination_is_unique(monkeypatch):
    monkeypatch.setattr(actuate, "_file_sha256", lambda p: "a" * 64)
    payload, undo, _ = actuate._build_quarantine(r"C:\Users\Public\evil.exe")
    assert "a" * 64 in payload
    assert "source file changed since the plan" in payload
    assert "quarantine destination already exists" in payload
    assert "refusing to overwrite" in undo
    payload2, _, _ = actuate._build_quarantine(r"C:\Temp\evil.exe")
    assert payload != payload2          # different source -> different dest


def test_isolation_verifies_management_allows_before_booking_blocks():
    payload, undo, _ = actuate._build_isolate()
    assert "$ErrorActionPreference = 'Stop'" in payload
    check = payload.index("management allow rules missing")
    first_block = payload.index("Plasma Isolate Block Inbound")
    assert check < first_block, "allow-rule check must precede block creation"
    # undo lifts blocks first, then the management allows
    assert undo.index("Block Inbound") < undo.index("Allow RDP")


def test_wmi_capture_and_undo_use_names_not_serialized_cim_objects():
    payload, capture, _ = actuate._build_disable_wmi_sub()
    assert "filter_name=$_.Filter.Name" in payload
    assert "consumer_class=$_.Consumer.CimClass.CimClassName" in payload

    entry = {"undo": {"kind": "wmi_bindings", "bindings": [
        {"filter_name": "F1", "consumer_name": "C1",
         "consumer_class": "CommandLineEventConsumer"}]}}
    undo_payload, err = actuate._undo_payload(entry)
    assert err is None
    assert "Get-CimInstance" in undo_payload
    assert "__EventFilter" in undo_payload
    assert "Name=''F1''" in undo_payload
    assert "New-CimInstance" in undo_payload
    assert "CimClass" not in undo_payload


def test_journal_ids_never_reuse_an_id_after_a_torn_line(tmp_path):
    journal = tmp_path / "actuate-journal.jsonl"
    journal.write_text('{"id": 7, "action": "x", "mode": "dry-run"}\n'
                       '{"id": 8, "torn\n')
    dry = actuate.execute("block_ip", tmp_path, target="1.2.3.4", reason="x")
    # The torn line is not a usable entry, so id 8 is free; what matters is
    # that the next id is derived from the highest *surviving* id, never
    # from len(rows) (which would hand out 2 here and collide with id 2).
    assert dry["id"] == 8


def test_playbook_refuses_a_truncated_step_plan(tmp_path, monkeypatch):
    monkeypatch.setattr(actuate, "_run", _ok_run)
    dry = playbooks.execute(tmp_path, "contain-user", target="bob", reason="x")
    # Simulate a crash that journaled only the first step of the playbook.
    damaged = {"id": dry["id"] + 1000, "action": "playbook:contain-user",
               "target": "bob", "reason": "x", "mode": "dry-run",
               "steps": dry["steps"][:1]}
    actuate._journal_append(tmp_path, damaged)
    res = playbooks.execute(tmp_path, "contain-user", target="bob", reason="x",
                            apply=True, plan=damaged["id"])
    assert res["code"] == "REFUSED"
    assert "expected 2" in res["error"]


# ---------------------------------------------------------------------------
# chain: user binding and bounded reads
# ---------------------------------------------------------------------------

def _auth(ts, eid, user):
    return {"ts": ts, "kind": "auth", "event_id": eid, "user": user,
            "description": "logon"}


def test_brute_force_success_must_be_the_same_user():
    failures = [_auth(f"2026-11-05T02:0{m}:00Z", 4625, "CORP\\alice")
                for m in range(5)]
    wrong = failures + [_auth("2026-11-05T02:10:00Z", 4624, "bob")]
    assert not [f for f in chain.scan(wrong)
                if f["type"] == "chain_brute_force_success"]
    right = failures + [_auth("2026-11-05T02:10:00Z", 4624, "alice")]
    finding = next(f for f in chain.scan(right)
                   if f["type"] == "chain_brute_force_success")
    assert finding["users"] == ["alice"]


def test_brute_force_does_not_borrow_another_users_failures():
    rows = ([_auth(f"2026-11-05T02:0{m}:00Z", 4625, "alice") for m in range(3)]
            + [_auth(f"2026-11-05T02:0{m}:00Z", 4625, "bob") for m in range(2)]
            + [_auth("2026-11-05T02:10:00Z", 4624, "bob")])
    assert not [f for f in chain.scan(rows)
                if f["type"] == "chain_brute_force_success"]


def test_scan_store_tail_read_still_finds_recent_stories(tmp_path):
    store_path = tmp_path / "events.jsonl"
    rows = [{"ts": "2026-11-01T00:00:00Z", "kind": "dns", "dns_query": "x"}
            for _ in range(100)]
    rows += [
        {"ts": "2026-11-05T10:00:00Z", "kind": "process",
         "process": r"C:\Program Files\Microsoft Office\winword.exe"},
        {"ts": "2026-11-05T10:01:00Z", "kind": "process",
         "process": r"C:\Windows\System32\powershell.exe",
         "description": "powershell -enc SQBFAFgA"},
        {"ts": "2026-11-05T10:02:00Z", "kind": "network", "dest_ip": "203.0.113.9"},
    ]
    store_path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    result = chain.scan_store(store_path, max_rows=50)
    assert result["findings"], result


# ---------------------------------------------------------------------------
# watch: high-criticality alert surfacing
# ---------------------------------------------------------------------------

def _alert(criticality, rule="Plasma Encoded Cmd"):
    return {
        "SystemTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "Computer": "WS1",
        "EventID": 1,
        "EventData": {"Image": r"C:\Windows\Temp\a.exe", "ProcessId": "42"},
        "Event": {"GeneInfo": {"Signature": [rule],
                               "Criticality": criticality, "Actions": []}},
    }


def _quiet_sweep(tmp_path, monkeypatch, alerts_dir):
    monkeypatch.setattr(watch, "ALERTS_DIR", alerts_dir)
    monkeypatch.setattr(health, "verdict",
                        lambda r: {"status": "ok", "failed": [], "checks": []})
    monkeypatch.setattr(watch.observatory, "run_question",
                        lambda q, **k: {"question": q, "blind_count": 0})
    monkeypatch.setattr("plasma.drift.load", lambda root, name: None)
    return watch.sweep(tmp_path)


def test_watch_surfaces_a_single_high_criticality_alert_once(tmp_path, monkeypatch):
    alerts = tmp_path / "alerts"
    alerts.mkdir()
    f = alerts / "alerts.jsonl"
    f.write_text(json.dumps(_alert(9)) + "\n")
    first = _quiet_sweep(tmp_path, monkeypatch, alerts)
    # First sight initializes at end-of-file (no history flood).
    assert not [x for x in first["findings"]
                if x["type"] == "whids_high_criticality"]
    with f.open("a") as fh:
        fh.write(json.dumps(_alert(9)) + "\n")
    second = _quiet_sweep(tmp_path, monkeypatch, alerts)
    high = [x for x in second["findings"] if x["type"] == "whids_high_criticality"]
    assert high and high[0]["score"] == 9
    third = _quiet_sweep(tmp_path, monkeypatch, alerts)
    assert not [x for x in third["findings"]
                if x["type"] == "whids_high_criticality"]


def test_watch_ignores_low_criticality_alerts(tmp_path, monkeypatch):
    alerts = tmp_path / "alerts"
    alerts.mkdir()
    f = alerts / "alerts.jsonl"
    f.write_text("")
    _quiet_sweep(tmp_path, monkeypatch, alerts)
    f.write_text(json.dumps(_alert(5)) + "\n")
    res = _quiet_sweep(tmp_path, monkeypatch, alerts)
    assert not [x for x in res["findings"]
                if x["type"] == "whids_high_criticality"]


def test_watch_alert_offsets_reset_after_rotation(tmp_path, monkeypatch):
    alerts = tmp_path / "alerts"
    alerts.mkdir()
    f = alerts / "alerts.jsonl"
    f.write_text(json.dumps(_alert(9)) + "\n")
    _quiet_sweep(tmp_path, monkeypatch, alerts)
    # a smaller file is a rotated/truncated log: read it from the beginning
    f.write_text(json.dumps(_alert(9, "Plasma Net Account Add")) + "\n")
    res = _quiet_sweep(tmp_path, monkeypatch, alerts)
    assert [x for x in res["findings"] if x["type"] == "whids_high_criticality"]


# ---------------------------------------------------------------------------
# collectors: deep, identity, health, store, canary
# ---------------------------------------------------------------------------

def test_deep_unsigned_windows_binary_is_not_suspect():
    payload = {"rows": [
        {"source": "service", "name": "WindowsThing", "detail": "",
         "path": r"C:\Windows\System32\thing.exe"},
        {"source": "run_key", "name": "Dropper", "detail": "",
         "path": r"C:\Users\Public\evil.exe"},
        {"source": "service", "name": "Folder", "detail": "",
         "path": r"C:\Users\Public"},
    ], "signatures": {
        r"c:\windows\system32\thing.exe": {"signed": False},
        r"c:\users\public\evil.exe": {"signed": False},
        r"c:\users\public": {"signed": False},
    }}
    result = deep.normalize(payload)
    assert result["suspect_count"] == 1
    assert result["suspects"][0]["name"] == "Dropper"


def test_identity_dash_domain_is_not_a_real_domain():
    event = identity.normalize_logon({
        "event_id": 4624, "ts": "2026-11-05T10:00:00Z",
        "domain": "-", "user": "Administrator", "logonType": 3}, "WS1")
    assert event["user"] == "Administrator"


def test_identity_drops_records_without_a_timestamp():
    with pytest.raises(ValueError):
        identity.normalize_logon({"event_id": 4624, "user": "bob", "ts": ""}, "WS1")


def test_health_flags_an_existing_but_empty_store(tmp_path, monkeypatch):
    ev = tmp_path / "events.jsonl"
    ev.write_text("")
    (tmp_path / "config.json").write_text(json.dumps({
        "events_path": str(ev), "sensors": {"whids": {"status": "active"}}}))
    monkeypatch.setattr(health, "IS_WINDOWS", True)
    monkeypatch.setattr(health, "_ps", lambda s, timeout=60: (
        "Running" if "Get-Service" in s else "deny=0;layer=1;cert=True"))
    monkeypatch.setattr(health, "_newest_event_age_minutes", lambda c: 1.0)
    monkeypatch.setattr("plasma.cli._locate_tap_exe", lambda: Path("tap"))
    v = health.verdict(tmp_path)
    hb = [c for c in v["checks"] if c["check"] == "sensor_heartbeat"]
    assert hb and hb[0]["ok"] is False and "empty" in hb[0]["detail"]
    assert v["status"] == "degraded"


def test_store_rotation_returns_an_error_instead_of_raising(tmp_path, monkeypatch):
    p = tmp_path / "events.jsonl"
    p.write_text("x" * (2 * 1024 * 1024))
    real_rename = Path.rename

    def locked(self, target):
        if str(target).endswith(".1"):
            raise OSError("file is in use")
        return real_rename(self, target)

    monkeypatch.setattr(Path, "rename", locked)
    res = store.rotate(p, max_mb=1, keep=2)
    assert res["rotated"] is False and "rotation failed" in res["error"]


def test_canary_manifest_does_not_duplicate_on_redeploy(tmp_path):
    first = canary.deploy(tmp_path)
    second = canary.deploy(tmp_path)
    data = json.loads((tmp_path / "canaries.json").read_text())
    assert len(data["canaries"]) == first["deployed"] == second["deployed"]
    assert all(Path(c["path"]).is_absolute() for c in data["canaries"])


def test_canary_deploy_is_blocked_by_the_kill_switch(tmp_path):
    killswitch.set_global(tmp_path, True, "pause")
    assert canary.deploy(tmp_path)["code"] == "KILLSWITCH"


# ---------------------------------------------------------------------------
# MCP / ledger
# ---------------------------------------------------------------------------

def test_rate_limit_counts_actions_not_reads(tmp_path):
    read = policy.evaluate("read_events", {}, {"scopes": ["*"]})
    write = policy.evaluate("contain_user", {"user": "bob"}, {"scopes": ["*"]})
    for _ in range(5):
        ledger.record(tmp_path, tool="read_events", args={}, decision=read)
    ledger.record(tmp_path, tool="contain_user", args={"user": "bob"},
                  decision=write)
    assert ledger.count_recent(tmp_path, 60, mutating_only=True) == 1


def test_approval_is_scoped_to_its_tenant(tmp_path):
    decision = policy.evaluate("contain_user", {"user": "bob"},
                               {"scopes": ["*"]})
    row = ledger.record(tmp_path, tool="contain_user", args={"user": "bob"},
                        decision=decision, context={"tenant": "acme"})
    ledger.approve(tmp_path, row["seq"], "ciso")
    args_sha = agentstate.sha256_obj({"tool": "contain_user",
                                      "args": {"user": "bob"}})
    assert ledger.consume_approval(tmp_path, row["seq"], "contain_user",
                                   args_sha, tenant="beta") is None
    assert ledger.consume_approval(tmp_path, row["seq"], "contain_user",
                                   args_sha, tenant="acme") is not None


def test_mcp_local_mutation_uses_local_host_for_killswitch(tmp_path, monkeypatch):
    import socket
    killswitch.set_host(tmp_path, socket.gethostname(), True, "pause")
    res = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "contain_user",
                                 "arguments": {"user": "bob"}}}, root=tmp_path)
    payload = json.loads(res["result"]["content"][0]["text"])
    assert payload["code"] == "DENIED"
    assert "kill switch" in " ".join(payload["reasons"]).lower()


# ---------------------------------------------------------------------------
# CLI exit-code contract
# ---------------------------------------------------------------------------

def test_cli_actuate_apply_refusal_is_exit_two(tmp_path, capsys):
    from argparse import Namespace
    from plasma import cli
    args = Namespace(action="quarantine_file", root=tmp_path,
                     target=r"C:\Windows\System32\cmd.exe", reason="x",
                     apply=True, plan=1, timeout=60)
    assert cli.cmd_actuate_apply(args) == 2
    capsys.readouterr()


# ---------------------------------------------------------------------------
# WHIDS: dump-tree retention and orphan recovery
# ---------------------------------------------------------------------------

def test_prune_dumps_bounds_size_oldest_first(tmp_path):
    dumps = tmp_path / "Whids" / "Dumps" / "g1"
    dumps.mkdir(parents=True)
    now = time.time()
    for i in range(3):
        f = dumps / f"d{i}.bin"
        f.write_bytes(b"x" * (2 * 1024 * 1024))
        # oldest -> newest
        os.utime(f, (now - (3 - i) * 3600, now - (3 - i) * 3600))
    keep = tmp_path / "keep.txt"
    keep.write_text("not a dump")
    res = whids.prune_dumps(tmp_path / "Whids", max_mb=3, keep_days=1)
    assert res["removed_files"] == 2
    assert res["remaining_bytes"] <= 3 * 1024 * 1024
    assert (dumps / "d2.bin").exists()
    assert keep.exists()


def test_prune_dumps_dry_run_deletes_nothing(tmp_path):
    dumps = tmp_path / "Whids" / "Dumps"
    dumps.mkdir(parents=True)
    (dumps / "a.bin").write_bytes(b"x" * 1024)
    res = whids.prune_dumps(tmp_path / "Whids", max_mb=0, dry_run=True)
    assert res["removed_files"] == 1 and (dumps / "a.bin").exists()


def test_ensure_force_kills_an_orphan_then_retries(monkeypatch):
    seq = iter(["StartPending", "StartPending", "Running"])
    calls = []
    monkeypatch.setattr(whids, "_whids_service_name", lambda: "Whids")
    monkeypatch.setattr(whids, "_service_state", lambda name=None: next(seq))
    monkeypatch.setattr(whids, "_ps",
                        lambda script, timeout=60: calls.append(script) or (0, ""))
    monkeypatch.setattr(whids, "prune_dumps", lambda *a, **k: {"removed_files": 0})
    monkeypatch.setattr(whids, "_watchdog_log", lambda root, result: None)
    monkeypatch.setattr("time.sleep", lambda seconds: None)
    res = whids.ensure(wait_seconds=0)
    assert res["ok"] is True and res["state"] == "Running"
    actions = [a["action"] for a in res["actions"]]
    assert "force_kill_orphan" in actions and "start_retry" in actions
    assert any("Stop-Process" in c for c in calls)


def test_diagnose_uses_the_install_dir_next_to_the_binary(tmp_path, monkeypatch):
    install = tmp_path / "Program Files" / "Whids"
    (install / "Logs").mkdir(parents=True)
    exe = install / "whids.exe"
    exe.write_bytes(b"MZ")
    (install / "config.toml").write_text("channels = []\n")
    (install / "Logs" / "whids.log").write_text("live\n")
    monkeypatch.setattr(whids, "_whids_service_name", lambda: "Whids")
    monkeypatch.setattr(whids.subprocess, "run", lambda cmd, **kw: (
        __import__("subprocess").CompletedProcess(
            cmd, 0,
            stdout=json.dumps({"state": "Stopped", "startMode": "Auto",
                               "pathName": f'"{exe}" -c config.toml',
                               "hang": False, "channels": [],
                               "serviceErrors": []}), stderr="")))
    res = whids.diagnose(tmp_path / "Plasma")
    assert res["install_dir"] == str(install)
    assert res["config_present"] is True
    assert res["log_tail"] == ["live"]


# ---------------------------------------------------------------------------
# WHIDS: conservative benign-context suppression
# ---------------------------------------------------------------------------

def _whids_record(rule, event_data, criticality=9):
    return {
        "SystemTime": "2026-11-05T10:00:00Z",
        "Computer": "WS1", "EventID": 1,
        "EventData": event_data,
        "Event": {"GeneInfo": {"Signature": [rule],
                               "Criticality": criticality, "Actions": []}},
    }


def test_signed_microsoft_binary_in_user_path_is_suppressed():
    rec = _whids_record("Plasma Execution From User Paths", {
        "Image": r"C:\Users\olu\AppData\Local\Microsoft\Teams\Teams.exe",
        "Signed": "Microsoft Windows", "Company": "Microsoft Corporation"})
    e = whids.normalize_alert(rec, host="WS1")
    assert e["suppressed"] and e["score"] == 0.2
    assert e["severity"] == "info"


def test_unsigned_binary_in_user_path_keeps_full_severity():
    rec = _whids_record("Plasma Execution From User Paths", {
        "Image": r"C:\Users\olu\Downloads\invoice.exe",
        "Signed": "Unavailable", "Company": ""})
    e = whids.normalize_alert(rec, host="WS1")
    assert not e.get("suppressed")
    assert e["score"] == 0.9 and e["severity"] == "critical"


def test_msiexec_run_key_write_is_suppressed():
    rec = _whids_record("Plasma Run Key Persistence", {
        "Image": r"C:\Windows\System32\msiexec.exe",
        "TargetObject": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Vendor"})
    e = whids.normalize_alert(rec, host="WS1")
    assert e["suppressed"] and e["score"] == 0.2


def test_attacker_run_key_write_is_not_suppressed():
    rec = _whids_record("Plasma Run Key Persistence", {
        "Image": r"C:\Users\Public\dropper.exe",
        "TargetObject": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Updater"})
    e = whids.normalize_alert(rec, host="WS1")
    assert not e.get("suppressed") and e["score"] == 0.9


def test_system_encoded_task_is_suppressed_but_user_encoded_is_not():
    benign = _whids_record("Plasma Encoded Cmd", {
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "ParentImage": r"C:\Windows\System32\svchost.exe",
        "User": "NT AUTHORITY\\SYSTEM",
        "CommandLine": "powershell -enc SQBFAFgA"})
    assert whids.normalize_alert(benign)["suppressed"]
    attacker = _whids_record("Plasma Encoded Cmd", {
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "ParentImage": r"C:\Windows\explorer.exe",
        "User": "CORP\\olu",
        "CommandLine": "powershell -enc SQBFAFgA"})
    assert not attacker or not whids.normalize_alert(attacker).get("suppressed")


def test_prune_dumps_moves_a_huge_tree_out_of_the_install_dir(tmp_path):
    install = tmp_path / "Program Files" / "Whids"
    dumps = install / "Dumps" / "g1"
    dumps.mkdir(parents=True)
    for i in range(5):
        (dumps / f"d{i}.bin").write_bytes(b"x")
    archive = tmp_path / "archive"
    res = whids.prune_dumps(install, max_files=2, archive_dir=archive)
    assert res["moved_dirs"], res
    assert (install / "Dumps").is_dir()
    assert (install / "Dumps").exists()
    assert not list((install / "Dumps").rglob("*.bin"))
    assert list(archive.rglob("*.bin"))


def test_prune_dumps_moves_legacy_pruned_dirs_out_of_install(tmp_path):
    install = tmp_path / "Whids"
    legacy = install / "Dumps.pruned-20260101-000000" / "g1"
    legacy.mkdir(parents=True)
    (legacy / "old.bin").write_bytes(b"x")
    archive = tmp_path / "archive"
    res = whids.prune_dumps(install, archive_dir=archive)
    assert res["moved_dirs"]
    assert not (install / "Dumps.pruned-20260101-000000").exists()
    assert list(archive.rglob("old.bin"))


def test_signed_lolbin_run_key_write_is_not_suppressed():
    """reg.exe is Microsoft-signed but is the technique, not an installer."""
    rec = _whids_record("Plasma Run Key Persistence", {
        "Image": r"C:\Windows\System32\reg.exe",
        "Signed": "Microsoft Windows", "Company": "Microsoft Corporation",
        "TargetObject": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Updater"})
    e = whids.normalize_alert(rec, host="WS1")
    assert not e.get("suppressed") and e["score"] == 0.9


def test_microsoft_service_binary_service_key_write_is_suppressed():
    rec = _whids_record("Plasma Service Registry Persistence", {
        "Image": r"C:\Windows\System32\dns.exe",
        "Signed": "Microsoft Windows", "Company": "Microsoft Corporation",
        "TargetObject": r"HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters"})
    e = whids.normalize_alert(rec, host="WS1")
    assert e["suppressed"] and e["score"] == 0.2


def test_sc_exe_service_key_write_keeps_full_severity():
    rec = _whids_record("Plasma Service Registry Persistence", {
        "Image": r"C:\Windows\System32\sc.exe",
        "Signed": "Microsoft Windows", "Company": "Microsoft Corporation",
        "TargetObject": r"HKLM\SYSTEM\CurrentControlSet\Services\Evil"})
    e = whids.normalize_alert(rec, host="WS1")
    assert not e.get("suppressed") and e["score"] == 0.9


def test_alert_files_skips_compressed_and_archived_logs(tmp_path):
    alerts = tmp_path / "Logs" / "Alerts"
    alerts.mkdir(parents=True)
    (alerts / "alerts.log").write_text("{}\n")
    (alerts / "alerts.log.1").write_text("{}\n")
    (alerts / "alerts.log.2.gz").write_bytes(b"\x1f\x8bnot-json")
    (alerts / "Alerts.old-20260101").mkdir()
    (alerts / "Alerts.old-20260101" / "alerts.log").write_text("{}\n")
    names = {p.name for p in whids.alert_files(str(tmp_path))}
    assert names == {"alerts.log", "alerts.log.1"}


def test_windows_service_path_without_signature_metadata_is_suppressed():
    """Registry events often omit Signed/Company; the System32 path is the
    positive evidence that keeps dns.exe/lsass.exe writes out of the noise."""
    rec = _whids_record("Plasma Service Registry Persistence", {
        "Image": r"C:\Windows\System32\dns.exe",
        "TargetObject": r"HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters"})
    e = whids.normalize_alert(rec, host="WS1")
    assert e["suppressed"] and e["score"] == 0.2
    evil = _whids_record("Plasma Service Registry Persistence", {
        "Image": r"C:\Windows\Temp\svc.exe",
        "TargetObject": r"HKLM\SYSTEM\CurrentControlSet\Services\Evil"})
    assert not whids.normalize_alert(evil).get("suppressed")


def test_adfs_service_binary_is_suppressed_but_windows_temp_is_not():
    adfs = _whids_record("Plasma Service Registry Persistence", {
        "Image": r"C:\Windows\ADFS\Microsoft.ActiveDirectory.WebServices.exe",
        "TargetObject": r"HKLM\SYSTEM\CurrentControlSet\Services\ADFS"})
    assert whids.normalize_alert(adfs)["suppressed"]
    temp = _whids_record("Plasma Service Registry Persistence", {
        "Image": r"C:\Windows\Temp\svc.exe",
        "TargetObject": r"HKLM\SYSTEM\CurrentControlSet\Services\Evil"})
    assert not whids.normalize_alert(temp).get("suppressed")


def test_storm_coalescing_keeps_samples_and_one_summary():
    events = []
    for i in range(100):
        events.append({"ts": f"2026-11-14T06:00:{i % 60:02d}Z",
                       "alert_id": "Plasma-Service-Registry-Persistence",
                       "process": "opencode.exe", "user": "SYSTEM",
                       "registry_path": r"HKLM\System\CurrentControlSet\Services\Tcpip\Parameters",
                       "image": r"C:\Users\olu\AppData\opencode.exe",
                       "score": 0.8, "severity": "high"})
    out, groups = whids.coalesce_storms(events, threshold=25, samples=2)
    assert groups == 1
    assert len(out) == 4          # 2 samples + last + summary
    summary = out[-1]
    assert summary["storm_count"] == 100
    assert summary["storm"] is True
    assert summary["score"] == 0.8


def test_pull_coalesces_a_storm_and_is_idempotent(tmp_path):
    alerts = tmp_path / "Logs" / "Alerts"
    alerts.mkdir(parents=True)
    rec = _alert(9)
    rows = []
    for i in range(60):
        r = json.loads(json.dumps(rec))
        r["SystemTime"] = f"2026-11-14T06:00:{i % 60:02d}Z"
        rows.append(json.dumps(r))
    (alerts / "alerts.log").write_text("\n".join(rows) + "\n")
    out = tmp_path / "events.jsonl"
    first = whids.pull(str(tmp_path), out=str(out))
    assert first["storm_groups"] == 1
    assert first["written"] <= whids.STORM_SAMPLES + 2
    stored = [json.loads(l) for l in out.read_text().splitlines()]
    assert any(e.get("storm_count") == 60 for e in stored)
    second = whids.pull(str(tmp_path), out=str(out))
    assert second["written"] == 0


def test_storm_window_is_time_sorted_across_files():
    events = []
    for ts in ["2026-11-14T06:00:30Z", "2026-11-14T06:00:10Z",
               "2026-11-14T06:00:50Z"] * 10:
        events.append({"ts": ts, "alert_id": "Plasma-Encoded-Cmd",
                       "process": "notepad.exe", "user": "SYSTEM",
                       "registry_path": "", "image": r"C:\Windows\notepad.exe",
                       "score": 0.9, "severity": "critical"})
    out, _ = whids.coalesce_storms(events, threshold=5, samples=2)
    storm = out[-1]
    assert storm["storm_first_ts"] == "2026-11-14T06:00:10Z"
    assert storm["ts"] == "2026-11-14T06:00:50Z"


def test_pull_updates_the_watch_backlog_counter(tmp_path):
    alerts = tmp_path / "Whids" / "Logs" / "Alerts"
    alerts.mkdir(parents=True)
    (alerts / "alerts.log").write_text(json.dumps(_alert(9)) + "\n")
    out = tmp_path / "Plasma" / "data" / "events.jsonl"
    whids.pull(str(tmp_path / "Whids"), out=str(out))
    state = json.loads((tmp_path / "Plasma" / "watch-alerts-state.json").read_text())
    assert state["seen_alert_rows"] == 1
