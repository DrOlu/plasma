"""Observatory + drift + actuate tests.

These run anywhere: the PowerShell payloads themselves are validated as
strings (structure, read-only posture, JSON termination), and the Python
logic (validation, journaling, drift scoring, undo) is exercised with a
mocked runner so no Windows host is needed.
"""

import json

import pytest

from plasma import observatory, actuate, drift


# ---------------------------------------------------------------------------
# observatory: payload hygiene
# ---------------------------------------------------------------------------

def test_question_catalog():
    qs = observatory.questions()
    for required in ("attest", "sketch", "edges", "explain", "pslogs",
                     "attackmap", "regedges", "flowstats", "canary",
                     "sysmon_health"):
        assert required in qs


@pytest.mark.parametrize("name", observatory.questions())
def test_payloads_terminate_in_json(name):
    payload = observatory.QUESTIONS[name](("plasma-canary",))
    stripped = payload.strip()
    assert stripped.endswith("$ans | ConvertTo-Json -Depth 6 -Compress"), name


@pytest.mark.parametrize("name", observatory.questions())
def test_payloads_are_read_only(name):
    payload = observatory.QUESTIONS[name](("plasma-canary",)).lower()
    for write_verb in ("new-netfirewallrule", "stop-", "disable-", "remove-",
                       "unregister-", "set-localuser", "set-service",
                       "set-itemproperty", "invoke-expression"):
        assert write_verb not in payload, f"{name} contains {write_verb}"


def test_unknown_question_is_data():
    answer = observatory.run_question("nope")
    assert "error" in answer and "questions" in answer


# ---------------------------------------------------------------------------
# drift: baseline + scoring with synthetic answers
# ---------------------------------------------------------------------------

BASE_ATTEST = {
    "question": "attest", "host": "WS1", "blind_count": 0,
    "blind_subcategories": [],
    "sysmon_service": "Running", "whids_service": "Running",
    "logon_ok_24h": 40, "logon_fail_24h": 2, "admin_fail_24h": 0,
}

BASE_SKETCH = {
    "question": "sketch", "host": "WS1",
    "administrators": ["WS1\\Administrator", "WS1\\olu"],
    "admin_group_adds_24h": [], "admin_group_adds_total_24h": 0,
    "services_installed_24h": [{"name": "whids", "path": "C:\\Program Files\\Whids\\whids.exe"}],
    "system_services_unusual": [],
    "tasks_created_24h": [], "untrusted_drivers": [],
}

BASE_ATTACKMAP = {
    "question": "attackmap",
    "findings": [
        {"technique": "T1547.001", "location": "HKLM:...\\Run\\OneDrive", "value": "x"},
        {"technique": "T1547.004", "location": "Winlogon\\Shell", "value": "explorer.exe"},
    ],
}


def _fresh_root(tmp_path):
    return tmp_path / "plasma"


def test_drift_record_and_list(tmp_path):
    root = _fresh_root(tmp_path)
    out = drift.record(root, "attest", BASE_ATTEST)
    assert out["ok"] is True
    assert drift.baselines(root) == ["attest"]
    blob = drift.load(root, "attest")
    assert blob["answer"]["blind_count"] == 0
    # failed answers are refused
    assert "error" in drift.record(root, "attest", {"error": "collector timeout"})


def test_drift_score_clean(tmp_path):
    root = _fresh_root(tmp_path)
    drift.record(root, "attest", BASE_ATTEST)
    result = drift.score(root, "attest", dict(BASE_ATTEST))
    assert result["drift"] == []
    assert result["verdict"] == "clean"
    assert result["top_score"] == 0


def test_drift_score_sensor_down_and_blind(tmp_path):
    root = _fresh_root(tmp_path)
    drift.record(root, "attest", BASE_ATTEST)
    now = dict(BASE_ATTEST, whids_service="Stopped", blind_count=2,
               blind_subcategories=["Registry", "File Share"])
    result = drift.score(root, "attest", now)
    types = {d["type"]: d for d in result["drift"]}
    assert types["sensor_down"]["score"] == 10
    assert types["blind_drift"]["score"] == 8
    assert result["verdict"] == "act now"


def test_drift_score_admin_added(tmp_path):
    root = _fresh_root(tmp_path)
    drift.record(root, "sketch", BASE_SKETCH)
    now = dict(BASE_SKETCH,
               administrators=BASE_SKETCH["administrators"] + ["WS1\\helpdesk"],
               services_installed_24h=BASE_SKETCH["services_installed_24h"]
               + [{"name": "evil-svc", "path": "C:\\Temp\\x.exe"}])
    result = drift.score(root, "sketch", now)
    types = {d["type"] for d in result["drift"]}
    assert types == {"admin_added", "new_service"}
    admin = next(d for d in result["drift"] if d["type"] == "admin_added")
    assert admin["detail"] == ["WS1\\helpdesk"]
    assert result["verdict"] == "act now"


def test_drift_score_new_persistence(tmp_path):
    root = _fresh_root(tmp_path)
    drift.record(root, "attackmap", BASE_ATTACKMAP)
    now = dict(BASE_ATTACKMAP, findings=BASE_ATTACKMAP["findings"]
               + [{"technique": "T1546.012", "location": "IFEO\\svchost.exe\\Debugger", "value": "cmd.exe"}])
    result = drift.score(root, "attackmap", now)
    assert result["drift"][0]["type"] == "new_persistence"
    assert result["top_score"] == 9


def test_drift_score_canary_trips_even_without_baseline_hits(tmp_path):
    root = _fresh_root(tmp_path)
    drift.record(root, "canary", {"question": "canary", "hit_count": 0, "hits": []})
    now = {"question": "canary", "hit_count": 1,
           "hits": [{"user": "plasma-canary", "source_ip": "10.0.0.9"}]}
    result = drift.score(root, "canary", now)
    assert result["drift"][0]["type"] == "canary_tripped"
    assert result["top_score"] == 10


def test_drift_missing_baseline_is_helpful(tmp_path):
    result = drift.score(_fresh_root(tmp_path), "edges", {"question": "edges"})
    assert "error" in result and "drift record" in result["hint"]


# ---------------------------------------------------------------------------
# actuate: allowlist, validation, journal, undo — runner mocked out
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_run(monkeypatch):
    """Replace _run with a canned responder; returns the calls list."""
    calls = []

    def fake_run(payload, timeout=60):
        calls.append(payload)
        if payload.startswith("New-NetFirewallRule -DisplayName 'Plasma Block"):
            return {"rc": 0, "output": '{"DisplayName":"Plasma Block 1.2.3.4 In"}',
                    "output_head": '{"DisplayName":"Plasma Block 1.2.3.4 In"}'}
        if payload.startswith("Remove-NetFirewallRule"):
            return {"rc": 0, "output": "removed", "output_head": "removed"}
        return {"rc": 0, "output": "ok", "output_head": "ok"}

    monkeypatch.setattr(actuate, "_run", fake_run)
    return calls


def test_actuate_allowlist_shape():
    actions = actuate.actions()
    for required in ("block_ip", "isolate_host", "disable_user", "remove_admin",
                     "kill_process", "quarantine_file", "stop_service",
                     "delete_task", "disable_wmi_sub", "rotate_credential",
                     "snapshot"):
        assert required in actions


def test_actuate_dry_run_is_default_and_journaled(tmp_path, mock_run):
    root = _fresh_root(tmp_path)
    entry = actuate.execute("block_ip", root, target="1.2.3.4", reason="C2 callback")
    assert entry["mode"] == "dry-run"
    assert entry["payload"].startswith("New-NetFirewallRule")
    assert mock_run == []                       # nothing executed
    assert len(actuate.journal_read(root)) == 1  # but it is journaled


def test_actuate_requires_reason(tmp_path, mock_run):
    result = actuate.execute("block_ip", tmp_path, target="1.2.3.4")
    assert "error" in result and "reason" in result["error"]


def test_actuate_target_validation(tmp_path, mock_run):
    assert "error" in actuate.execute("block_ip", tmp_path, target="999.1.1.1", reason="x")
    assert "error" in actuate.execute("block_ip", tmp_path, target="not-an-ip", reason="x")
    assert "error" in actuate.execute("disable_user", tmp_path, target="dom\\bob", reason="x")
    assert "error" in actuate.execute("kill_process", tmp_path, target="rm -rf", reason="x")
    assert "error" in actuate.execute("stop_service", tmp_path, target="bad name!", reason="x")


def test_actuate_protected_lists(tmp_path, mock_run):
    # protected services refused (lockout-proof guarantee)
    for svc in ("WinRM", "TermService", "Whids", "Sysmon64", "BFE", "MpsSvc"):
        assert "error" in actuate.execute("stop_service", tmp_path, target=svc, reason="x")
    # protected accounts refused
    assert "error" in actuate.execute("disable_user", tmp_path, target="Administrator", reason="x")


def test_actuate_isolate_keeps_management_open(tmp_path, mock_run):
    root = _fresh_root(tmp_path)
    dry = actuate.execute("isolate_host", root, reason="ransomware")
    assert dry["mode"] == "dry-run"
    entry = actuate.execute("isolate_host", root, reason="ransomware",
                            apply=True, plan=dry["id"])
    assert entry["plan"] == dry["id"]
    payload = mock_run[0]
    # allow rules are created BEFORE any block rule, in the same payload
    assert payload.index("Allow RDP") < payload.index("Block Inbound")
    assert payload.index("Allow WinRM") < payload.index("Block Inbound")
    assert "5985" in payload and "3389" in payload
    assert entry["mode"] == "applied"
    assert entry["undo"]["payload"].startswith("Remove-NetFirewallRule")


def test_actuate_apply_requires_plan_from_seen_dry_run(tmp_path, mock_run):
    """--apply without a matching seen dry-run plan must never mutate."""
    root = _fresh_root(tmp_path)
    # no plan at all
    res = actuate.execute("block_ip", root, target="1.2.3.4",
                          reason="C2", apply=True)
    assert "error" in res and "--plan" in res["error"]
    # dry-run, then apply with a DIFFERENT target -> refused
    dry = actuate.execute("block_ip", root, target="1.2.3.4", reason="C2")
    res = actuate.execute("block_ip", root, target="5.6.7.8",
                          reason="C2", apply=True, plan=dry["id"])
    assert "error" in res and "target" in res["error"]
    # plan id that does not exist
    res = actuate.execute("block_ip", root, target="1.2.3.4",
                          reason="C2", apply=True, plan=999)
    assert "error" in res
    # nothing ever ran: journal holds only the one dry-run
    assert [r["mode"] for r in actuate.journal_read(root)] == ["dry-run"]
    assert mock_run == []


def test_actuate_apply_refuses_payload_drift(tmp_path, mock_run):
    """A plan whose rendered payload changed must not be appliable."""
    root = _fresh_root(tmp_path)
    dry = actuate.execute("block_ip", root, target="1.2.3.4", reason="C2")
    # tamper with the journaled digest: state moved on since the dry-run
    journal = root / "actuate-journal.jsonl"
    lines = journal.read_text().splitlines()
    row = json.loads(lines[0])
    row["payload_sha256"] = "0" * 64
    lines[0] = json.dumps(row)
    journal.write_text("\n".join(lines) + "\n")
    res = actuate.execute("block_ip", root, target="1.2.3.4",
                          reason="C2", apply=True, plan=dry["id"])
    assert "error" in res and "payload" in res["error"]


def test_actuate_apply_journals_result_and_verification(tmp_path, mock_run):
    root = _fresh_root(tmp_path)
    dry = actuate.execute("block_ip", root, target="1.2.3.4", reason="C2")
    entry = actuate.execute("block_ip", root, target="1.2.3.4",
                            reason="C2", apply=True, plan=dry["id"])
    assert entry["result"]["rc"] == 0
    assert entry["verification"] is not None
    assert entry["undo"]["payload"].startswith("Remove-NetFirewallRule")
    journaled = actuate.journal_read(root)
    assert [r["mode"] for r in journaled] == ["dry-run", "applied"]
    # a later plain dry-run of the same action stays dry
    dry2 = actuate.execute("block_ip", root, target="1.2.3.4", reason="again")
    assert dry2["mode"] == "dry-run"


def test_actuate_undo_flow(tmp_path, mock_run):
    root = _fresh_root(tmp_path)
    dry = actuate.execute("block_ip", root, target="1.2.3.4", reason="C2")
    applied = actuate.execute("block_ip", root, target="1.2.3.4",
                              reason="C2", apply=True, plan=dry["id"])
    undo_dry = actuate.undo(root, applied["id"])
    # apply already ran payload + verification (2 calls); dry undo adds none
    assert undo_dry["mode"] == "dry-run" and len(mock_run) == 2
    done = actuate.undo(root, applied["id"], apply=True)
    assert done["action"] == "undo" and done["result"]["rc"] == 0
    # journal records all four
    modes = [r["mode"] for r in actuate.journal_read(root)]
    assert modes == ["dry-run", "applied", "dry-run", "applied"]


def test_actuate_undo_refuses_dry_run_entries(tmp_path, mock_run):
    root = _fresh_root(tmp_path)
    dry = actuate.execute("block_ip", root, target="1.2.3.4", reason="x")
    assert "error" in actuate.undo(root, dry["id"], apply=True)


def test_actuate_kill_process_guard(monkeypatch, tmp_path):
    """Protected process names are refused before any kill payload runs."""
    monkeypatch.setattr(actuate, "_run", lambda p, timeout=60: (
        {"rc": 0, "output": "lsass.exe", "output_head": "lsass.exe"}))
    result = actuate.execute("kill_process", tmp_path, target="516", reason="x", apply=True)
    assert "error" in result and "protected" in result["error"]


def test_actuate_wmi_undo_restores_bindings(tmp_path, monkeypatch):
    """Bindings are captured to a sidecar file (survives journal truncation)
    and undo re-creates each filter/consumer pair."""
    root = _fresh_root(tmp_path)
    binds_file = tmp_path / "bindings.json"
    binds_file.write_text('[{"filter":"\\\\G1","consumer":"\\\\C1"}]')
    calls = []

    def fake_run(payload, timeout=60):
        calls.append(payload)
        if "Get-CimInstance -Namespace root/subscription" in payload:
            return {"rc": 0, "output": f"{binds_file}\nbindings removed",
                    "output_head": f"{binds_file}\nbindings removed"}
        if payload.startswith("New-CimInstance"):
            return {"rc": 0, "output": "bindings restored",
                    "output_head": "bindings restored"}
        return {"rc": 0, "output": "ok", "output_head": "ok"}

    monkeypatch.setattr(actuate, "_run", fake_run)
    dry = actuate.execute("disable_wmi_sub", root, reason="WMI persistence")
    entry = actuate.execute("disable_wmi_sub", root, reason="WMI persistence",
                            apply=True, plan=dry["id"])
    assert entry["undo"]["bindings_file"] == str(binds_file)
    undo_dry = actuate.undo(root, entry["id"])
    undone = actuate.undo(root, entry["id"], apply=True, plan=undo_dry["id"])
    assert undone["result"]["rc"] == 0
    assert calls[-1].startswith("New-CimInstance")


def test_actuate_journal_tolerates_torn_lines(tmp_path, mock_run):
    """A crash mid-append must not brick actuate forever."""
    root = _fresh_root(tmp_path)
    journal = root / "actuate-journal.jsonl"
    journal.parent.mkdir(parents=True, exist_ok=True)
    journal.write_text('{"id": 1, "broken json...\n')
    rows = actuate.journal_read(root)
    assert rows == []
    # the next execute still works and ids continue from the parsed rows
    dry = actuate.execute("block_ip", root, target="1.2.3.4", reason="x")
    assert dry["id"] >= 1
