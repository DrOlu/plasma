"""Identity-plane tests: normalization onto the PlasmaEvent contract,
dedupe, machine-account filtering, CLI wiring."""

import json

import pytest
from models import PlasmaEvent

from plasma import identity


def row(user="Administrator", domain="CORP", eid=4625, **kw):
    r = {"ts": "2026-10-19T13:00:00.000Z", "event_id": eid, "user": user,
         "domain": domain, "logonType": "3", "workstation": "WS2",
         "source_ip": "172.31.20.0", "process": r"C:\Windows\System32\svchost.exe",
         "pid": "4"}
    r.update(kw)
    return r


def test_normalize_failed_logon_contract():
    ev = identity.normalize_logon(row(), host="WS1")
    assert ev["kind"] == "auth"
    assert ev["user"] == "CORP\\Administrator"
    assert ev["severity"] == "medium" and ev["score"] == 0.5
    assert ev["dest_ip"] == "172.31.20.0"
    assert "FAILED" in ev["description"]
    PlasmaEvent(**ev)


def test_normalize_success_logon():
    ev = identity.normalize_logon(row(eid=4624), host="WS1")
    assert ev["severity"] == "info" and ev["score"] == 0.2
    PlasmaEvent(**ev)


def test_machine_accounts_and_local_noise_filtered():
    assert "user" not in identity.normalize_logon(row(user="WS1$"), host="WS1")
    assert "user" not in identity.normalize_logon(row(user="-"), host="WS1")
    assert "dest_ip" not in identity.normalize_logon(row(source_ip="127.0.0.1"), host="WS1")


def test_pull_appends_with_dedupe(tmp_path, monkeypatch):
    events = tmp_path / "events.jsonl"
    monkeypatch.setattr(identity, "_run_ps",
                        lambda m, **kw: {"events": [row(), row(), row(user="olu", domain="CORP")]})
    first = identity.pull(events, host="WS1", since_minutes=15)
    assert first["events_seen"] == 3 and first["written"] == 2
    assert first["written_by_id"] == {"4625": 2}
    second = identity.pull(events, host="WS1", since_minutes=15)
    assert second["written"] == 0

    stored = [json.loads(l) for l in events.read_text().splitlines() if l.strip()]
    assert len(stored) == 2
    assert all(PlasmaEvent(**r) for r in stored)


def test_pull_collector_failure_is_data(tmp_path, monkeypatch):
    monkeypatch.setattr(identity, "_run_ps", lambda m, **kw: {"error": "timeout"})
    out = identity.pull(tmp_path / "e.jsonl", host="WS1")
    assert "error" in out and out["written"] == 0


# --- Kerberos, NTLM and process lineage -----------------------------------

def kerberos_row(eid=4768, status="0x0", **kw):
    r = row(eid=eid, user="olu@CORP.LOCAL", domain=None,
            source_ip="172.31.20.10", status=status, workstation="WS2")
    r.update(kw)
    return r


def test_kerberos_tgt_request_is_an_auth_event():
    ev = identity.normalize_logon(kerberos_row(), host="WS1")
    assert ev["kind"] == "auth" and ev["event_id"] == 4768
    assert ev["severity"] == "info" and ev["score"] == 0.2
    assert ev["user"] == "olu@CORP.LOCAL"
    assert "Kerberos TGT success" in ev["description"]
    PlasmaEvent(**ev)


def test_kerberos_preauth_failure_is_medium():
    ev = identity.normalize_logon(
        kerberos_row(eid=4771, status="0x18"), host="WS1")
    assert ev["severity"] == "medium" and ev["score"] == 0.5
    assert "FAILED" in ev["description"]


def test_service_ticket_keeps_the_service_name():
    ev = identity.normalize_logon(
        kerberos_row(eid=4769, service="cifs/ws2.corp.local"), host="WS1")
    assert "service=cifs/ws2.corp.local" in ev["description"]


def test_ntlm_failure_uses_the_workstation_as_source():
    ev = identity.normalize_logon(
        row(eid=4776, domain="CORP", user="Administrator",
            status="0xC000006A", source_ip=None, workstation="WS2",
            package="NTLM"), host="WS1")
    assert ev["severity"] == "medium" and ev["dest_ip"] == "WS2"
    assert "NTLM credential validation FAILED" in ev["description"]


def test_4688_carries_creator_parent_and_command_line():
    ev = identity.normalize_process(
        row(eid=4688, user="olu", domain="CORP",
            process=r"C:\Windows\System32\cmd.exe",
            parent=r"C:\Windows\explorer.exe", pid="2200",
            cmdline="cmd.exe /c whoami"), host="WS1")
    assert ev["kind"] == "process" and ev["event_id"] == 4688
    assert ev["user"] == "CORP\\olu"
    assert ev["process"] == "cmd.exe" and ev["parent"] == "explorer.exe"
    assert ev["image"].endswith("cmd.exe") and ev["cmdline"] == "cmd.exe /c whoami"
    assert ev["action"] == "logged"
    PlasmaEvent(**ev)


def test_4688_command_line_is_redacted():
    ev = identity.normalize_process(
        row(eid=4688, cmdline="cmd.exe /c run --password hunter2"), host="WS1")
    assert "hunter2" not in ev.get("cmdline", "")


def test_pull_dispatches_by_event_family(tmp_path, monkeypatch):
    captured = {}

    def fake(since, ids=None, max_events=None):
        captured["ids"] = ids
        return {"events": [
            row(eid=4625),
            kerberos_row(eid=4768),
            row(eid=4688, user="olu", domain="CORP",
                process=r"C:\Windows\System32\cmd.exe",
                parent=r"C:\Windows\explorer.exe", cmdline="cmd.exe /c hostname"),
        ]}

    monkeypatch.setattr(identity, "_run_ps", fake)
    events = tmp_path / "e.jsonl"
    out = identity.pull(events, host="WS1")
    assert out["written"] == 3
    assert out["written_by_id"] == {"4625": 1, "4688": 1, "4768": 1}
    kinds = [json.loads(l)["kind"] for l in events.read_text().splitlines()]
    assert kinds.count("auth") == 2 and kinds.count("process") == 1
    assert identity.PROCESS_ID in captured["ids"]


@pytest.mark.parametrize("bad", ["4624,9999", "4624;x", "abc"])
def test_pull_refuses_unsupported_event_ids(tmp_path, bad):
    out = identity.pull(tmp_path / "e.jsonl", host="WS1", ids=bad)
    assert "error" in out and out["written"] == 0


def test_ids_allowlist_has_no_duplicates():
    assert identity.parse_ids("4624,4625,4624") == (4624, 4625)
    assert 4688 in identity.DEFAULT_IDS and 4768 in identity.DEFAULT_IDS


def test_max_events_is_bounded(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(identity, "_run_ps",
                        lambda since, ids=None, max_events=None:
                        (seen.update(events=max_events) or {"events": []}))
    identity.pull(tmp_path / "e.jsonl", host="WS1", max_events=10**9)
    assert seen["events"] == 50000


def test_cli_identity_wiring():
    from plasma import cli
    cli.build_parser().parse_args(["identity", "pull", "--events", "e.jsonl", "--since", "30"])


def test_schedule_registers_a_system_task(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(identity, "_ps_task",
                        lambda script, timeout=120: (seen.append(script) or (0, "ok")))
    res = identity.schedule(tmp_path, every_minutes=10,
                            exe=r"C:\Program Files\Plasma\plasma.exe")
    assert res["ok"] is True
    assert res["every_minutes"] == 10
    script = seen[0]
    assert identity.TASK_NAME in script
    assert "identity pull" in script and "--since 10" in script
    assert "SYSTEM" in script and "Highest" in script


def test_schedule_clamps_interval(tmp_path, monkeypatch):
    monkeypatch.setattr(identity, "_ps_task", lambda script, timeout=120: (0, "ok"))
    assert identity.schedule(tmp_path, every_minutes=0,
                            exe=r"C:\plasma.exe")["every_minutes"] == 1
    assert identity.schedule(tmp_path, every_minutes=99999,
                            exe=r"C:\plasma.exe")["every_minutes"] == 1440


def test_unschedule_reports_task_name(monkeypatch):
    seen = []
    monkeypatch.setattr(identity, "_ps_task",
                        lambda script, timeout=120: (seen.append(script) or (0, "")))
    res = identity.unschedule()
    assert res["ok"] and identity.TASK_NAME in seen[0]


def test_schedule_status_parses_json(monkeypatch):
    payload = '{"installed":true,"state":"Ready","last_result":0}'
    monkeypatch.setattr(identity, "_ps_task",
                        lambda script, timeout=60: (0, payload))
    res = identity.schedule_status()
    assert res["installed"] is True and res["state"] == "Ready"


def test_kerberos_machine_account_with_realm_is_still_filtered():
    ev = identity.normalize_logon(
        kerberos_row(eid=4769, user="EC2AMAZ-8NK9FUP$",
                     domain="CORP.LOCAL", service="cifs/ws2"), host="WS1")
    assert "user" not in ev


def test_realm_qualified_upn_is_not_double_prefixed():
    ev = identity.normalize_logon(
        kerberos_row(eid=4768, user="olu@CORP.LOCAL", domain="CORP.LOCAL"),
        host="WS1")
    assert ev["user"] == "olu@CORP.LOCAL"


# --- Account, group and privilege coverage (v1.23.0) ----------------------

def account_row(eid=4720, **kw):
    r = row(eid=eid, user="svc-temp", domain="CORP",
            target_user="svc-temp", target_domain="CORP",
            actor="Administrator")
    r.update(kw)
    return r


def test_account_creation_is_high_signal():
    ev = identity.normalize_logon(account_row(), host="WS1")
    assert ev["event_id"] == 4720
    assert ev["user"] == "CORP\\svc-temp"
    assert ev["severity"] == "high" and ev["score"] == 0.8
    assert "account created" in ev["description"]
    PlasmaEvent(**ev)


def test_group_membership_change_is_described():
    ev = identity.normalize_logon(
        account_row(eid=4728, user="Domain Admins",
                    target_user="Domain Admins",
                    member="CORP\\svc-temp"), host="WS1")
    assert ev["event_id"] == 4728
    assert "global group membership added" in ev["description"]
    assert "svc-temp" in ev["description"]
    PlasmaEvent(**ev)


def test_explicit_credentials_uses_actor_as_user():
    ev = identity.normalize_logon(
        row(eid=4648, user="olu", domain="CORP",
            target_user="Administrator", target_domain="CORP"), host="WS1")
    assert ev["event_id"] == 4648
    assert ev["user"] == "CORP\\olu"
    assert "explicit credentials" in ev["description"]
    assert ev["severity"] == "medium"
    PlasmaEvent(**ev)


def test_privilege_and_directory_events_are_supported():
    ev = identity.normalize_logon(
        row(eid=4672, user="olu", domain="CORP",
            privileges="SeDebugPrivilege, SeBackupPrivilege"), host="WS1")
    assert "special privileges" in ev["description"]
    assert "SeDebugPrivilege" in ev["description"]
    PlasmaEvent(**ev)
    ev2 = identity.normalize_logon(
        row(eid=4662, user="olu", domain="CORP",
            object_name="DC=corp,DC=local"), host="WS1")
    assert "directory service access" in ev2["description"]
    PlasmaEvent(**ev2)


def test_process_lineage_keeps_parent_pid():
    ev = identity.normalize_process(
        {"event_id": 4688, "ts": "2026-10-19T13:00:00.000Z",
         "user": "olu", "domain": "CORP", "process": "C:\\Windows\\cmd.exe",
         "parent": "C:\\Windows\\explorer.exe", "pid": "200", "ppid": "100",
         "cmdline": "cmd.exe /c whoami"}, host="WS1")
    assert ev["pid"] == 200 and ev["ppid"] == 100
    assert ev["parent"] == "explorer.exe"
    PlasmaEvent(**ev)


def test_supported_ids_include_directory_events_but_default_excludes_noise():
    assert identity.parse_ids("4662,4672") == (4662, 4672)
    assert 4662 not in identity.DEFAULT_IDS
    assert 4672 not in identity.DEFAULT_IDS
    assert 4720 in identity.DEFAULT_IDS
    with pytest.raises(ValueError):
        identity.parse_ids("9999")
