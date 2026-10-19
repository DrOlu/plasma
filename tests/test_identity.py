"""Identity-plane tests: normalization onto the PlasmaEvent contract,
dedupe, machine-account filtering, CLI wiring."""

import json
from pathlib import Path

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
                        lambda m: {"events": [row(), row(), row(user="olu", domain="CORP")]})
    first = identity.pull(events, host="WS1", since_minutes=15)
    assert first["logons_seen"] == 3 and first["written"] == 2
    second = identity.pull(events, host="WS1", since_minutes=15)
    assert second["written"] == 0

    stored = [json.loads(l) for l in events.read_text().splitlines() if l.strip()]
    assert len(stored) == 2
    assert all(PlasmaEvent(**r) for r in stored)


def test_pull_collector_failure_is_data(tmp_path, monkeypatch):
    monkeypatch.setattr(identity, "_run_ps", lambda m: {"error": "timeout"})
    out = identity.pull(tmp_path / "e.jsonl", host="WS1")
    assert "error" in out and out["written"] == 0


def test_cli_identity_wiring():
    from plasma import cli
    cli.build_parser().parse_args(["identity", "pull", "--events", "e.jsonl", "--since", "30"])
