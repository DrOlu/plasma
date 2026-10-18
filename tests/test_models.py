import json

import pytest
from pydantic import ValidationError

from models import PlasmaEvent


def base(**over):
    row = {
        "ts": "2026-10-16T09:14:03Z",
        "host": "WS1",
        "source": "sysmon",
        "kind": "process",
        "event_id": 1,
        "severity": "high",
        "user": "CORP\\olu",
        "process": "powershell.exe",
        "pid": 4832,
        "ppid": 3200,
        "parent": "explorer.exe",
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "cmdline": "powershell.exe -nop -w hidden -enc SQBFAFgA",
        "dest_ip": None,
        "dest_port": None,
        "dns_query": None,
        "file_path": None,
        "registry_path": None,
        "technique": "T1059.001",
        "alert_id": None,
        "score": None,
        "action": None,
        "description": "PowerShell spawned with encoded command",
    }
    row.update(over)
    return row


def test_valid_event_parses():
    ev = PlasmaEvent(**base())
    assert ev.host == "WS1"
    assert ev.kind == "process"
    assert ev.technique == "T1059.001"


def test_new_host_and_user_accepted():
    ev = PlasmaEvent(**base(host="BRANCH-SRV-042", user="EU\\new.analyst"))
    assert ev.host == "BRANCH-SRV-042"


def test_alert_fields():
    ev = PlasmaEvent(**base(
        kind="alert", source="sentinel", event_id=9001,
        severity="critical", alert_id="SEN-1001", score=0.97, action="killed",
    ))
    assert ev.score == 0.97
    assert ev.action == "killed"


@pytest.mark.parametrize("field,value", [
    ("kind", "kernel"),
    ("severity", "urgent"),
    ("source", "unknown"),
    ("technique", "1059"),
    ("host", "-bad-host"),
])
def test_invalid_fields_rejected(field, value):
    with pytest.raises(ValidationError):
        PlasmaEvent(**base(**{field: value}))


def test_bad_score_and_port_rejected():
    with pytest.raises(ValidationError):
        PlasmaEvent(**base(score=1.5))
    with pytest.raises(ValidationError):
        PlasmaEvent(**base(event_id=1, dest_port=70000))


def test_extra_field_forbidden():
    with pytest.raises(ValidationError):
        PlasmaEvent(**base(unknown_field="x"))
