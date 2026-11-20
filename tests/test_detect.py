"""Detection-engineering harness."""
from __future__ import annotations

import json

import pytest

from plasma import detect


def _rule(name="Test Rule", pattern=r"(?i:^c:\\windows\\cmd\.exe$)",
          condition="$img"):
    return {
        "Name": name,
        "Meta": {"EventIDs": [1], "Schema": "1.0.0"},
        "Matches": [f"$img: Image ~= '{pattern}'"],
        "Condition": condition,
    }


def _write(tmp_path, name, rules):
    path = tmp_path / name
    path.write_text("".join(json.dumps(rule) + "\n" for rule in rules))
    return path


def test_validate_good_rule(tmp_path):
    out = detect.validate(_write(tmp_path, "rules.gen", [_rule()]))
    assert out["ok"] is True
    assert out["rules"] == 1
    assert out["errors"] == []


def test_validate_reports_bad_regex_and_unknown_variable(tmp_path):
    path = _write(tmp_path, "rules.gen", [_rule(pattern="(", condition="$nope")])
    out = detect.validate(path)
    assert out["ok"] is False
    assert "bad regex" in out["errors"][0]["error"]
    assert any("unknown variable" in row["warning"] for row in out["warnings"])


def test_validate_reports_missing_matches(tmp_path):
    path = tmp_path / "rules.gen"
    path.write_text(json.dumps({"Name": "No matches"}) + "\n")
    out = detect.validate(path)
    assert out["ok"] is False
    assert out["errors"][0]["error"] == "missing Matches list"


def test_diff_reports_added_removed_changed(tmp_path):
    old = _write(tmp_path, "old.gen", [
        _rule("Keep"), _rule("Change", pattern="a"), _rule("Remove")])
    new = _write(tmp_path, "new.gen", [
        _rule("Keep"), _rule("Change", pattern="b"), _rule("Add")])
    out = detect.diff(old, new)
    assert [r["rule"] for r in out["added"]] == ["Add"]
    assert [r["rule"] for r in out["removed"]] == ["Remove"]
    assert [r["rule"] for r in out["changed"]] == ["Change"]
    assert out["summary"] == {"added": 1, "removed": 1, "changed": 1,
                              "unchanged": 1}


def test_replay_runs_chains_and_summary(tmp_path):
    events = tmp_path / "events.jsonl"
    rows = [
        {"ts": "2026-11-20T10:00:00Z", "host": "WS1", "kind": "process",
         "source": "sysmon", "event_id": 1, "process": "winword.exe",
         "parent": "explorer.exe", "score": 0.2},
        {"ts": "2026-11-20T10:01:00Z", "host": "WS1", "kind": "process",
         "source": "sysmon", "event_id": 1, "process": "powershell.exe",
         "parent": "winword.exe", "score": 0.2,
         "description": "powershell -enc SQBFAFgA"},
        {"ts": "2026-11-20T10:02:00Z", "host": "WS1", "kind": "network",
         "source": "sysmon", "event_id": 3, "process": "powershell.exe",
         "score": 0.2, "dest_ip": "203.0.113.9"},
    ]
    events.write_text("".join(json.dumps(r) + "\n" for r in rows))
    out = detect.replay(events)
    assert out["summary"]["checked"] == 3
    assert out["chains"]["top_score"] >= 9


def test_empty_rule_file_is_refused(tmp_path):
    path = tmp_path / "empty.gen"
    path.write_text("")
    with pytest.raises(detect.DetectError):
        detect.load_rules(path)


def test_json_array_is_supported(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps([_rule()]))
    assert detect.load_rules(path)[0]["Name"] == "Test Rule"
