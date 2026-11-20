"""Case workspace: collection, report, sealing and tamper detection."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from plasma import case


def _seed(root):
    events = root / "data" / "events.jsonl"
    events.parent.mkdir(parents=True)
    row = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "host": "WS1", "kind": "alert", "source": "plasma",
        "event_id": 9001, "severity": "high", "score": 0.9,
        "user": "CORP\\olu", "process": "powershell.exe", "pid": 200,
        "technique": "T1055", "description": "shellcode in memory",
    }
    events.write_text(json.dumps(row) + "\n")
    return events


def test_open_reopen_and_list(tmp_path):
    first = case.open_case(tmp_path, "IR-2026-042", host="WS1",
                           title="Injection", note="first look")
    assert first["created"] is True
    second = case.open_case(tmp_path, "IR-2026-042", note="second look")
    assert second["created"] is False
    assert second["case"]["counts"]["notes"] == 2
    assert case.list_cases(tmp_path)["count"] == 1


def test_invalid_name_is_refused(tmp_path):
    with pytest.raises(case.CaseError):
        case.open_case(tmp_path, "../escape")


def test_add_query_copies_only_matches_and_dedupes(tmp_path):
    events = _seed(tmp_path)
    case.open_case(tmp_path, "c1")
    result = case.add_query(tmp_path, "c1", {"process": "powershell.exe"},
                            events_path=events)
    assert result["matched"] == 1
    assert result["added"] == 1
    again = case.add_query(tmp_path, "c1", {"process": "powershell.exe"},
                           events_path=events)
    assert again["added"] == 0
    assert again["counts"]["events"] == 1


def test_timeline_merges_events_and_notes(tmp_path):
    events = _seed(tmp_path)
    case.open_case(tmp_path, "c1")
    case.add_query(tmp_path, "c1", {"kind": "alert"}, events_path=events)
    case.add_note(tmp_path, "c1", "confirmed with the user")
    result = case.timeline(tmp_path, "c1")
    kinds = [row["kind"] for row in result["timeline"]]
    assert "alert" in kinds and "note" in kinds


def test_report_contains_high_score_and_note(tmp_path):
    events = _seed(tmp_path)
    case.open_case(tmp_path, "c1", host="WS1")
    case.add_query(tmp_path, "c1", {"min_score": 0.5}, events_path=events)
    case.add_note(tmp_path, "c1", "approved isolation")
    result = case.report(tmp_path, "c1")
    markdown = result["markdown"]
    assert "# Case c1" in markdown
    assert "powershell.exe" in markdown
    assert "approved isolation" in markdown
    assert (tmp_path / "cases" / "c1" / "report.md").exists()


def test_seal_and_verify_detects_tamper(tmp_path):
    events = _seed(tmp_path)
    case.open_case(tmp_path, "c1")
    case.add_query(tmp_path, "c1", {"kind": "alert"}, events_path=events)
    sealed = case.seal(tmp_path, "c1")
    assert sealed["files"]
    assert sealed["chain_sha256"]
    assert case.verify(tmp_path, "c1")["ok"] is True
    target = tmp_path / "cases" / "c1" / "events.jsonl"
    target.write_text(target.read_text() + "\n")
    checked = case.verify(tmp_path, "c1")
    assert checked["ok"] is False
    assert "events.jsonl" in checked["changed"]
    assert checked["code"] == "TAMPERED"


def test_verify_before_seal_is_structured(tmp_path):
    case.open_case(tmp_path, "c1")
    result = case.verify(tmp_path, "c1")
    assert result["ok"] is False
    assert result["code"] == "NOT_SEALED"


def test_missing_case_is_refused(tmp_path):
    with pytest.raises(case.CaseError):
        case.timeline(tmp_path, "nope")


def test_empty_note_is_refused(tmp_path):
    case.open_case(tmp_path, "c1")
    with pytest.raises(case.CaseError):
        case.add_note(tmp_path, "c1", "   ")


def test_read_only_report_does_not_write(tmp_path):
    events = _seed(tmp_path)
    case.open_case(tmp_path, "c1")
    case.add_query(tmp_path, "c1", {"kind": "alert"}, events_path=events)
    result = case.report(tmp_path, "c1", write=False)
    assert result["markdown"]
    assert not (tmp_path / "cases" / "c1" / "report.md").exists()
