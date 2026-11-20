"""Typed query language and PID lineage."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from plasma import query


def _ts(minutes_ago=0):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()


def _rows():
    return [
        {"ts": _ts(30), "host": "WS1", "kind": "process", "event_id": 1,
         "source": "sysmon", "process": "explorer.exe", "pid": 100, "ppid": 4,
         "user": "CORP\\olu", "score": 0.1, "description": "shell"},
        {"ts": _ts(20), "host": "WS1", "kind": "process", "event_id": 1,
         "source": "sysmon", "process": "powershell.exe", "pid": 200,
         "ppid": 100, "user": "CORP\\olu", "score": 0.2,
         "cmdline": "powershell -enc SQBFAFgA"},
        {"ts": _ts(10), "host": "WS2", "kind": "alert", "event_id": 9001,
         "source": "canary", "process": "cmd.exe", "pid": 300, "ppid": 200,
         "user": "CORP\\admin", "score": 0.8,
         "technique": "T1055", "description": "shellcode in memory"},
        {"ts": _ts(5), "host": "WS2", "kind": "auth", "event_id": 4625,
         "source": "plasma", "user": "CORP\\admin", "score": 0.5,
         "description": "logon FAILED"},
    ]


def _write(tmp_path, rows=None):
    path = tmp_path / "events.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in (rows or _rows())))
    return path


def test_filters_by_process_case_insensitively(tmp_path):
    result = query.query(_write(tmp_path), {"process": "POWERSHELL.EXE"})
    assert result["matched"] == 1
    assert result["events"][0]["pid"] == 200


def test_process_glob(tmp_path):
    result = query.query(_write(tmp_path), {"process": "power*.exe"})
    assert result["matched"] == 1


def test_user_and_host_are_exact(tmp_path):
    assert query.query(_write(tmp_path), {"user": "corp\\olu"})["matched"] == 2
    assert query.query(_write(tmp_path), {"host": "WS2"})["matched"] == 2


def test_since_and_score_filters(tmp_path):
    result = query.query(_write(tmp_path), {"since": "15m", "min_score": 0.5})
    assert result["matched"] == 2
    assert all(float(r["score"]) >= 0.5 for r in result["events"])


def test_count_by_and_order(tmp_path):
    result = query.query(_write(tmp_path),
                         {"count_by": "host", "order": "asc"})
    counts = {row["value"]: row["count"] for row in result["counts"]}
    assert counts == {"WS1": 2, "WS2": 2}
    stamps = [row["ts"] for row in result["events"]]
    assert stamps == sorted(stamps)


def test_limit_is_bounded_and_reported(tmp_path):
    result = query.query(_write(tmp_path), {"limit": 2})
    assert result["returned"] == 2
    assert result["truncated"] is True
    assert result["matched"] == 4


def test_unknown_field_is_refused(tmp_path):
    with pytest.raises(query.QueryError):
        query.query(_write(tmp_path), {"proces": "cmd.exe"})


def test_invalid_duration_is_refused(tmp_path):
    with pytest.raises(query.QueryError):
        query.query(_write(tmp_path), {"since": "yesterday"})


def test_invalid_regex_is_refused(tmp_path):
    with pytest.raises(query.QueryError):
        query.query(_write(tmp_path), {"regex": "("})


def test_missing_store_is_empty_not_an_error(tmp_path):
    result = query.query(tmp_path / "nope.jsonl", {"kind": "alert"})
    assert result["ok"] is True
    assert result["checked"] == 0


def test_tree_uses_explicit_ppid_edges(tmp_path):
    result = query.tree(_write(tmp_path), pid=100, depth=3)
    pids = [node["pid"] for node in result["nodes"]]
    assert pids == [100, 200, 300]
    assert {"from": 100, "to": 200} in result["edges"]


def test_tree_by_process_selects_newest_match(tmp_path):
    rows = _rows()
    result = query.tree(_write(tmp_path, rows), process_name="powershell.exe")
    assert result["nodes"][0]["pid"] == 200
    assert [n["pid"] for n in result["nodes"]] == [200, 300]


def test_tree_depth_limits_nodes(tmp_path):
    result = query.tree(_write(tmp_path), pid=100, depth=1)
    assert [n["pid"] for n in result["nodes"]] == [100, 200]


def test_tree_missing_pid_is_empty(tmp_path):
    result = query.tree(_write(tmp_path), pid=999)
    assert result["nodes"] == []


def test_tree_rejects_bad_pid(tmp_path):
    with pytest.raises(query.QueryError):
        query.tree(_write(tmp_path), pid="not-a-pid")
