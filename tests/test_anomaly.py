"""Anomaly scoring: explainable, bounded and honest about cold starts."""
from __future__ import annotations

import json

from plasma import anomaly, profile


def _benign(days=6, per_day=12):
    rows = []
    for day in range(1, days + 1):
        for minute in range(per_day):
            rows.append({
                "ts": f"2026-11-{day:02d}T09:{minute:02d}:00Z",
                "host": "WS1", "kind": "process", "event_id": 1,
                "process": "chrome.exe", "parent": "explorer.exe",
                "user": "CORP\\olu", "pid": 1000 + minute, "ppid": 500,
                "cmdline": "chrome.exe --type=renderer", "dest_port": 443,
                "registry_path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive",
            })
    return rows


def _build(tmp_path, rows, name="events.jsonl"):
    path = tmp_path / name
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    return profile.build(path), path


def _append(path, row):
    with path.open("a") as handle:
        handle.write(json.dumps(row) + "\n")


def test_score_row_is_none_on_a_cold_profile(tmp_path):
    built, _path = _build(tmp_path, _benign(days=1, per_day=2))
    result = anomaly.score_row(_benign(days=1, per_day=1)[0], built)
    assert result["score"] is None
    assert result["cold_start"] is True
    assert "required" in result["reason"]


def test_rank_puts_an_injected_anomaly_on_top(tmp_path):
    built, path = _build(tmp_path, _benign())
    _append(path, {
        "ts": "2026-11-07T03:00:00Z", "host": "WS1", "kind": "process",
        "event_id": 1, "process": "mimikatz.exe", "parent": "cmd.exe",
        "user": "CORP\\olu", "pid": 9001, "ppid": 9000,
        "cmdline": "mimikatz sekurlsa::logonpasswords",
        "registry_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil",
    })
    ranked = anomaly.rank(path, built, limit=5)
    assert ranked["ok"] is True
    assert ranked["events"][0]["process"] == "mimikatz.exe"
    assert ranked["events"][0]["score"] > 7.0
    names = {component["name"] for component in ranked["events"][0]["components"]}
    assert {"image", "edge", "shape", "registry"} <= names


def test_first_seen_keys_score_one_and_say_so(tmp_path):
    built, _path = _build(tmp_path, _benign())
    row = {
        "ts": "2026-11-07T03:00:00Z", "host": "WS1", "kind": "process",
        "event_id": 1, "process": "neverseen.exe", "parent": "explorer.exe",
        "user": "CORP\\olu",
    }
    result = anomaly.score_row(row, built)
    by_name = {component["name"]: component for component in result["components"]}
    assert by_name["image"]["value"] == 1.0
    assert by_name["image"]["first_seen"] is True
    assert any("never seen" in reason for reason in result["reasons"])


def test_volume_compares_the_day_not_the_whole_tail(tmp_path):
    built, path = _build(tmp_path, _benign())
    # A second, normal day must not look like a volume anomaly just because
    # the tail now holds twice as many events.
    for minute in range(12):
        _append(path, {
            "ts": f"2026-11-07T09:{minute:02d}:00Z", "host": "WS1",
            "kind": "process", "event_id": 1, "process": "chrome.exe",
            "parent": "explorer.exe", "user": "CORP\\olu",
            "cmdline": "chrome.exe --type=renderer",
        })
    ranked = anomaly.rank(path, built, limit=50)
    volumes = [component for event in ranked["events"]
               for component in event["components"]
               if component["name"] == "volume"]
    assert all(component["value"] == 0.0 for component in volumes)


def test_rank_caps_repeated_behaviour_but_reports_it(tmp_path):
    built, path = _build(tmp_path, _benign())
    for index in range(6):
        _append(path, {
            "ts": f"2026-11-07T04:0{index}:00Z", "host": "WS1",
            "kind": "process", "event_id": 1, "process": "rare.exe",
            "parent": "cmd.exe", "user": "CORP\\olu",
            "cmdline": "rare.exe --once",
        })
    ranked = anomaly.rank(path, built, limit=20, per_behaviour=2)
    rare = [event for event in ranked["events"] if event["process"] == "rare.exe"]
    assert len(rare) == 2


def test_suppressed_rows_are_skipped_by_default(tmp_path):
    built, path = _build(tmp_path, _benign())
    _append(path, {
        "ts": "2026-11-07T04:00:00Z", "host": "WS1", "kind": "alert",
        "event_id": 11, "process": "powershell.exe", "parent": "explorer.exe",
        "user": "CORP\\olu", "score": 0.2, "severity": "info",
        "suppressed": "PowerShell policy-test temp file",
        "description": "noise",
    })
    default = anomaly.rank(path, built, limit=20)
    assert all(event.get("process") != "powershell.exe" for event in default["events"])
    included = anomaly.rank(path, built, limit=20, include_suppressed=True)
    assert any(event.get("process") == "powershell.exe"
               for event in included["events"])


def test_explain_returns_a_readable_breakdown(tmp_path):
    built, path = _build(tmp_path, _benign())
    _append(path, {
        "ts": "2026-11-07T05:00:00Z", "host": "WS1", "kind": "process",
        "event_id": 1, "process": "rundll32.exe", "parent": "winword.exe",
        "user": "CORP\\olu", "cmdline": "rundll32 javascript:alert(1)",
    })
    result = anomaly.explain(path, built, contains="rundll32")
    assert result["ok"] is True
    assert result["event"]["process"] == "rundll32.exe"
    assert result["reading"]
    assert result["weights"]["edge"] == 1.5


def test_traces_join_parents_within_one_host(tmp_path):
    rows = [
        {"ts": "2026-11-07T09:00:00Z", "host": "WS1", "kind": "process",
         "event_id": 1, "process": "explorer.exe", "pid": 100, "ppid": 4,
         "user": "CORP\\olu"},
        {"ts": "2026-11-07T09:01:00Z", "host": "WS1", "kind": "process",
         "event_id": 1, "process": "cmd.exe", "pid": 200, "ppid": 100,
         "user": "CORP\\olu"},
        {"ts": "2026-11-07T09:02:00Z", "host": "WS1", "kind": "process",
         "event_id": 1, "process": "powershell.exe", "pid": 300, "ppid": 200,
         "user": "CORP\\olu"},
        # Same PID on another host must not be joined to WS1's tree.
        {"ts": "2026-11-07T09:02:30Z", "host": "WS2", "kind": "process",
         "event_id": 1, "process": "other.exe", "pid": 300, "ppid": 200,
         "user": "CORP\\olu"},
    ]
    traces = anomaly.build_traces(rows, min_spans=1)
    assert len(traces) == 2
    ws1 = next(trace for trace in traces if trace["host"] == "WS1")
    assert ws1["spans"] == 3
    assert ws1["depth"] == 2
    assert ws1["root_process"] == "explorer.exe"
    assert "cmd.exe>powershell.exe" in ws1["edges"]
    ws2 = next(trace for trace in traces if trace["host"] == "WS2")
    assert ws2["spans"] == 1


def test_pid_reuse_starts_a_new_tree(tmp_path):
    rows = [
        {"ts": "2026-11-07T09:00:00Z", "host": "WS1", "kind": "process",
         "event_id": 1, "process": "a.exe", "pid": 10, "ppid": 4},
        {"ts": "2026-11-07T09:01:00Z", "host": "WS1", "kind": "process",
         "event_id": 1, "process": "b.exe", "pid": 20, "ppid": 10},
        {"ts": "2026-11-07T10:00:00Z", "host": "WS1", "kind": "process",
         "event_id": 1, "process": "c.exe", "pid": 20, "ppid": 4},
        {"ts": "2026-11-07T10:01:00Z", "host": "WS1", "kind": "process",
         "event_id": 1, "process": "d.exe", "pid": 30, "ppid": 20},
    ]
    traces = anomaly.build_traces(rows, min_spans=1)
    assert len(traces) == 2
    assert sorted(trace["spans"] for trace in traces) == [2, 2]


def test_trace_score_marks_a_first_seen_edge(tmp_path):
    built, _path = _build(tmp_path, _benign())
    trace = {"edges": ["explorer.exe>chrome.exe", "winword.exe>rundll32.exe"]}
    result = anomaly.trace_score(trace, built)
    assert result["cold_start"] is False
    assert "winword.exe>rundll32.exe" in result["first_seen_edges"]
    assert result["score"] > 0


def test_traces_command_is_bounded_and_serialisable(tmp_path):
    built, path = _build(tmp_path, _benign())
    result = anomaly.traces(path, built, min_spans=1, limit=3)
    json.dumps(result)
    assert result["ok"] is True
    assert result["returned"] <= 3


def test_service_parents_are_damped_but_not_hidden(tmp_path):
    built, _path = _build(tmp_path, _benign())
    row = {
        "ts": "2026-11-07T06:00:00Z", "host": "WS1", "kind": "process",
        "event_id": 1, "process": "neverseen.exe", "parent": "svchost.exe",
        "user": "CORP\\SYSTEM", "cmdline": "neverseen.exe -run",
    }
    damped = anomaly.score_row(row, built)
    undamped = anomaly.score_row({**row, "parent": "explorer.exe"}, built)
    assert damped["damping"]["factor"] == anomaly.SERVICE_PARENT_DAMPING
    assert damped["score"] < undamped["score"]
    assert damped["score"] > 0


def test_bands_reserve_critical_for_multi_signal_novelty():
    rows = [{"score": 9.4}, {"score": 9.6}, {"score": 8.0}, {"score": 6.0}]
    assert anomaly._bands(rows) == {
        "critical": 2, "high": 1, "medium": 1, "low": 0}


def test_plasma_self_noise_is_skipped_unless_requested(tmp_path):
    built, path = _build(tmp_path, _benign())
    _append(path, {
        "ts": "2026-11-07T07:00:00Z", "host": "WS1", "kind": "process",
        "event_id": 1, "process": "plasma-1.27.1-windows-x64.exe", "parent": "powershell.exe",
        "user": "CORP\\olu", "cmdline": "plasma-1.27.1.exe install --force",
    })
    default = anomaly.rank(path, built, limit=20)
    assert all(event["process"] != "plasma-1.27.1-windows-x64.exe"
               for event in default["events"])
    included = anomaly.rank(path, built, limit=20, include_self=True)
    assert any(event["process"] == "plasma-1.27.1-windows-x64.exe"
               for event in included["events"])


def test_trace_listing_skips_plasma_rooted_trees(tmp_path):
    rows = [
        {"ts": "2026-11-07T08:00:00Z", "host": "WS1", "kind": "process",
         "event_id": 1, "process": "plasma-1.27.1-windows-x64.exe", "pid": 10, "ppid": 4},
        {"ts": "2026-11-07T08:00:01Z", "host": "WS1", "kind": "process",
         "event_id": 1, "process": "whoami.exe", "pid": 11, "ppid": 10},
    ]
    assert anomaly.build_traces(rows, min_spans=2)
    result = anomaly.traces(_write_rows(tmp_path, rows), None, min_spans=2)
    assert result["count"] == 0
    included = anomaly.traces(_write_rows(tmp_path, rows, "b.jsonl"), None,
                              min_spans=2, include_self=True)
    assert included["count"] == 1


def _write_rows(tmp_path, rows, name="t.jsonl"):
    path = tmp_path / name
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    return path


def test_self_detection_does_not_swallow_lookalike_names():
    assert anomaly._is_self("plasma-1.27.2-windows-x64.exe") is True
    assert anomaly._is_self("plasma.exe") is True
    assert anomaly._is_self("plasma-rare-deadbeef.exe") is False
    assert anomaly._is_self("plasmaloader.exe") is False


def test_children_of_plasma_are_damped(tmp_path):
    built, _path = _build(tmp_path, _benign())
    row = {
        "ts": "2026-11-07T09:30:00Z", "host": "WS1", "kind": "process",
        "event_id": 1, "process": "icacls.exe",
        "parent": "plasma-1.27.2-windows-x64.exe", "user": "CORP\\olu",
        "cmdline": "icacls C:\\ProgramData\\Plasma /grant *S-1-5-18:F",
    }
    result = anomaly.score_row(row, built)
    assert result["damping"]["reason"] == "Plasma's own process tree"
