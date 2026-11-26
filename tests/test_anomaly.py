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


def _paths(tmp_path):
    return [tmp_path / "a.jsonl", tmp_path / "b.jsonl"]


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
    assert ranked["events"][0]["score"] >= 9.0
    names = {component["name"] for component in ranked["events"][0]["components"]}
    assert {"image", "edge", "shape", "registry"} <= names


def test_first_seen_identity_is_capped_and_says_so(tmp_path):
    built, _path = _build(tmp_path, _benign())
    row = {
        "ts": "2026-11-07T03:00:00Z", "host": "WS1", "kind": "process",
        "event_id": 1, "process": "neverseen.exe", "parent": "explorer.exe",
        "user": "CORP\\olu",
    }
    result = anomaly.score_row(row, built)
    by_name = {component["name"]: component for component in result["components"]}
    assert by_name["image"]["first_seen"] is True
    assert by_name["image"]["value"] == anomaly.IDENTITY_FIRST_SEEN_CAP
    assert by_name["image"]["value"] < 1.0
    assert any("never seen" in reason for reason in result["reasons"])


def test_benign_first_run_cannot_reach_the_critical_band(tmp_path):
    built, _path = _build(tmp_path, _benign())
    row = {
        "ts": "2026-11-07T03:00:00Z", "host": "WS1", "kind": "process",
        "event_id": 1, "process": "zoom-installer.exe",
        "parent": "explorer.exe", "user": "CORP\\olu",
        "cmdline": "zoom-installer.exe /silent",
    }
    result = anomaly.score_row(row, built)
    assert result["score"] < 9.0
    # Pure identity novelty with no content signal and no volume fact is
    # capped at high band even when every present component is first-seen.
    all_novel = anomaly.score_row(
        {**row, "process": "totallynew.exe", "cmdline": ""}, built)
    assert all_novel["score"] <= 8.9


def test_content_signals_still_reach_critical(tmp_path):
    built, path = _build(tmp_path, _benign())
    evil = {
        "ts": "2026-11-07T03:00:00Z", "host": "WS1", "kind": "process",
        "event_id": 1, "process": "mimikatz.exe", "parent": "cmd.exe",
        "user": "CORP\\olu",
        "cmdline": "mimikatz sekurlsa::logonpasswords",
        "registry_path": "HKCU\\Software\\Microsoft\\Windows\\"
                         "CurrentVersion\\Run\\Evil",
    }
    _append(path, evil)
    result = anomaly.score_row(evil, built)
    assert result["score"] >= 9.0


def test_service_parents_damp_familiar_children_but_not_first_seen(tmp_path):
    built, _path = _build(tmp_path, _benign())
    # chrome.exe is in the baseline: the classic maintenance FP class.
    familiar = {
        "ts": "2026-11-07T06:00:00Z", "host": "WS1", "kind": "process",
        "event_id": 1, "process": "chrome.exe", "parent": "svchost.exe",
        "user": "CORP\\SYSTEM", "cmdline": "chrome.exe --type=renderer",
    }
    damped = anomaly.score_row(familiar, built)
    assert damped["damping"]["factor"] == anomaly.SERVICE_PARENT_DAMPING
    # neverseen.exe under svchost.exe is where service-installed payloads
    # run: no damping, novelty keeps its full weight.
    novel = {
        "ts": "2026-11-07T06:00:00Z", "host": "WS1", "kind": "process",
        "event_id": 1, "process": "neverseen.exe", "parent": "svchost.exe",
        "user": "CORP\\SYSTEM", "cmdline": "neverseen.exe -run",
    }
    undamped = anomaly.score_row(novel, built)
    assert undamped["damping"] is None
    assert undamped["score"] > damped["score"]


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


def test_defender_and_ngen_parents_are_benign():
    assert {"mpcmdrun.exe", "msmpeng.exe", "ngentask.exe"} <= (
        anomaly.BENIGN_SERVICE_PARENTS)


def test_self_detection_does_not_swallow_lookalike_names():
    assert anomaly._is_self("plasma-1.27.2-windows-x64.exe") is True
    assert anomaly._is_self("plasma-1.27.3.exe") is True
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


def test_estate_scoring_ignores_incomplete_identity_pairs(tmp_path):
    built, _path = _build(tmp_path, _benign())
    estate = profile.merge([built])
    row = {
        "ts": "2026-11-07T10:00:00Z", "host": "WS1", "kind": "auth",
        "event_id": 4624, "user": "CORP\\olu",
    }
    result = anomaly.score_row(row, built, estate=estate)
    assert result["score"] is None
    assert result["cold_start"] is True


def test_volume_ignores_a_drop_in_activity(tmp_path):
    built, path = _build(tmp_path, _benign())
    row = {
        "ts": "2026-11-07T21:00:00Z", "host": "WS1", "kind": "process",
        "event_id": 1, "process": "chrome.exe", "parent": "explorer.exe",
        "user": "CORP\\olu", "cmdline": "chrome.exe --type=renderer",
    }
    _append(path, row)
    batch = anomaly._batch_counts([row])
    result = anomaly.score_row(row, built, batch=batch)
    names = {component["name"] for component in result["components"]}
    assert "volume" not in names


def test_volume_zero_median_hour_never_scores(tmp_path):
    built, _path = _build(tmp_path, _benign())
    # Hour 21 has no baseline for chrome.exe: no median, no volume verdict.
    assert profile.volume(built, "image:chrome.exe", 21, 9) is None


def test_constant_baseline_needs_a_real_step(tmp_path):
    built, _path = _build(tmp_path, _benign())
    stats = built["hourly"]["image:chrome.exe"]["9"]
    built["hourly"]["image:chrome.exe"]["9"] = {
        **stats, "median": 4.0, "mad": 0.0}
    assert profile.volume(built, "image:chrome.exe", 9, 9) is None
    spike = profile.volume(built, "image:chrome.exe", 9, 17)
    assert spike is not None and spike["value"] == 1.0


def test_one_strong_signal_is_not_diluted_away(tmp_path):
    built, path = _build(tmp_path, _benign())
    beacon = {
        "ts": "2026-11-07T09:30:00Z", "host": "WS1", "kind": "process",
        "event_id": 1, "process": "chrome.exe", "parent": "explorer.exe",
        "user": "CORP\\olu", "dest_ip": "185.10.20.30", "dest_port": 8443,
        "cmdline": "chrome.exe --type=renderer",
    }
    _append(path, beacon)
    result = anomaly.score_row(beacon, built)
    assert result["score"] >= 4.0  # novel C2 destination surfaces


def test_trace_max_leads_mean_context(tmp_path):
    import pathlib
    rows = []
    edges = []
    for index in range(10):
        edge = f"p{index}.exe>child.exe"
        edges.append(edge)
        parent, child = edge.split(">")
        rows.append({"ts": f"2026-11-07T08:00:{index:02d}Z",
                     "host": "WS1", "kind": "process", "event_id": 1,
                     "process": child, "parent": parent})
    path = pathlib.Path(_paths(tmp_path)[0])
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    built = profile.build(path)
    built["limits"]["min_observations"] = 1
    scored = anomaly.trace_score({"edges": ["winword.exe>evil.exe"] + edges},
                                 built)
    assert scored["score"] >= 7.0


def test_single_host_estate_is_not_double_counted(tmp_path):
    built, _path = _build(tmp_path, _benign())
    estate = profile.merge([built])
    row = {
        "ts": "2026-11-07T03:00:00Z", "host": "WS1", "kind": "process",
        "event_id": 1, "process": "neverseen.exe", "parent": "explorer.exe",
        "user": "CORP\\olu",
    }
    solo = anomaly.score_row(row, built)
    with_estate = anomaly.score_row(row, built, estate=estate)
    assert [c["name"] for c in with_estate["components"]] == \
        [c["name"] for c in solo["components"]]
    assert with_estate["score"] == solo["score"]


def test_single_volume_spike_is_capped_below_critical(tmp_path):
    burst = [{
        "ts": f"2026-11-07T09:{minute:02d}:00Z", "host": "WS1",
        "kind": "auth", "event_id": 4624, "user": "CORP\\olu",
        "description": "logon type=3",
    } for minute in range(45)]
    rows = _benign() + burst
    built, _path = _build(tmp_path, rows)
    batch = anomaly._batch_counts(rows)
    result = anomaly.score_row(burst[0], built, batch=batch)
    assert result["score"] <= 8.5


def test_updater_lookalike_is_not_self():
    assert anomaly._is_self("plasma-update.exe") is True
    assert anomaly._is_self("plasma-updater.exe") is False
