"""Estate edge ledger: build, merge, fan-out findings and sync."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

import pytest

from plasma import estate


def _ts(minutes_ago=0):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat().replace("+00:00", "Z")


def _row(user=None, source=None, process="cmd.exe", file_hash=None, minutes=1,
         kind="auth", event_id=4624):
    row = {"ts": _ts(minutes), "host": "WS1", "kind": kind,
           "event_id": event_id, "description": "logon type=3"}
    if user:
        row["user"] = user
    if source:
        row["dest_ip"] = source
    if process:
        row["process"] = process
    if file_hash:
        row["file_hash"] = file_hash
    return row


def _write(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    return path


def _ledger(host, users, sources=None, generated_at=None, window=60,
            hashes=None, coverage=None):
    body = {
        "schema": estate.SCHEMA,
        "kind": "host-edge-ledger",
        "host": host,
        "role": "member",
        "generated_at": generated_at or _ts(0),
        "window": {"minutes": window, "start": _ts(60), "end": _ts(0)},
        "n": 1,
        "users": {},
        "processes": {},
        "hashes": dict(hashes or {}),
        "truncated": {},
        "coverage": coverage or {},
    }
    for user in users:
        body["users"][user] = {
            "count": 1, "first": _ts(10), "last": _ts(1),
            "sources": {sources[user]: 1} if sources and user in sources else {},
            "logon_types": {"3": 1},
        }
    return estate.sign_ledger(body)


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------

def test_build_counts_users_sources_processes_and_hashes(tmp_path):
    path = _write(tmp_path / "events.jsonl", [
        _row("CORP\\alice", "10.0.0.5", "powershell.exe", "a" * 64, minutes=2),
        _row("CORP\\alice", "10.0.0.5", "powershell.exe", "a" * 64, minutes=1),
        _row("CORP\\bob", "10.0.0.6", "cmd.exe", minutes=3),
        _row("MACHINE$", "10.0.0.7", minutes=1),
    ])
    ledger = estate.build(path, host="WS1")
    assert ledger["host"] == "WS1"
    assert ledger["users"]["alice"]["count"] == 2
    assert ledger["users"]["alice"]["sources"] == {"10.0.0.5": 2}
    assert ledger["users"]["alice"]["logon_types"] == {"3": 2}
    assert ledger["users"]["bob"]["count"] == 1
    assert "machine" not in ledger["users"]
    assert ledger["processes"]["alice>powershell.exe"] == 2
    assert ledger["hashes"]["a" * 64] == 2
    assert estate.verify_ledger(ledger)["ok"] is True
    blob = json.dumps(ledger)
    assert "cmdline" not in blob and "file_path" not in blob


def test_build_caps_users_and_keeps_integrity(tmp_path):
    rows = [_row(f"CORP\\user{index}", f"10.0.{index // 250}.{index % 250}")
            for index in range(320)]
    ledger = estate.build(_write(tmp_path / "events.jsonl", rows), host="WS1")
    assert len(ledger["users"]) == estate.MAX_USERS
    assert ledger["truncated"]["users"] == 320 - estate.MAX_USERS
    assert estate.verify_ledger(ledger)["ok"] is True


def test_build_coverage_counts_identity_and_kerberos(tmp_path):
    path = _write(tmp_path / "events.jsonl", [
        _row("CORP\\alice", "10.0.0.5", event_id=4624, minutes=2),
        _row("CORP\\bob", "10.0.0.6", event_id=4768, minutes=1),
        _row(None, None, "powershell.exe", kind="process", event_id=1, minutes=3),
    ])
    coverage = estate.build(path, host="WS1")["coverage"]
    assert coverage["rows"] == 3
    assert coverage["identity_events"] == 2
    assert coverage["kerberos_events"] == 1
    assert coverage["last_identity_event"]
    assert coverage["kinds"] == {"auth": 2, "process": 1}


def test_no_identity_evidence_is_unverified_not_a_clean_result(tmp_path):
    path = _write(tmp_path / "events.jsonl", [
        _row(None, None, "powershell.exe", kind="process", event_id=1),
    ])
    result = estate.findings(estate.build(path, host="WS1"), threshold=2)
    item = next(item for item in result["findings"]
                if item["type"] == "estate_identity_unverified")
    assert item["score"] == 7 and item["reason"] == "no_identity_evidence"
    assert item["rows"] == 1


def test_identity_feed_that_stopped_inside_the_window_is_blind(tmp_path):
    path = _write(tmp_path / "events.jsonl", [
        _row("CORP\\alice", minutes=120),   # identity worked before the window
        _row(None, None, "powershell.exe", kind="process", event_id=1),
    ])
    result = estate.findings(estate.build(path, host="WS1"), threshold=2)
    blind = next(item for item in result["findings"]
                 if item["type"] == "estate_identity_blind")
    assert blind["score"] == 9 and blind["reason"] == "identity_stopped"


def test_empty_window_is_no_telemetry_not_a_clean_result(tmp_path):
    path = _write(tmp_path / "events.jsonl", [])
    result = estate.findings(estate.build(path, host="WS1"), threshold=2)
    types = {item["type"] for item in result["findings"]}
    assert "estate_no_telemetry" in types
    assert "estate_identity_blind" not in types
    empty = next(item for item in result["findings"]
                 if item["type"] == "estate_no_telemetry")
    assert empty["score"] == 8


def test_failed_identity_pull_is_blind(tmp_path):
    path = _write(tmp_path / "events.jsonl", [_row("CORP\\alice")])
    (tmp_path / "identity-pull.json").write_text(json.dumps({
        "ts": _ts(1), "ok": False, "events_seen": 0, "written": 0,
        "error": "Get-WinEvent: RPC server unavailable"}))
    result = estate.findings(estate.build(path, host="WS1"), threshold=2)
    blind = next(item for item in result["findings"]
                 if item["type"] == "estate_identity_blind")
    assert blind["score"] == 9 and blind["reason"] == "identity_pull_failed"
    assert "RPC server unavailable" in blind["error"]


def test_dc_without_kerberos_is_flagged_but_member_is_not(tmp_path):
    path = _write(tmp_path / "events.jsonl", [_row("CORP\\alice")])
    dc = estate.findings(estate.build(path, host="DC1", role="dc"), threshold=2)
    assert any(item["type"] == "estate_kerberos_blind"
               for item in dc["findings"])
    member = estate.findings(estate.build(path, host="WS1"), threshold=2)
    assert not any(item["type"] == "estate_kerberos_blind"
                   for item in member["findings"])


def test_stale_identity_pull_is_flagged(tmp_path):
    path = _write(tmp_path / "events.jsonl", [_row("CORP\\alice")])
    (tmp_path / "identity-pull.json").write_text(json.dumps({
        "ts": _ts(400), "ok": True, "events_seen": 1, "written": 1}))
    result = estate.findings(estate.build(path, host="WS1"), threshold=2,
                             max_identity_age_minutes=180)
    stale = next(item for item in result["findings"]
                 if item["type"] == "estate_identity_stale")
    assert stale["score"] == 8 and stale["age_minutes"] >= 399


def test_stale_host_does_not_duplicate_coverage_findings():
    old = _ledger("WS1", ["alice"], generated_at=_ts(600),
                  coverage={"rows": 10, "identity_events": 0})
    result = estate.findings(estate.merge([old], max_age_minutes=180),
                             threshold=2)
    types = {item["type"] for item in result["findings"]}
    assert "estate_stale_host" in types
    assert "estate_identity_blind" not in types


def test_merge_preserves_coverage():
    coverage = {"rows": 10, "identity_events": 3, "kerberos_events": 1,
                "last_identity_event": _ts(1), "last_event": _ts(1),
                "kinds": {"auth": 3}, "identity_pull": {"ok": True}}
    merged = estate.merge([_ledger("WS1", ["alice"], coverage=coverage)])
    assert merged["hosts"]["WS1"]["coverage"] == coverage


def test_tampered_ledger_is_refused(tmp_path):
    path = tmp_path / "ledger.json"
    estate.save(path, _ledger("WS1", ["alice"]))
    data = json.loads(path.read_text())
    data["users"]["alice"]["count"] = 999
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        estate.load(path)


# ---------------------------------------------------------------------------
# merge
# ---------------------------------------------------------------------------

def test_merge_combines_hosts_and_keeps_newest_copy():
    first = _ledger("WS1", ["alice"], generated_at=_ts(10))
    newer = _ledger("WS1", ["alice", "bob"], generated_at=_ts(1))
    second = _ledger("WS2", ["alice"])
    merged = estate.merge([first, newer, second], max_age_minutes=180)
    assert set(merged["hosts"]) == {"WS1", "WS2"}
    assert set(merged["users"]["alice"]["hosts"]) == {"WS1", "WS2"}
    assert "bob" in merged["users"]  # newest WS1 copy won
    assert estate.verify_ledger(merged)["ok"] is True


def test_stale_host_is_flagged():
    old = _ledger("WS1", ["alice"], generated_at=_ts(600))
    merged = estate.merge([old], max_age_minutes=180)
    assert merged["hosts"]["WS1"]["stale"] is True
    result = estate.findings(merged, threshold=2)
    assert any(item["type"] == "estate_stale_host" for item in result["findings"])


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------

def _fanout(count=5, shared=False):
    ledgers = []
    for index in range(count):
        source = "10.0.0.9" if shared else f"10.0.1.{index}"
        ledgers.append(_ledger(f"WS{index}", ["alice"], {"alice": source}))
    return estate.merge(ledgers)


def test_user_fanout_without_a_shared_source_scores_seven():
    result = estate.findings(_fanout(5), threshold=5)
    fan = next(item for item in result["findings"]
               if item["type"] == "estate_user_fanout")
    assert fan["host_count"] == 5 and fan["score"] == 7
    assert fan["linked"] is False


def test_user_fanout_with_a_shared_source_scores_nine():
    result = estate.findings(_fanout(5, shared=True), threshold=5)
    fan = next(item for item in result["findings"]
               if item["type"] == "estate_user_fanout")
    assert fan["score"] == 9 and fan["linked"] is True
    assert fan["shared_sources"] == ["10.0.0.9"]


def test_threshold_is_respected():
    result = estate.findings(_fanout(4), threshold=5)
    assert not [item for item in result["findings"]
                if item["type"] == "estate_user_fanout"]


def test_source_fanout_is_detected():
    ledgers = [_ledger(f"WS{index}", [f"user{index}"],
                       {f"user{index}": "10.0.0.9"})
               for index in range(5)]
    result = estate.findings(estate.merge(ledgers), threshold=5)
    source = next(item for item in result["findings"]
                  if item["type"] == "estate_source_fanout")
    assert source["host_count"] == 5 and source["score"] == 9


def test_shared_file_hash_across_hosts_is_detected():
    digest = "b" * 64
    ledgers = [_ledger(f"WS{index}", [f"user{index}"], hashes={digest: 1})
               for index in range(5)]
    result = estate.findings(estate.merge(ledgers), threshold=5)
    item = next(found for found in result["findings"]
                if found["type"] == "estate_hash_fanout")
    assert item["host_count"] == 5 and item["score"] == 8
    assert item["hash"] == digest


def test_save_is_atomic_and_leaves_no_temp_file(tmp_path):
    path = tmp_path / "WS1.json"
    estate.save(path, _ledger("WS1", ["alice"]))
    assert path.exists() and not list(tmp_path.glob("*.tmp"))
    assert estate.load(path)["host"] == "WS1"


def test_new_host_edge_against_a_baseline():
    baseline = {"users": {"alice": {"hosts": {"WS0": {}}}}}
    result = estate.findings(_fanout(2), threshold=2, baseline=baseline)
    edge = next(item for item in result["findings"]
                if item["type"] == "estate_new_host_edge")
    assert edge["score"] == 7 and edge["edges"]


# ---------------------------------------------------------------------------
# scale
# ---------------------------------------------------------------------------

def test_thousand_host_merge_is_bounded():
    ledgers = []
    for host in range(1000):
        ledgers.append(_ledger(
            f"HOST{host}", [f"user{host}_{index}" for index in range(10)]))
    started = time.time()
    merged = estate.merge(ledgers)
    report = estate.findings(merged, threshold=5)
    elapsed = time.time() - started
    assert len(merged["hosts"]) == 1000
    assert len(merged["users"]) == estate.ESTATE_MAX_USERS
    assert merged["truncated"]["users"] == 10000 - estate.ESTATE_MAX_USERS
    assert report["ok"] is True
    assert elapsed < 15
    assert len(json.dumps(merged)) < 8_000_000


# ---------------------------------------------------------------------------
# sync
# ---------------------------------------------------------------------------

def _inventory(tmp_path, hosts):
    entries = []
    for index, host in enumerate(hosts):
        events = _write(tmp_path / f"{host}.jsonl", [
            _row("CORP\\alice", "10.0.0.9", minutes=1),
            _row("CORP\\bob", f"10.0.2.{index}", minutes=2),
        ])
        entries.append({"name": host, "transport": "file",
                        "events_path": str(events)})
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps({"hosts": entries}))
    return path


def test_sync_builds_merges_and_reports(tmp_path):
    inventory = _inventory(tmp_path, ["WS1", "WS2", "WS3"])
    out = tmp_path / "estate"
    result = estate.sync(inventory, out, threshold=2)
    assert result["ok"] is True and result["pulled"] == 3
    assert result["estate"]["hosts"] == 3
    assert (out / "estate.json").exists() and (out / "findings.json").exists()
    report = json.loads((out / "findings.json").read_text())
    fan = next(item for item in report["findings"]
               if item["type"] == "estate_user_fanout")
    assert fan["user"] == "alice" and fan["host_count"] == 3
    assert fan["score"] == 9  # shared source across the hosts
    second = estate.sync(inventory, out, threshold=2)
    assert second["ok"] is True and second["pulled"] == 3


def test_sync_records_a_failed_host_without_aborting(tmp_path):
    inventory = _inventory(tmp_path, ["WS1", "WS2"])
    data = json.loads(inventory.read_text())
    data["hosts"].append({"name": "BROKEN", "transport": "file",
                          "events_path": str(tmp_path / "missing.jsonl")})
    inventory.write_text(json.dumps(data))
    result = estate.sync(inventory, tmp_path / "estate", threshold=2)
    assert result["ok"] is True and result["pulled"] == 2
    assert result["failures"][0]["host"] == "BROKEN"
