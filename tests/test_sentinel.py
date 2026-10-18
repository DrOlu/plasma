import gzip
import json

from models import PlasmaEvent
from plasma import sentinel

HASH = "9f2c8e14d7b3a6c5e8f1042736b9adc2e5f7081a3b6d9c4e7f2a5b8d1c4e7f09"
PUBLIC_IP = "185.220.101.4"
PRIVATE_IP = "10.0.0.5"
BENIGN_DOMAIN = "outlook.office365.com"
BAD_DOMAIN = "cdn-sync.bad-c2.example"


def detection(rule="Credential + Beacon", rule_id="SENT-001", confidence=0.97,
              tier=0, response=5, metadata=None, process="p.exe", pid=5011,
              ts="2026-10-19T10:00:00Z"):
    return {
        "type": "detection",
        "timestamp": ts,
        "data": {
            "RuleName": rule,
            "RuleId": rule_id,
            "Evidence": "Encoded PowerShell with outbound connection",
            "Reasoning": "Two independent fragments on one PID",
            "Confidence": confidence,
            "Tier": tier,
            "ProcessName": process,
            "ProcessId": pid,
            "SignalType": 1,
            "Metadata": metadata or {},
            "Timestamp": ts,
            "AuthorizedResponse": response,
            "KillAuthorized": response >= 4,
        },
    }


def write_sentinel_events(root, records):
    root.mkdir(parents=True, exist_ok=True)
    with open(root / "events.jsonl", "w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record) + "\n")


def test_normalize_tier1_kill():
    event = sentinel.normalize_detection(detection(metadata={
        "AttackTechnique": "T1059.001", "RemoteIp": PUBLIC_IP,
        "Domain": BAD_DOMAIN, "User": "CORP\\olu",
    }), host="WS1")
    assert event["source"] == "sentinel"
    assert event["kind"] == "alert"
    assert event["severity"] == "critical"
    assert event["action"] == "killed"
    assert event["technique"] == "T1059.001"
    assert event["dest_ip"] == PUBLIC_IP
    assert event["dns_query"] == BAD_DOMAIN
    assert event["alert_id"] == "SENT-001"
    assert event["host"] == "WS1"
    # The normalized record must satisfy the frozen contract.
    PlasmaEvent(**event)


def test_normalize_tier2_log_only():
    event = sentinel.normalize_detection(detection(confidence=0.55, tier=1, response=0))
    assert event["severity"] == "low"
    assert event["action"] == "logged"


def test_non_detection_records_ignored():
    assert sentinel.normalize_detection({"type": "response", "data": {}}) is None
    assert sentinel.normalize_detection({"type": "audit", "data": {}}) is None


def test_pull_and_dedupe(tmp_path):
    sentinel_root = tmp_path / "Sentinel"
    out = tmp_path / "plasma" / "events.jsonl"
    write_sentinel_events(sentinel_root, [
        detection(rule="One", rule_id="SENT-001"),
        detection(rule="Two", rule_id="SENT-002", ts="2026-10-19T10:01:00Z"),
        {"type": "response", "timestamp": "2026-10-19T10:02:00Z", "data": {"ActionTaken": "LOG"}},
    ])

    first = sentinel.pull(sentinel_root, out, host="WS1")
    assert first["detections"] == 2
    assert first["written"] == 2
    assert first["skipped_records"] == 1

    second = sentinel.pull(sentinel_root, out, host="WS1")
    assert second["written"] == 0
    assert second["already_present"] == 2

    lines = [json.loads(ln) for ln in out.read_text().splitlines() if ln.strip()]
    assert len(lines) == 2
    assert all(PlasmaEvent(**line) for line in lines)


def test_extract_filters_private_and_benign():
    rows = [
        {"dest_ip": PUBLIC_IP, "dns_query": BAD_DOMAIN, "file_hash": HASH,
         "severity": "critical", "score": 0.97, "alert_id": "SENT-001"},
        {"dest_ip": PRIVATE_IP, "dns_query": BENIGN_DOMAIN,
         "severity": "critical", "score": 0.97, "alert_id": "SENT-002"},
        {"dest_ip": "127.0.0.1", "dns_query": "localhost",
         "severity": "high", "score": 0.90, "alert_id": "SENT-003"},
    ]
    iocs = sentinel.extract_indicators(rows, min_confidence=85)
    indicators = {i["Indicator"] for i in iocs}
    assert PUBLIC_IP in indicators
    assert BAD_DOMAIN in indicators
    assert HASH in indicators
    assert PRIVATE_IP not in indicators
    assert "127.0.0.1" not in indicators
    assert BENIGN_DOMAIN not in indicators
    assert all(i["Source"] == "Plasma" for i in iocs)


def test_low_confidence_excluded():
    rows = [{"dest_ip": PUBLIC_IP, "severity": "medium", "score": 0.55}]
    assert sentinel.extract_indicators(rows, min_confidence=85) == []


def test_merge_prefers_higher_confidence():
    existing = [{"Indicator": PUBLIC_IP, "IocType": "ip", "Confidence": 60, "Source": "Bundled"}]
    new = [{"Indicator": PUBLIC_IP, "IocType": "ip", "Confidence": 95, "Source": "Plasma"}]
    merged = sentinel.merge_bundle(existing, new)
    assert len(merged) == 1
    assert merged[0]["Confidence"] == 95
    assert merged[0]["Source"] == "Plasma"


def test_push_dry_run_writes_nothing(tmp_path):
    events = tmp_path / "plasma" / "events.jsonl"
    events.parent.mkdir(parents=True)
    events.write_text(json.dumps({
        "severity": "critical", "score": 0.97, "dest_ip": PUBLIC_IP,
        "dns_query": BAD_DOMAIN, "file_hash": HASH, "alert_id": "SENT-001",
    }) + "\n")
    sentinel_root = tmp_path / "Sentinel"

    result = sentinel.push(events, sentinel_root, apply=False)
    assert result["dry_run"] is True
    assert result["new_iocs"] == 3
    assert not (sentinel_root / "threatfox-bundle.json.gz").exists()


def test_push_apply_backs_up_merges_and_journals(tmp_path):
    events = tmp_path / "plasma" / "events.jsonl"
    events.parent.mkdir(parents=True)
    events.write_text(json.dumps({
        "severity": "critical", "score": 0.97, "dest_ip": PUBLIC_IP,
        "dns_query": BAD_DOMAIN, "file_hash": HASH, "alert_id": "SENT-001",
    }) + "\n")

    sentinel_root = tmp_path / "Sentinel"
    sentinel_root.mkdir(parents=True)
    existing = [{"Indicator": "203.0.113.9", "IocType": "ip",
                 "Confidence": 70, "Source": "Bundled"}]
    with gzip.open(sentinel_root / "threatfox-bundle.json.gz", "wt", encoding="utf-8") as fh:
        json.dump(existing, fh)

    result = sentinel.push(events, sentinel_root, apply=True, reason="audit test")
    assert result["ok"] is True
    assert result["dry_run"] is False
    assert result["merged_iocs"] == 4
    assert result["backup"] and (sentinel_root / "threatfox-bundle.json.gz").exists()

    bundle = sentinel.read_bundle(sentinel_root / "threatfox-bundle.json.gz")
    assert len(bundle) == 4
    assert any(i["Indicator"] == PUBLIC_IP for i in bundle)

    journal = (events.parent / "sentinel-intel-journal.jsonl").read_text().splitlines()
    entry = json.loads(journal[-1])
    assert entry["action"] == "sentinel.push"
    assert entry["reason"] == "audit test"
    assert entry["new_iocs"] == 3
    assert entry["bundle_sha256"]


def test_status_reports_both_sides(tmp_path):
    sentinel_root = tmp_path / "Sentinel"
    write_sentinel_events(sentinel_root, [detection()])
    events = tmp_path / "plasma" / "events.jsonl"
    sentinel.pull(sentinel_root, events)
    sentinel.push(events, sentinel_root, apply=True)

    result = sentinel.status(sentinel_root, events)
    assert result["sentinel_detections"] == 1
    assert result["plasma_events_present"] is True
    assert result["bundle_present"] is True
    assert result["bundle_iocs"] >= 1
    assert result["last_push"]["action"] == "sentinel.push"
