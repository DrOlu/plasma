import json
import shutil

from models import PlasmaEvent
from plasma import whids


def load_fixture():
    return [json.loads(ln) for ln in
            open("tests/fixtures/whids_alerts.jsonl", encoding="utf-8").read().splitlines()
            if ln.strip()]


def seed(root):
    """Seed a WHIDS Logs/Alerts tree with the fixture alerts."""
    alerts = root / "Logs" / "Alerts" / "2026-10-19"
    alerts.mkdir(parents=True)
    shutil.copy("tests/fixtures/whids_alerts.jsonl", alerts / "alerts.jsonl")
    return root


def test_normalize_process_alert():
    alert = load_fixture()[0]
    event = whids.normalize_alert(alert, host="WS1")
    assert event["source"] == "whids"
    assert event["kind"] == "alert"
    assert event["severity"] == "critical"
    assert event["action"] == "killed"
    assert event["technique"] == "T1059.001"
    assert event["process"] == "powershell.exe"
    assert event["pid"] == 6102
    assert event["dest_ip"] == "185.220.101.4"
    assert event["dest_port"] == 4444
    assert event["file_hash"] == "9f2c8e14d7b3a6c5e8f1042736b9adc2e5f7081a3b6d9c4e7f2a5b8d1c4e7f09"
    assert event["score"] == 1.0
    assert event["host"] == "WS1"
    # Must satisfy the frozen PlasmaEvent contract.
    PlasmaEvent(**event)


def test_normalize_dns_alert():
    event = whids.normalize_alert(load_fixture()[2], host="WS1")
    assert event["dns_query"] == "cdn-sync.bad-c2.example"
    assert event["technique"] == "T1071.004"
    assert event["severity"] == "critical"


def test_non_alert_ignored():
    assert whids.normalize_alert({"Event": {"EventData": {}}}) is None


def test_pull_dedupe(tmp_path):
    out = tmp_path / "plasma" / "events.jsonl"
    whids_seed = seed(tmp_path / "whids")
    first = whids.pull(tmp_path / "whids", out, host="WS1")
    assert first["alerts"] == 4
    assert first["written"] == 4
    second = whids.pull(tmp_path / "whids", out, host="WS1")
    assert second["written"] == 0
    assert second["already_present"] == 4
    rows = [json.loads(ln) for ln in out.read_text().splitlines() if ln.strip()]
    assert len(rows) == 4
    assert all(PlasmaEvent(**row) for row in rows)


def test_pull_missing_logs(tmp_path):
    result = whids.pull(tmp_path / "no-whids", tmp_path / "out.jsonl")
    assert "error" in result


def test_extract_indicators_filters():
    rows = [json.loads(ln) for ln in
            open("tests/fixtures/whids_alerts.jsonl", encoding="utf-8").read().splitlines() if ln.strip()]
    events = [whids.normalize_alert(row) for row in rows]
    iocs = whids.extract_indicators([e for e in events if e], min_confidence=8)
    indicators = {i["indicator"] for i in iocs}
    assert "9f2c8e14d7b3a6c5e8f1042736b9adc2e5f7081a3b6d9c4e7f2a5b8d1c4e7f09" in indicators
    assert "cdn-sync.bad-c2.example" in indicators
    assert "outlook.office365.com" not in indicators  # benign, and criticality 3
    for ioc in iocs:
        assert ioc["criticality"] >= 8


def test_detect_only_posture():
    """WHIDS ships neutered: no kill/blacklist/dump actions anywhere."""
    lines = [ln for ln in open("sensors/whids.toml", encoding="utf-8")
             if ln.strip() and not ln.strip().startswith("#")]
    toml = "\n".join(lines)
    for forbidden in ("kill", "blacklist", "memdump", "filedump", "regdump"):
        assert forbidden not in toml
    assert 'critical = ["report"]' in toml
    rule = whids.build_gene_rule([
        {"indicator": "9f2c8e14d7b3a6c5e8f1042736b9adc2e5f7081a3b6d9c4e7f2a5b8d1c4e7f09",
         "ioc_type": "sha256", "criticality": 10, "family": "x"},
    ])
    assert "Actions" not in rule


def test_gene_rule_shape():
    iocs = [
        {"indicator": "9f2c8e14d7b3a6c5e8f1042736b9adc2e5f7081a3b6d9c4e7f2a5b8d1c4e7f09",
         "ioc_type": "sha256", "criticality": 10, "family": "T1059.001"},
        {"indicator": "cdn-sync.bad-c2.example", "ioc_type": "domain", "criticality": 9,
         "family": "T1071.004"},
        {"indicator": "185.220.101.4", "ioc_type": "ip", "criticality": 9, "family": "T1059.001"},
    ]
    rule = whids.build_gene_rule(iocs)
    assert rule["Name"] == "Plasma IOC Feed"
    assert rule["Meta"]["Schema"] == "1.0.0"          # WHIDS v1.7.0 engine
    assert rule["Meta"]["EventIDs"] == [1, 3, 6, 7, 15, 22]
    assert "Actions" not in rule                      # no action semantics in pushed rules
    # sha256 yields two expressions (Hashes + ImageHashes), domain one, ip one.
    assert len(rule["Matches"]) == 4
    assert " or " in rule["Condition"]
    assert "Hashes ~= '(?i)sha256=9f2c" in rule["Matches"][0]
    assert "QueryName" in rule["Matches"][2]
    assert "DestinationIp = '185.220.101.4'" in rule["Matches"][3]


def test_merge_dedupes_expressions():
    existing = {"Name": "Plasma IOC Feed", "Matches": ["$plasma0: Hashes ~= /a/"], "Condition": "$plasma0"}
    new = whids.build_gene_rule([
        {"indicator": "9f2c8e14d7b3a6c5e8f1042736b9adc2e5f7081a3b6d9c4e7f2a5b8d1c4e7f09",
         "ioc_type": "sha256", "criticality": 10, "family": "x"},
    ])
    merged = whids.merge_rules(existing, new)
    assert len(merged["Matches"]) == 3
    labels = [m.split(":")[0] for m in merged["Matches"]]
    assert labels == ["$plasma0", "$plasma1", "$plasma2"]
    assert merged["Condition"] == "$plasma0 or $plasma1 or $plasma2"


def test_push_dry_run_and_apply(tmp_path):
    events = tmp_path / "plasma" / "events.jsonl"
    seed(tmp_path / "whids")
    whids.pull(tmp_path / "whids", events, host="WS1")
    root = tmp_path / "Whids"

    dry = whids.push(events, root, min_confidence=8, apply=False)
    assert dry["dry_run"] is True
    assert dry["indicators"] >= 2
    assert not (root / "Database" / "Rules" / "plasma-iocs.gen").exists()

    result = whids.push(events, root, min_confidence=8, apply=True, reason="live demo")
    assert result["ok"] is True
    rules_file = root / "Database" / "Rules" / "plasma-iocs.gen"
    assert rules_file.exists()
    rule = json.loads(rules_file.read_text(encoding="utf-8"))
    assert rule["Name"] == "Plasma IOC Feed"
    assert len(rule["Matches"]) == rule["Condition"].count("$plasma")  # 1:1 labels

    journal = (events.parent / "whids-intel-journal.jsonl").read_text().splitlines()
    entry = json.loads(journal[-1])
    assert entry["action"] == "whids.push"
    assert entry["reason"] == "live demo"
    assert entry["rules_sha256"]


def test_apply_twice_creates_backup(tmp_path):
    events = tmp_path / "plasma" / "events.jsonl"
    seed(tmp_path / "whids")
    whids.pull(tmp_path / "whids", events, host="WS1")
    root = tmp_path / "Whids"
    whids.push(events, root, min_confidence=8, apply=True)
    whids.push(events, root, min_confidence=8, apply=True, reason="second apply")
    backups = list((root / "Database" / "Rules").glob("plasma-iocs.*.bak.gen"))
    assert len(backups) == 1


def test_status(tmp_path):
    events = tmp_path / "plasma" / "events.jsonl"
    root = seed(tmp_path / "whids")
    whids.pull(root, events, host="WS1")
    whids.push(events, root, min_confidence=8, apply=True)

    result = whids.status(root, events)
    assert result["whids_alerts"] == 4
    assert result["plasma_events_present"] is True
    assert result["rules_present"] is True
    assert result["rules_expressions"] >= 2
    assert result["last_push"]["action"] == "whids.push"
