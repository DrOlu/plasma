"""ATT&CK coverage: what the shipped rules watch vs the curated core list."""
import json

from plasma import coverage


def test_coverage_over_real_shipped_rules():
    cov = coverage.coverage()
    assert cov["core_total"] == len(coverage.CORE_TECHNIQUES)
    assert 0 < cov["core_covered"] < cov["core_total"], \
        "both zero and full coverage would mean the probe is broken"
    assert 40 <= cov["coverage_pct"] <= 90
    # every covered entry carries its rule provenance
    for tech, info in cov["covered"].items():
        assert info["name"] == coverage.CORE_TECHNIQUES[tech]
        assert info["rules"], tech
    # blind entries are core techniques with no rules
    for tech in cov["blind"]:
        assert tech not in cov["covered"]


def test_specific_techniques_are_covered_by_known_rules():
    cov = coverage.coverage()
    covered = cov["covered"]
    # tap rule for hidden windows
    assert any("ps-hidden-window" in r for r in covered["T1564.003"]["rules"])
    # gene rules for certutil (decode) and mshta
    assert any("Certutil" in r for r in covered["T1140"]["rules"])
    assert any("Mshta" in r for r in covered["T1218.005"]["rules"])
    # office-spawn rule covers a technique outside the core list -> extra
    assert any("Office" in r for r in
               (cov["extra_coverage"].get("T1566.001") or []))


def test_ransomware_is_honestly_blind():
    """The audit's whole point: Plasma does NOT watch ransomware staging —
    the coverage probe must say so out loud instead of pretending."""
    cov = coverage.coverage()
    assert "T1486" in cov["blind"]


def test_collect_rule_techniques_records_provenance():
    cov_map = coverage.collect_rule_techniques()
    assert cov_map["T1027"], "ps-base64-decode tap rule"
    assert any("tap:ps-base64-decode" in r for r in cov_map["T1027"])


def test_custom_sensors_dir(tmp_path):
    sensors = tmp_path / "sensors"
    sensors.mkdir()
    (sensors / "plasma-tap-rules.json").write_text(json.dumps({
        "version": 1,
        "providers": {"powershell": "Microsoft-Windows-PowerShell"},
        "rules": [{"name": "r1", "provider": "powershell", "event_id": 4104,
                   "field": "f", "substr": "x", "severity": "low",
                   "technique": "T1486"}],
    }))
    cov = coverage.coverage(sensors)
    assert "T1486" in cov["covered"]
    assert "T1486" not in cov["blind"]
