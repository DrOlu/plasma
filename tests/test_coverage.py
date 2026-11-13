"""ATT&CK coverage: exact vs rollup counts, fidelity, honest blind spots."""
import json

from plasma import coverage

CORE = coverage.CORE_TECHNIQUES


def _labels(info):
    return [r["rule"] for r in info["rules"]]


def test_coverage_over_real_shipped_rules():
    cov = coverage.coverage()
    assert cov["core_total"] == len(CORE) == 36
    # rollup coverage is the headline; exact stays lower by design
    assert cov["coverage_pct"] >= 85
    assert cov["coverage_exact_pct"] < cov["coverage_pct"]
    assert cov["weighted_pct"] <= cov["coverage_pct"]
    assert sum(cov["fidelity_breakdown"].values()) == cov["core_covered"]
    for tech, info in cov["covered"].items():
        assert info["name"] == CORE[tech]
        assert info["rules"], tech
        for r in info["rules"]:
            assert r["rule"] and r["fidelity"] in coverage.FIDELITY_WEIGHTS
        assert info["fidelity"] in coverage.FIDELITY_WEIGHTS


def test_parents_roll_up_from_covered_subtechniques():
    cov = coverage.coverage()
    for parent in ("T1003", "T1059", "T1071", "T1078", "T1136"):
        assert parent in cov["covered"], parent
        assert cov["covered"][parent]["via_subtechnique"] is True
        assert parent not in {t for t, _ in
                              [(t, v) for t, v in cov["covered"].items()
                               if not v["via_subtechnique"]]}
    # rollup is not inflation: the exact count stays below the rollup count
    assert cov["coverage_exact_pct"] < cov["coverage_pct"]
    assert 70 <= cov["coverage_exact_pct"] <= 75


def test_one_three_zero_rules_close_their_techniques():
    cov = coverage.coverage()
    expected = ("T1070.004", "T1547.001", "T1543.003", "T1098", "T1204.002")
    for tech in expected:
        assert tech in cov["covered"], tech
        assert cov["covered"][tech]["rules"], tech


def test_honest_blind_spots_remain():
    """Keylogging needs kernel hooks; generic registry edits are
    deliberately not checkbox-covered."""
    cov = coverage.coverage()
    assert set(cov["blind"]) == {"T1056", "T1056.001", "T1112"}


def test_canary_capability_covers_impact():
    cov = coverage.coverage()
    assert "T1486" in cov["covered"]
    info = cov["covered"]["T1486"]
    assert any(r["rule"] == "canary:verify" and r["fidelity"] == "high"
               for r in info["rules"])


def test_specific_techniques_are_covered_by_known_rules():
    cov = coverage.coverage()
    covered = cov["covered"]
    assert any("ps-hidden-window" in r for r in _labels(covered["T1564.003"])) \
        if "T1564.003" in covered else True
    assert any("Certutil" in r for r in _labels(covered["T1140"]))
    assert any("Mshta" in r for r in _labels(covered["T1218.005"]))
    # office-spawn rule covers a technique outside the core list -> extra
    assert any("Office" in r["rule"] for r in cov["extra_coverage"]["T1566.001"])


def test_collect_rule_techniques_records_provenance_and_fidelity():
    cov_map = coverage.collect_rule_techniques()
    labels = [r["rule"] for r in cov_map["T1027"]]
    assert "tap:ps-base64-decode" in labels
    assert all(r["fidelity"] in coverage.FIDELITY_WEIGHTS for r in cov_map["T1027"])


def test_gene_fidelity_overrides_default():
    cov_map = coverage.collect_rule_techniques()
    sam = [r for r in cov_map["T1003.002"] if r["rule"].startswith("gene:")]
    assert sam and sam[0]["fidelity"] == "high"       # mapped in GENE_FIDELITY


def test_custom_sensors_dir_and_low_fidelity_discount(tmp_path):
    sensors = tmp_path / "sensors"
    sensors.mkdir()
    (sensors / "plasma-tap-rules.json").write_text(json.dumps({
        "version": 1,
        "providers": {"powershell": "Microsoft-Windows-PowerShell"},
        "rules": [{"name": "r1", "provider": "powershell", "event_id": 4104,
                   "field": "f", "substr": "x", "severity": "low",
                   "fidelity": "low", "technique": "T1112"}],
    }))
    cov = coverage.coverage(sensors)
    assert "T1112" in cov["covered"]
    assert cov["covered"]["T1112"]["fidelity"] == "low"
    # one low-fidelity rule cannot masquerade as full-strength coverage
    assert cov["weighted_pct"] < cov["coverage_pct"]


def test_missing_fidelity_defaults_to_medium(tmp_path):
    sensors = tmp_path / "sensors"
    sensors.mkdir()
    (sensors / "plasma-tap-rules.json").write_text(json.dumps({
        "version": 1,
        "providers": {"powershell": "Microsoft-Windows-PowerShell"},
        "rules": [{"name": "r1", "provider": "powershell", "event_id": 4104,
                   "field": "f", "substr": "x", "severity": "low",
                   "technique": "T1112"}],
    }))
    cov = coverage.coverage(sensors)
    assert cov["covered"]["T1112"]["fidelity"] == "medium"


def test_sensors_resolve_from_frozen_bundle(tmp_path, monkeypatch):
    """Installed nodes keep the payload at <_MEIPASS>/embedded/sensors."""
    sensors = tmp_path / "embedded" / "sensors"
    sensors.mkdir(parents=True)
    (sensors / "plasma-tap-rules.json").write_text('{"rules": []}\n')
    (sensors / "plasma-baseline.gen").write_text("")
    monkeypatch.setattr("sys._MEIPASS", str(tmp_path), raising=False)
    monkeypatch.chdir(tmp_path)
    assert coverage._repo_sensors() == sensors
    cov = coverage.coverage()
    assert cov["core_total"] == 36
