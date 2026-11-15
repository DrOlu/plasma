"""The vendored SigmaHQ corpus: provenance, shape and licence."""
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SENSORS = REPO / "sensors"
CORPUS = SENSORS / "plasma-sigma.gen"
META = SENSORS / "sigma-sources.json"
LICENSE = SENSORS / "SIGMA-DRL-1.1.md"

MATCH_RE = re.compile(r"^\$([a-z0-9_]+): ([A-Za-z0-9_]+) ~= '(.*)'$")


def rules():
    return [json.loads(line) for line in CORPUS.read_text().splitlines()
            if line.strip()]


def test_corpus_is_vendored_with_licence_and_source_metadata():
    assert CORPUS.exists() and META.exists() and LICENSE.exists()
    meta = json.loads(META.read_text())
    assert meta["upstream"] == "https://github.com/SigmaHQ/sigma"
    assert re.fullmatch(r"[0-9a-f]{40}", meta["commit"])
    assert meta["license"] == "Detection Rule License (DRL) 1.1"
    assert "Detection Rule License" in LICENSE.read_text()
    assert meta["selected"] == len(rules()) >= 200


def test_corpus_is_deterministic_and_well_formed():
    rows = rules()
    names = [r["Name"] for r in rows]
    assert len(names) == len(set(names)), "WHIDS refuses duplicate names"
    allowed = {1, 3, 6, 7, 10, 11, 12, 13, 14, 17, 18}
    for rule in rows:
        assert set(rule["Meta"]["EventIDs"]) <= allowed
        assert rule["Meta"]["Author"]
        assert rule["Meta"]["Criticality"] >= 6
        variables = set()
        for match in rule["Matches"]:
            found = MATCH_RE.match(match)
            assert found, match
            variables.add("$" + found.group(1))
            re.compile(found.group(3))
        assert "$" in rule["Condition"]
        for used in re.findall(r"\$[a-z0-9_]+", rule["Condition"]):
            assert used in variables, (rule["Name"], used)
        assert any(t.startswith("T") for t in rule["Tags"])


def test_corpus_carries_attack_techniques_into_coverage():
    from plasma import coverage
    cov = coverage.coverage()
    assert cov["coverage_pct"] >= 94
    assert cov["weighted_pct"] >= 85
    sigma_rules = [r for info in cov["covered"].values()
                   for r in info["rules"] if r["rule"].startswith("sigma:")]
    assert sigma_rules, "Sigma corpus must contribute to the matrix"


def test_deploy_rules_ships_the_sigma_corpus(tmp_path):
    from plasma import whids
    src = tmp_path / "sensors"
    db = tmp_path / "rules"
    src.mkdir()
    for name in ("plasma-iocs.gen", "plasma-baseline.gen", "plasma-sigma.gen"):
        (src / name).write_text('{"Name":"x"}\n')
    copied = whids.deploy_rules(src, db)
    assert copied == ["plasma-iocs.gen", "plasma-baseline.gen",
                      "plasma-sigma.gen"]
    assert (db / "plasma-sigma.gen").exists()


def test_bundle_ships_the_sysmon_config_for_telemetry():
    from plasma import bundle
    assert "sysmon-config.xml" in bundle.SENSOR_FILES
    assert (SENSORS / "sysmon-config.xml").exists()
