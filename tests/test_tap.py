"""Tap control-plane tests: rules, pipe format, normalization, collection.

The C++ binary itself is compiled + selftested in CI (tap job); here we
exercise everything that must be true regardless of platform, including
that every normalized tap match satisfies the frozen PlasmaEvent contract.
"""

import json
from pathlib import Path

import pytest

from models import PlasmaEvent
from plasma import tap

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "sensors" / "plasma-tap-rules.json"
FIXTURE = ROOT / "tests" / "fixtures" / "tap_matches.jsonl"


def fixture_rows():
    return [json.loads(ln) for ln in FIXTURE.read_text().splitlines() if ln.strip()]


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------

def test_shipped_rules_are_valid():
    rules = tap.load_rules(RULES)
    assert len(rules) >= 10
    names = {r["name"] for r in rules}
    assert "ps-base64-decode" in names and "wmi-event-filter" in names
    providers = {r["provider"] for r in rules}
    assert providers <= set(tap.TAP_PROVIDER_ALIASES) | {"*"}


def test_rule_validation_rejects(tmp_path):
    bad = tmp_path / "rules.json"
    bad.write_text(json.dumps({"rules": [
        {"name": "x|y", "provider": "powershell", "event_id": 1, "field": "",
         "substr": "pipe|inside", "severity": "high", "technique": "T1027"},
    ]}))
    with pytest.raises(ValueError):
        tap.load_rules(bad)


def test_pipe_format_round_trip(tmp_path):
    rules = tap.load_rules(RULES)
    out = tmp_path / "rules.txt"
    n = tap.build_rules_txt(rules, out)
    assert n == len(rules)
    lines = [ln for ln in out.read_text().splitlines() if ln.strip() and not ln.startswith("#")]
    assert len(lines) == n
    for ln in lines:
        parts = ln.split("|")
        assert len(parts) == 7
        assert parts[5] in tap.SEVERITY_SCORE
        assert int(parts[2]) >= 0


def test_parse_duration():
    assert tap.parse_duration("90s") == 90
    assert tap.parse_duration("5m") == 300
    assert tap.parse_duration("2h") == 7200
    assert tap.parse_duration("45") == 45
    with pytest.raises(ValueError):
        tap.parse_duration("soon")


# ---------------------------------------------------------------------------
# normalization: every match must satisfy the frozen PlasmaEvent contract
# ---------------------------------------------------------------------------

def test_normalize_match_contract():
    for row in fixture_rows():
        event = tap.normalize_match(row, host="WS1")
        PlasmaEvent(**event)  # raises on any contract violation
    ev = tap.normalize_match(fixture_rows()[0], host="WS1")
    assert ev["source"] == "tap"
    assert ev["kind"] == "alert"
    assert ev["severity"] == "high"
    assert ev["score"] == 0.8
    assert ev["action"] == "logged"
    assert ev["technique"] == "T1027"
    assert ev["alert_id"] == "tap:ps-base64-decode"
    assert ev["cmdline"].startswith("$d=")
    assert ev["pid"] == 6102


def test_normalize_defensive_defaults():
    row = {"ts": "2026-10-19T00:00:00Z", "provider": "dns", "event_id": 0,
           "rule": "weird", "severity": "banana", "technique": "not-a-tech",
           "props": {"QueryName": "x" * 400}}
    event = tap.normalize_match(row, host="WS1")
    assert event["event_id"] == 1          # 0 clamped up
    assert event["severity"] == "low"      # unknown severity falls back
    assert len(event["dns_query"]) <= 253  # contract length kept
    PlasmaEvent(**event)


def test_normalize_clips_oversized_scriptblock():
    row = dict(fixture_rows()[0],
               props={"ScriptBlockText": "A" * 9000})
    event = tap.normalize_match(row, host="WS1")
    assert len(event["cmdline"]) == 8192
    PlasmaEvent(**event)


# ---------------------------------------------------------------------------
# collection into the events store
# ---------------------------------------------------------------------------

def test_collect_dedupe(tmp_path):
    matches = tmp_path / "matches.jsonl"
    matches.write_text(FIXTURE.read_text())
    events = tmp_path / "plasma" / "events.jsonl"

    first = tap.collect(matches, events, host="WS1")
    assert first["written"] == 2 and first["already_present"] == 0
    second = tap.collect(matches, events, host="WS1")
    assert second["written"] == 0 and second["already_present"] == 2

    stored = [json.loads(ln) for ln in events.read_text().splitlines() if ln.strip()]
    assert len(stored) == 2
    assert all(PlasmaEvent(**row) for row in stored)


def test_collect_missing_file(tmp_path):
    assert "error" in tap.collect(tmp_path / "nope.jsonl", tmp_path / "e.jsonl")


def test_run_missing_exe_is_data(tmp_path):
    result = tap.run(tmp_path / "no-such-tap.exe", ["dns"], 5,
                     tmp_path / "m.jsonl", tmp_path / "r.txt")
    assert "error" in result


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------

def test_cli_tap_group_wiring():
    from plasma import cli
    p = cli.build_parser()
    p.parse_args(["tap", "list"])
    p.parse_args(["tap", "selftest"])
    p.parse_args(["tap", "run", "--providers", "powershell,dns", "--for", "5m"])
    p.parse_args(["tap", "collect", "--matches", "m.jsonl", "--events", "e.jsonl"])
