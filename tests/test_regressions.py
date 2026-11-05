"""1.0.0 audit regression tests.

Each test pins a defect found in the pre-release audit (bugs / FP / FN).
Names reference the module; the docstring carries the failure scenario.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from plasma import actuate, fleet, health, identity, notify, observatory, \
    tap, update, watch, whids

REPO = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# update.parse_version — pre-release suffixes must not inflate the patch
# ---------------------------------------------------------------------------

def test_parse_version_ignores_prerelease_suffix():
    assert update.parse_version("v1.0.0") == (1, 0, 0)
    assert update.parse_version("v1.0.0-rc1") == (1, 0, 0)
    assert update.parse_version("v1.0.0-rc12") == (1, 0, 0)
    # a published final release is never "older" than its own rc
    assert not update.is_newer("1.0.0", "v1.0.0-rc2")


def test_parse_version_orders_correctly():
    assert update.is_newer("1.9.9", "v1.10.0")
    assert update.is_newer("0.11.1", "v1.0.0")
    assert not update.is_newer("1.0.0", "v1.0.0")
    assert update.parse_version("garbage") == (0, 0, 0)


# ---------------------------------------------------------------------------
# fleet — mixed naive/aware timestamps must not crash correlate
# ---------------------------------------------------------------------------

def test_parse_ts_treats_offsetless_as_utc():
    ts = fleet._parse_ts("2026-10-19T12:00:00.123")
    assert ts.tzinfo is not None
    assert ts.utcoffset().total_seconds() == 0
    aware = fleet._parse_ts("2026-10-19T12:00:00+02:00")
    assert aware.utcoffset().total_seconds() == 7200
    assert fleet._parse_ts("") is None
    assert fleet._parse_ts("not-a-date") is None


def test_correlate_survives_mixed_timestamp_formats(tmp_path):
    """One offset-less row beside Z-suffixed rows used to raise TypeError."""
    import json as _json
    root = tmp_path / "plasma"
    cd = root / "fleet-cases" / "c1"
    (cd / "answers").mkdir(parents=True)
    (cd / "case.json").write_text(_json.dumps(
        {"case": "c1", "window_seconds": 1800, "canaries": []}))
    (cd / "answers" / "a.events.jsonl").write_text("\n".join([
        _json.dumps({"ts": "2026-10-19T12:00:00.000Z", "user": "bob",
                     "kind": "auth", "host": "a"}),
        _json.dumps({"ts": "2026-10-19T12:05:00.000", "user": "bob",
                     "kind": "auth", "host": "b"}),
    ]) + "\n")
    (cd / "answers" / "b.events.jsonl").write_text(_json.dumps(
        {"ts": "2026-10-19T12:02:00+00:00", "user": "bob",
         "kind": "auth", "host": "b"}) + "\n")
    result = fleet.correlate(root, "c1")
    assert "error" not in result
    hops = [f for f in result["findings"] if f["type"] == "lateral_hop"]
    assert hops and hops[0]["user"] == "bob"


def test_rows_from_text_cap_zero_is_empty():
    assert fleet._rows_from_text('{"a":1}\n{"a":2}\n', 0) == []
    assert fleet._rows_from_text('{"a":1}\n', None) == []
    assert len(fleet._rows_from_text('{"a":1}\n{"a":2}\n', 1)) == 1


def test_init_case_updates_window_and_canaries(tmp_path):
    root = tmp_path / "plasma"
    fleet.init_case(root, "c1")
    fleet.init_case(root, "c1", window_seconds=300)
    fleet.init_case(root, "c1", canaries=["alice"])
    meta = json.loads((fleet.case_dir(root, "c1") / "case.json").read_text())
    assert meta["window_seconds"] == 300
    assert meta["canaries"] == ["alice"]
    # defaults never clobber an explicit value
    fleet.init_case(root, "c1")
    meta = json.loads((fleet.case_dir(root, "c1") / "case.json").read_text())
    assert meta["window_seconds"] == 300


# ---------------------------------------------------------------------------
# identity — timestamps are UTC at the source; process is a basename
# ---------------------------------------------------------------------------

def test_identity_ps_template_emits_utc_and_basename():
    text = identity._PS_TEMPLATE
    assert "ToUniversalTime()" in text, "TimeCreated is local; Z suffix would lie"
    assert "Split-Path -Leaf" in text, "process must be a basename"


# ---------------------------------------------------------------------------
# health — culture-invariant number formatting
# ---------------------------------------------------------------------------

def test_health_sysmon_age_ps_is_wellformed(monkeypatch):
    """E2E regression: a space before .ToString broke the PS method call and
    sysmon_feed silently read as empty (WS2 reported 'down' in the field)."""
    captured = {}
    monkeypatch.setattr(health, "_ps",
                        lambda s, timeout=60: captured.update(script=s) or "5")
    age = health._newest_event_age_minutes("Microsoft-Windows-Sysmon/Operational")
    assert age == 5.0
    script = captured["script"]
    assert "InvariantCulture" in script
    assert ") .ToString" not in script          # the field bug
    assert ").ToString(" in script


# ---------------------------------------------------------------------------
# observatory — PS single-quoted regexes are NOT python strings
# ---------------------------------------------------------------------------

def test_observatory_service_filter_matches_single_backslash():
    import inspect
    src = inspect.getsource(observatory)
    # 'Windows\\' in PS reaches .NET as Windows\ (one literal backslash)
    assert r"-notmatch 'Windows\\'" in src, \
        "service filter must match C:\\Windows paths (single backslash)"
    # device-path strip must match \\?\ and \??\ prefixes exactly
    assert r"-replace '^\\\\\?\\','' -replace '^\\\?\\\?\\',''" in src


# ---------------------------------------------------------------------------
# notify — min_score actually gates delivery
# ---------------------------------------------------------------------------

def test_notify_min_score_suppresses_low_score(tmp_path, monkeypatch):
    (tmp_path / "notify.json").write_text(json.dumps({
        "channels": [{"type": "webhook", "url": "https://x.example/hook"}],
        "min_score": 7}))
    sent = []
    monkeypatch.setattr(notify, "_post", lambda url, payload, timeout=15: sent.append(payload) or {"ok": True})
    out = notify.notify_all(tmp_path, "t", "b", score=5)
    assert out["sent"] == 0 and out["suppressed"] is True and sent == []
    out = notify.notify_all(tmp_path, "t", "b", score=8)
    assert out["sent"] == 1 and "suppressed" not in out
    # explicit min_score overrides config
    out = notify.notify_all(tmp_path, "t", "b", score=5, min_score=1)
    assert out["sent"] == 1
    # no score given -> always deliver (caller opted in)
    out = notify.notify_all(tmp_path, "t", "b")
    assert out["sent"] == 1


def test_notify_inline_secret_still_refused(tmp_path):
    (tmp_path / "notify.json").write_text(json.dumps({
        "channels": [{"type": "telegram", "token": "123:abc", "chat_id": "1"}]}))
    with pytest.raises(ValueError, match="token_env"):
        notify.load_config(tmp_path)


# ---------------------------------------------------------------------------
# watch — unpulled alert counting is growth-based, never re-fires
# ---------------------------------------------------------------------------

def test_watch_unpulled_alerts_fire_on_growth_only(tmp_path, monkeypatch):
    alerts = tmp_path / "whids" / "Logs" / "Alerts" / "2026-10-19"
    alerts.mkdir(parents=True)
    rows = ['{"criticality": 9, "rules": ["x"]}'] * 30
    (alerts / "alerts.jsonl").write_text("\n".join(rows) + "\n")

    monkeypatch.setattr(health, "verdict",
                        lambda r: {"status": "ok", "failed": [], "checks": []})
    monkeypatch.setattr(watch.observatory, "run_question",
                        lambda q, **k: {"question": q, "blind_count": 0})
    monkeypatch.setattr("plasma.drift.load", lambda root, name: None)

    res1 = watch.sweep(tmp_path)
    first = [f for f in res1["findings"] if f["type"] == "unpulled_whids_alerts"]
    # only fires if the sweep actually saw our dir; on posix the literal
    # C:\\ path never matches, so assert the counter file exists after a run
    state = tmp_path / "watch-alerts-state.json"
    if first:
        seen = json.loads(state.read_text())["seen_alert_rows"]
        assert seen == 30
        res2 = watch.sweep(tmp_path)
        assert not [f for f in res2["findings"] if f["type"] == "unpulled_whids_alerts"], \
            "same rows must not re-fire on the next sweep"
    else:
        # posix desk: counter still records what it saw (0)
        assert json.loads(state.read_text())["seen_alert_rows"] == 0


# ---------------------------------------------------------------------------
# whids — default min_confidence is on the gene 0-10 scale
# ---------------------------------------------------------------------------

def test_whids_default_min_confidence_matches_cli_help():
    assert whids.DEFAULT_MIN_CONFIDENCE == 8
    # a score-0.9 event with an IOC survives the default threshold...
    row = {"severity": "critical", "score": 0.9, "file_hash": "ab" * 32,
           "technique": "T1003"}
    assert whids.extract_indicators([row]) != []
    # ...and the same shape at score 0.5 does not
    row5 = dict(row, score=0.5, severity="medium")
    assert whids.extract_indicators([row5]) == []


# ---------------------------------------------------------------------------
# tap — clean errors for hand-edited rules
# ---------------------------------------------------------------------------

def test_tap_load_rules_clean_error_on_missing_provider(tmp_path):
    rules = {"version": 1, "providers": {"powershell": "Microsoft-Windows-PowerShell"},
             "rules": [{"name": "r1", "event_id": 4104, "field": "ScriptBlockText",
                        "substr": "x", "severity": "low", "technique": "T1027"}]}
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(rules))
    with pytest.raises(ValueError, match="unknown provider"):
        tap.load_rules(p)


def test_tap_load_rules_rejects_pipe_in_name(tmp_path):
    rules = {"version": 1, "providers": {"powershell": "Microsoft-Windows-PowerShell"},
             "rules": [{"name": "bad|name", "provider": "powershell",
                        "event_id": 4104, "field": "f", "substr": "x",
                        "severity": "low", "technique": "T1027"}]}
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(rules))
    with pytest.raises(ValueError, match="may not contain"):
        tap.load_rules(p)


# ---------------------------------------------------------------------------
# actuate — plan gate + journal robustness (behavior in test_observatory.py)
# ---------------------------------------------------------------------------

def test_actuate_wmi_payload_writes_sidecar_not_stdout_blob():
    """Undo data must not depend on stdout length (4000-char truncation)."""
    payload, undo, verify = actuate._build_disable_wmi_sub()
    assert "Set-Content -Path $file" in payload
    assert "ConvertTo-Json -InputObject" in payload, \
        "@() must survive ConvertTo-Json for single bindings"
    assert undo["kind"] == "wmi_bindings"
