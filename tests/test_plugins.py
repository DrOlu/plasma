"""Plugin API, registry, supervisor and signature tests."""
from __future__ import annotations

import json
import textwrap
import time
from pathlib import Path

import pytest

from plasma import plugin_api, plugin_host, plugins

REPO = Path(__file__).resolve().parent.parent
SAMPLES = REPO / "examples" / "plugins"


def _sample(tmp_path, name, kind):
    target = tmp_path / "src" / name
    plugins.scaffold(target.parent, name, kind)
    return target


def _install(root, source, **kwargs):
    return plugins.install(root, source, allow_unsigned=True, **kwargs)


def _write_events(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))


def _read_events(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line]


# ---------------------------------------------------------------------------
# manifest and envelope
# ---------------------------------------------------------------------------

def test_manifest_accepts_the_shipped_samples():
    for kind, name in (("sensor", "sample-sensor"),
                       ("detector", "sample-detector"),
                       ("responder", "sample-responder")):
        manifest = plugin_api.load_manifest(SAMPLES / name)
        assert manifest["kind"] == kind
        assert plugin_api.validate_manifest(manifest, SAMPLES / name) == []


def test_manifest_rejects_bad_names_versions_and_escape(tmp_path):
    base = tmp_path / "p"
    base.mkdir()
    (base / "x.py").write_text("")
    bad = {
        "api_version": "1.0", "name": "Bad Name", "version": "1",
        "kind": "sensor", "entrypoint": "../x.py",
        "runtime": "python", "protocol": "ndjson-stdio",
    }
    errors = plugin_api.validate_manifest(bad, base)
    assert any("name" in error for error in errors)
    assert any("version" in error for error in errors)
    assert any("inside the plugin" in error for error in errors)


def test_manifest_caps_line_size(tmp_path):
    base = tmp_path / "p"
    base.mkdir()
    (base / "x.py").write_text("")
    manifest = {
        "api_version": "1.0", "name": "ok", "version": "1.0.0",
        "kind": "sensor", "entrypoint": "x.py", "runtime": "python",
        "protocol": "ndjson-stdio",
        "limits": {"max_line_bytes": 1 << 20},
    }
    assert any("max_line_bytes" in error for error in
               plugin_api.validate_manifest(manifest, base))


@pytest.mark.parametrize("line", [
    "not json",
    json.dumps({"v": 2, "type": "event"}),
    json.dumps({"v": 1, "type": "bogus"}),
    json.dumps({"v": 1, "type": "event", "plugin": "other"}),
])
def test_parse_line_rejects_bad_envelopes(line):
    with pytest.raises(plugin_api.PluginError):
        plugin_api.parse_line(line, "sample")


def test_normalize_event_maps_known_fields_and_bounds_attributes():
    event = plugin_api.normalize_event({
        "v": 1, "type": "event",
        "event": {
            "ts": "2026-11-22T10:00:00Z", "kind": "process",
            "process": "cmd.exe", "parent": "explorer.exe",
            "pid": "123", "score": 0.4, "cmdline": "cmd /c whoami",
            "custom": "x" * 2000,
        }
    }, "sample", "1.2.3")
    assert event["source"] == "plugin:sample"
    assert event["plugin"] == "sample@1.2.3"
    assert event["pid"] == 123 and event["score"] == 0.4
    assert len(event["attributes"]["custom"]) == 512


@pytest.mark.parametrize("event", [
    {"score": 2.0, "process": "x.exe"},
    {"technique": "nope", "process": "x.exe"},
    {"kind": "nonsense", "process": "x.exe"},
    {"kind": "process"},
])
def test_normalize_event_rejects_bad_records(event):
    with pytest.raises(plugin_api.PluginError):
        plugin_api.normalize_event({"v": 1, "type": "event", "event": event},
                                   "sample")


def test_normalize_finding_caps_score_and_evidence():
    finding = plugin_api.normalize_finding({
        "v": 1, "type": "finding",
        "finding": {"description": "hit", "score": 0.9,
                    "technique": "T1059.001",
                    "evidence": [str(index) for index in range(50)]},
    }, "det", "0.1.0")
    assert finding["kind"] == "alert"
    assert finding["alert_id"] == "plugin:det"
    assert len(finding["evidence"]) == plugin_api.MAX_EVIDENCE
    with pytest.raises(plugin_api.PluginError):
        plugin_api.normalize_finding(
            {"v": 1, "type": "finding",
             "finding": {"description": "x", "score": 1.5}}, "det")


# ---------------------------------------------------------------------------
# signatures
# ---------------------------------------------------------------------------

def test_sign_and_verify_round_trip_and_tamper(tmp_path):
    plugin = _sample(tmp_path, "signed-sensor", "sensor")
    keys = plugin_api.keygen(tmp_path / "keys")
    plugin_api.sign(plugin, keys["private_key"])
    verdict = plugin_api.verify_signature(plugin, trust_key=keys["public_key"])
    assert verdict["ok"] is True and verdict["signed"] is True
    assert verdict["fingerprint"] == keys["fingerprint"]

    (plugin / "extra.txt").write_text("tampered")
    assert plugin_api.verify_signature(plugin)["ok"] is False
    assert "digest mismatch" in plugin_api.verify_signature(plugin)["reason"]


def test_signature_refuses_a_different_trust_key(tmp_path):
    plugin = _sample(tmp_path, "signed-sensor", "sensor")
    keys = plugin_api.keygen(tmp_path / "keys")
    other = plugin_api.keygen(tmp_path / "other")
    plugin_api.sign(plugin, keys["private_key"])
    verdict = plugin_api.verify_signature(plugin, trust_key=other["public_key"])
    assert verdict["ok"] is False
    assert "not trusted" in verdict["reason"]


def test_install_refuses_unsigned_unless_allowed(tmp_path):
    plugin = _sample(tmp_path, "unsigned-sensor", "sensor")
    root = tmp_path / "root"
    with pytest.raises(plugin_api.PluginError):
        plugins.install(root, plugin)
    result = plugins.install(root, plugin, allow_unsigned=True)
    assert result["ok"] is True and result["signed"] is False


# ---------------------------------------------------------------------------
# registry lifecycle
# ---------------------------------------------------------------------------

def test_install_enable_disable_and_uninstall(tmp_path):
    plugin = _sample(tmp_path, "life-sensor", "sensor")
    root = tmp_path / "root"
    installed = _install(root, plugin)
    assert installed["ok"] is True and installed["enabled"] is False
    listed = plugins.list_plugins(root)
    assert [row["name"] for row in listed["plugins"]] == ["life-sensor"]
    assert plugins.set_enabled(root, "life-sensor", True)["enabled"] is True
    assert plugins.get(root, "life-sensor")["enabled"] is True
    assert plugins.set_enabled(root, "life-sensor", False)["enabled"] is False
    assert plugins.uninstall(root, "life-sensor")["ok"] is True
    assert plugins.list_plugins(root)["plugins"] == []
    with pytest.raises(plugin_api.PluginError):
        plugins.get(root, "life-sensor")


def test_install_force_replaces_and_detects_tamper(tmp_path):
    plugin = _sample(tmp_path, "force-sensor", "sensor")
    root = tmp_path / "root"
    _install(root, plugin)
    installed_path = root / "plugins" / "force-sensor" / "sensor.py"
    installed_path.write_text("tampered")
    assert plugins.verify(root, "force-sensor")["integrity"] is False
    assert plugins.install(root, plugin, allow_unsigned=True,
                           force=True)["ok"] is True
    assert plugins.verify(root, "force-sensor")["integrity"] is True


# ---------------------------------------------------------------------------
# sensor host
# ---------------------------------------------------------------------------

def test_sensor_run_writes_events_and_honours_the_cap(tmp_path):
    plugin = _sample(tmp_path, "run-sensor", "sensor")
    root = tmp_path / "root"
    _install(root, plugin, enable=True)
    out = tmp_path / "data" / "events.jsonl"
    result = plugin_host.run_sensor(root, "run-sensor", out_events=out,
                                    max_events=3, timeout_seconds=20)
    assert result["ok"] is True
    assert result["written"] == 3
    rows = _read_events(out)
    assert len(rows) == 3
    assert all(row["source"] == "plugin:run-sensor" for row in rows)
    assert plugins.get(root, "run-sensor")["status"] == "ok"


def test_sensor_dedupe_and_disabled_refusal(tmp_path):
    plugin = _sample(tmp_path, "dedupe-sensor", "sensor")
    root = tmp_path / "root"
    _install(root, plugin)
    out = tmp_path / "events.jsonl"
    with pytest.raises(plugin_api.PluginError):
        plugin_host.run_sensor(root, "dedupe-sensor", out_events=out)
    row = {"ts": "2026-11-22T10:00:00Z", "host": "WS1",
           "source": "plugin:dedupe-sensor", "kind": "process",
           "process": "x.exe", "event_id": 1, "score": 0.1}
    first = plugin_host.append_events(out, [row])
    second = plugin_host.append_events(out, [row])
    assert first["written"] == 1 and second["written"] == 0


def test_sensor_quarantines_garbage_without_crashing(tmp_path):
    plugin = _sample(tmp_path, "bad-sensor", "sensor")
    (plugin / "sensor.py").write_text(textwrap.dedent("""
        import sys, time
        for _ in range(20):
            sys.stdout.write("this is not json\\n")
            sys.stdout.flush()
        time.sleep(0.2)
    """))
    root = tmp_path / "root"
    _install(root, plugin, enable=True)
    result = plugin_host.run_sensor(root, "bad-sensor",
                                    out_events=tmp_path / "events.jsonl",
                                    timeout_seconds=10)
    assert result["ok"] is False
    assert result["status"] == "quarantined"
    assert result["rejected"] >= 10
    assert result["written"] == 0


def test_sensor_timeout_is_bounded(tmp_path):
    plugin = _sample(tmp_path, "slow-sensor", "sensor")
    manifest = json.loads((plugin / "plugin.json").read_text())
    manifest["limits"]["timeout_seconds"] = 1
    (plugin / "plugin.json").write_text(json.dumps(manifest))
    (plugin / "sensor.py").write_text("import time\ntime.sleep(10)\n")
    root = tmp_path / "root"
    _install(root, plugin, enable=True)
    started = time.time()
    result = plugin_host.run_sensor(root, "slow-sensor",
                                    out_events=tmp_path / "events.jsonl",
                                    timeout_seconds=1)
    assert result["timed_out"] is True
    assert time.time() - started < 8


# ---------------------------------------------------------------------------
# detector host
# ---------------------------------------------------------------------------

def test_detector_turns_findings_into_alerts(tmp_path):
    plugin = _sample(tmp_path, "run-detector", "detector")
    root = tmp_path / "root"
    _install(root, plugin, enable=True)
    out = tmp_path / "events.jsonl"
    _write_events(out, [
        {"ts": "2026-11-22T10:00:00Z", "host": "WS1", "kind": "process",
         "process": "mimikatz.exe", "event_id": 1, "score": 0.1},
        {"ts": "2026-11-22T10:01:00Z", "host": "WS1", "kind": "process",
         "process": "notepad.exe", "event_id": 1, "score": 0.1},
    ])
    result = plugin_host.run_detector(root, "run-detector", out_events=out)
    assert result["ok"] is True and result["written"] == 1
    alerts = [row for row in _read_events(out) if row.get("alert_id")]
    assert alerts and alerts[0]["alert_id"] == "plugin:run-detector"
    assert alerts[0]["technique"] == "T1059"


def test_detector_timeout_returns_data_not_an_exception(tmp_path):
    plugin = _sample(tmp_path, "slow-detector", "detector")
    (plugin / "detector.py").write_text("import time\ntime.sleep(10)\n")
    root = tmp_path / "root"
    _install(root, plugin, enable=True)
    out = tmp_path / "events.jsonl"
    _write_events(out, [{"ts": "2026-11-22T10:00:00Z", "kind": "process",
                         "process": "x.exe"}])
    result = plugin_host.run_detector(root, "slow-detector", out_events=out,
                                      timeout_seconds=1)
    assert result["ok"] is False and result["status"] == "timeout"
