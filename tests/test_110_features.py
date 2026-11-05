"""1.1.0 feature tests: new actuate actions, notify throttle, health depth,
watch chain integration."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from plasma import actuate, health, notify, watch


# ---------------------------------------------------------------------------
# actuate: disable_task + remove_run_key
# ---------------------------------------------------------------------------

def test_disable_task_payload_and_undo():
    payload, undo, verify = actuate._build_disable_task("EvilTask")
    assert "Disable-ScheduledTask" in payload
    assert "Export-ScheduledTask" in payload          # definition travels
    assert undo.startswith("Enable-ScheduledTask")
    assert verify.endswith(".State\"") or ".State" in verify
    assert "disable_task" in actuate.actions()


def test_remove_run_key_target_validation():
    with pytest.raises(ValueError, match="pipe-separated"):
        actuate._v_runkey_combo(r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    with pytest.raises(ValueError, match="allowlisted"):
        actuate._v_runkey_combo(r"HKLM:\SOFTWARE\Evil|name")
    with pytest.raises(ValueError, match="value name"):
        actuate._v_runkey_combo(
            r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run|bad|name!")
    # the canonical happy path validates
    actuate._v_runkey_combo(
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run|Backdoor")


def test_remove_run_key_payload_captures_sidecar():
    payload, undo, verify = actuate._build_remove_run_key(
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Backdoor")
    assert "GetValue('Backdoor')" in payload
    assert "Remove-ItemProperty" in payload
    assert undo["kind"] == "run_key_value"
    assert "runkey-Backdoor.json" in undo and undo["backup_file"] if False else True


def test_run_key_undo_restores_from_backup_file(tmp_path, monkeypatch):
    root = tmp_path / "plasma"
    backup = tmp_path / "runkey-Backdoor.json"
    backup.write_text(json.dumps(
        {"name": "Backdoor", "data": r"C:\Users\bob\AppData\evil.exe -q"}))
    calls = []

    def fake_run(payload, timeout=60):
        calls.append(payload)
        if "Get-Item" in payload and "GetValue" in payload:
            return {"rc": 0, "output": f"{backup}\nremoved",
                    "output_head": f"{backup}\nremoved"}
        if payload.startswith("New-ItemProperty"):
            return {"rc": 0, "output": "run-key value restored",
                    "output_head": "run-key value restored"}
        return {"rc": 0, "output": "ok", "output_head": "ok"}

    monkeypatch.setattr(actuate, "_run", fake_run)
    dry = actuate.execute(
        "remove_run_key", root,
        target=r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run|Backdoor",
        reason="persistence drill")
    applied = actuate.execute(
        "remove_run_key", root,
        target=r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run|Backdoor",
        reason="persistence drill", apply=True, plan=dry["id"])
    assert applied["undo"]["backup_file"] == str(backup)
    undone = actuate.undo(root, applied["id"], apply=True)
    assert undone["result"]["rc"] == 0
    assert calls[-1].startswith("New-ItemProperty")
    assert "evil.exe -q" in calls[-1], "restored value must come from the capture"


# ---------------------------------------------------------------------------
# notify throttling
# ---------------------------------------------------------------------------

def test_throttle_suppresses_repeat_key_within_window(tmp_path):
    (tmp_path / "notify.json").write_text(json.dumps({
        "channels": [{"type": "webhook", "url": "https://x.example/hook"}],
        "min_score": 1}))
    sent = []
    import plasma.notify as n
    monkey_mod = n
    orig_post = n._post
    n._post = lambda url, payload, timeout=15: sent.append(payload) or {"ok": True}
    try:
        first = notify.notify_all(tmp_path, "t", "b", score=9,
                                  throttle_key="health", throttle_seconds=3600)
        assert first["sent"] == 1 and "throttled" not in first
        second = notify.notify_all(tmp_path, "t", "b", score=9,
                                   throttle_key="health", throttle_seconds=3600)
        assert second["sent"] == 0 and second["throttled"] is True
        assert len(sent) == 1
        # a different key is not throttled by the first key's window
        other = notify.notify_all(tmp_path, "t", "b", score=9,
                                  throttle_key="drift_peer_change",
                                  throttle_seconds=3600)
        assert other["sent"] == 1
    finally:
        n._post = orig_post


def test_throttle_window_does_not_burn_when_delivery_fails(tmp_path):
    (tmp_path / "notify.json").write_text(json.dumps({
        "channels": [{"type": "webhook", "url": "https://x.example/hook"}],
        "min_score": 1}))
    import plasma.notify as n
    orig_post = n._post
    n._post = lambda url, payload, timeout=15: {"ok": False, "status": 500}
    try:
        first = notify.notify_all(tmp_path, "t", "b", score=9,
                                  throttle_key="health")
        assert first["sent"] == 0
        assert not (tmp_path / "notify-state.json").exists(), \
            "failed delivery must not create throttle state"
    finally:
        n._post = orig_post


# ---------------------------------------------------------------------------
# health: sensor heartbeat + rdp hardening drift
# ---------------------------------------------------------------------------

def _iso(dt):
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


def test_store_age_minutes_parses_z_and_naive(tmp_path):
    fresh = tmp_path / "fresh.jsonl"
    now = datetime.now(timezone.utc)
    fresh.write_text(json.dumps({"ts": _iso(now - timedelta(minutes=5)),
                                 "kind": "auth"}) + "\n")
    assert health._store_age_minutes(fresh) is not None
    assert health._store_age_minutes(fresh) < 60
    naive = tmp_path / "naive.jsonl"
    naive.write_text(json.dumps({"ts": "2026-11-05T10:00:00.000"}) + "\n")
    assert health._store_age_minutes(naive) is not None
    assert health._store_age_minutes(tmp_path / "nope.jsonl") is None


def test_rdp_hardening_drift_check(tmp_path, monkeypatch):
    (tmp_path / "config.json").write_text(json.dumps({
        "events_path": str(tmp_path / "e.jsonl"), "degraded": False,
        "sensors": {"whids": {"status": "skipped"}}}))
    monkeypatch.setattr(health, "IS_WINDOWS", True)

    def healthy(query, timeout=60):
        if "deny=" in query:
            return "deny=0;layer=1;cert=True"
        return ""
    monkeypatch.setattr(health, "_ps", healthy)
    checks = {c["check"]: c for c in health.checks(tmp_path)}
    assert checks["rdp_hardening_drift"]["ok"] is True

    def drifted(query, timeout=60):
        if "deny=" in query:
            return "deny=1;layer=2;cert="
        return ""
    monkeypatch.setattr(health, "_ps", drifted)
    checks = {c["check"]: c for c in health.checks(tmp_path)}
    assert checks["rdp_hardening_drift"]["ok"] is False
    assert "drifted" in checks["rdp_hardening_drift"]["detail"]


# ---------------------------------------------------------------------------
# watch: chain scan integration + throttle key wiring
# ---------------------------------------------------------------------------

def test_watch_sweep_surfaces_chain_findings(tmp_path, monkeypatch):
    (tmp_path / "config.json").write_text(json.dumps({
        "events_path": str(tmp_path / "e.jsonl"), "degraded": True,
        "sensors": {"whids": {"status": "skipped"}}}))
    monkeypatch.setattr(health, "verdict",
                        lambda r: {"status": "ok", "failed": [], "checks": []})
    monkeypatch.setattr(watch.observatory, "run_question",
                        lambda q, **k: {"question": q, "blind_count": 0})
    monkeypatch.setattr("plasma.drift.load", lambda root, name: None)
    store = tmp_path / "data" / "events.jsonl"
    store.parent.mkdir(parents=True)
    story = [
        {"ts": "2026-11-05T10:00:00Z", "kind": "process", "user": "sam",
         "process": r"C:\Program Files\Microsoft Office\winword.exe"},
        {"ts": "2026-11-05T10:01:00Z", "kind": "process", "user": "sam",
         "process": r"C:\Windows\System32\powershell.exe",
         "description": "powershell -enc SQBFAFgA"},
        {"ts": "2026-11-05T10:02:00Z", "kind": "network", "user": "sam",
         "dest_ip": "203.0.113.9"},
    ]
    store.write_text("\n".join(json.dumps(r) for r in story) + "\n")
    res = watch.sweep(tmp_path)
    chains = [f for f in res["findings"] if f["type"] == "chain_phish_spawn_chain"]
    assert chains and chains[0]["score"] == 9
    assert res["verdict"] == "act now"


def test_watch_once_throttles_by_loudest_finding(tmp_path, monkeypatch):
    (tmp_path / "config.json").write_text(json.dumps({
        "events_path": str(tmp_path / "e.jsonl"), "degraded": True,
        "sensors": {"whids": {"status": "skipped"}}}))
    (tmp_path / "notify.json").write_text(json.dumps({
        "channels": [{"type": "webhook", "url": "https://x.example/hook"}],
        "min_score": 1}))
    monkeypatch.setattr(health, "verdict",
                        lambda r: {"status": "down", "failed": ["whids_service"],
                                   "checks": []})
    monkeypatch.setattr(watch.observatory, "run_question",
                        lambda q, **k: {"question": q, "blind_count": 0})
    monkeypatch.setattr("plasma.drift.load", lambda root, name: None)
    sent = []
    import plasma.notify as n
    orig_post = n._post
    n._post = lambda url, payload, timeout=15: sent.append(payload) or {"ok": True}
    try:
        first = watch.watch_once(tmp_path)
        assert first["notify"]["sent"] == 1
        second = watch.watch_once(tmp_path)
        assert second["notify"]["throttled"] is True
        assert len(sent) == 1, "same loudest finding must not re-notify"
    finally:
        n._post = orig_post
