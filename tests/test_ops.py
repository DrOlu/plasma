"""Ops-layer tests: notify channels, health verdicts, update mechanics,
watch sweeps. All external effects (HTTP, services, ETW) are mocked."""

import json
from pathlib import Path

import pytest

from plasma import health, notify, update, watch


# ---------------------------------------------------------------------------
# notify
# ---------------------------------------------------------------------------

def test_notify_config_secrets_never_inline(tmp_path):
    bad = tmp_path / "notify.json"
    bad.write_text(json.dumps({"channels": [
        {"type": "telegram", "token": "SECRET", "chat_id": "1"}]}))
    with pytest.raises(ValueError, match="token_env"):
        notify.load_config(tmp_path)


def test_notify_config_ok(tmp_path):
    ok = tmp_path / "notify.json"
    ok.write_text(json.dumps({"channels": [
        {"type": "telegram", "token_env": "TG", "chat_id": "42"},
        {"type": "webhook", "url": "https://hooks.test/plasma"}], "min_score": 5}))
    cfg = notify.load_config(tmp_path)
    assert cfg["min_score"] == 5 and len(cfg["channels"]) == 2


def test_deliver_telegram_uses_env_and_payload(tmp_path, monkeypatch):
    monkeypatch.setenv("TG", "bot-token")
    sent = {}
    monkeypatch.setattr(notify, "_post",
                        lambda url, payload, timeout=15: sent.update(url=url, payload=payload) or {"ok": True, "status": 200})
    res = notify.deliver({"type": "telegram", "token_env": "TG", "chat_id": "42"},
                         "title", "body")
    assert res["ok"] and "bot-token" in sent["url"]
    assert sent["payload"]["text"].startswith("title")


def test_deliver_failure_is_data(monkeypatch):
    monkeypatch.setattr(notify, "_post", lambda *a, **k: (_ for _ in ()).throw(OSError("down")))
    res = notify.deliver({"type": "webhook", "url": "https://x"}, "t", "b")
    assert res["ok"] is False and "down" in res["error"]


def test_notify_all_without_config_sends_nothing(tmp_path):
    res = notify.notify_all(tmp_path, "t", "b")
    assert res["configured"] == 0 and res["sent"] == 0


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------

def test_health_tolerates_bom_config(tmp_path, monkeypatch):
    """PS 5.1 Set-Content -Encoding UTF8 writes a BOM; config must still parse."""
    (tmp_path / "config.json").write_bytes(
        b"\xef\xbb\xbf" + json.dumps({
            "events_path": str(tmp_path / "e.jsonl"), "degraded": True,
            "sensors": {"whids": {"status": "skipped"}}}).encode())
    v = health.verdict(tmp_path)
    assert all(c["check"] != "config" or c["ok"] for c in v["checks"])


def test_health_down_when_whids_expected_but_stopped(tmp_path, monkeypatch):
    (tmp_path / "config.json").write_text(json.dumps({
        "events_path": str(tmp_path / "e.jsonl"), "degraded": False,
        "sensors": {"whids": {"status": "active"}}}))
    monkeypatch.setattr(health, "IS_WINDOWS", True)
    monkeypatch.setattr(health, "_ps", lambda s, timeout=60: "Stopped")
    monkeypatch.setattr("plasma.cli._locate_tap_exe", lambda: Path("tap"))
    v = health.verdict(tmp_path)
    assert v["status"] == "down"
    assert "whids_service" in v["failed"]


def test_health_ok_when_minimal_mode(tmp_path, monkeypatch):
    (tmp_path / "config.json").write_text(json.dumps({
        "events_path": str(tmp_path / "e.jsonl"), "degraded": True,
        "sensors": {"whids": {"status": "skipped"}}}))
    monkeypatch.setattr(health, "_ps", lambda s, timeout=60: "")
    monkeypatch.setattr("plasma.cli._locate_tap_exe", lambda: None)
    v = health.verdict(tmp_path)
    assert v["status"] == "ok"  # minimal mode: missing WHIDS is expected


def test_health_degraded_on_sensor_gap(tmp_path, monkeypatch):
    (tmp_path / "config.json").write_text(json.dumps({
        "events_path": str(tmp_path / "e.jsonl"), "degraded": False,
        "sensors": {"whids": {"status": "active"}}}))
    states = {"Whids": "Running"}
    monkeypatch.setattr(health, "_ps",
                        lambda s, timeout=60: next((v for k, v in states.items() if k in s), ""))

    def _age(channel):
        return 5.0 if "Sysmon" in channel else None
    monkeypatch.setattr(health, "_newest_event_age_minutes", _age)
    monkeypatch.setattr("plasma.cli._locate_tap_exe", lambda: Path("tap"))
    v = health.verdict(tmp_path)
    assert v["status"] == "ok"


# ---------------------------------------------------------------------------
# update
# ---------------------------------------------------------------------------

def test_version_compare():
    assert update.is_newer("0.9.2", "v0.10.0")
    assert update.is_newer("0.9.2", "0.11.0")
    assert not update.is_newer("0.10.0", "v0.10.0")
    assert not update.is_newer("0.11.0", "0.9.2")


def test_download_and_verify(monkeypatch, tmp_path):
    payload = b"MZ fake exe"
    good_sha = __import__("hashlib").sha256(payload).hexdigest()
    def fake_gh(url, token, timeout=60, accept="json"):
        if "/releases/latest" in url:
            return json.dumps({"tag_name": "v0.11.0", "assets": [
                {"name": "plasma-0.11.0.exe", "url": "https://x/plasma.exe"},
                {"name": "SHA256SUMS", "url": "https://x/sums"}]}).encode()
        return payload if url.endswith("plasma.exe") else f"{good_sha}  plasma-0.11.0.exe".encode()
    monkeypatch.setattr(update, "_gh", fake_gh)
    res = update.download_and_verify("r/p", "v0.11.0", "tok", tmp_path / "staged.exe")
    assert res["ok"] and res["sha256"] == good_sha
    assert Path(res["staged"]).read_bytes() == payload


def test_download_rejects_bad_hash(monkeypatch, tmp_path):
    def fake_gh(url, token, timeout=60, accept="json"):
        if "/releases/latest" in url:
            return json.dumps({"tag_name": "v0.11.0", "assets": [
                {"name": "plasma.exe", "url": "https://x/plasma.exe"},
                {"name": "SHA256SUMS", "url": "https://x/sums"}]}).encode()
        return b"tampered" if url.endswith("plasma.exe") else f"{'0'*64}  plasma.exe".encode()
    monkeypatch.setattr(update, "_gh", fake_gh)
    res = update.download_and_verify("r/p", "v", "tok", tmp_path / "s.exe")
    assert not res["ok"] and res["error"] == "sha256 mismatch"


def test_rotate_bin_renames_running(tmp_path):
    bin_exe = tmp_path / "bin" / "plasma.exe"
    bin_exe.parent.mkdir(parents=True)
    bin_exe.write_bytes(b"old-running")
    staged = tmp_path / "staged.exe"
    staged.write_bytes(b"new")
    res = update.rotate_bin(staged, bin_exe)
    assert res["ok"]
    assert bin_exe.read_bytes() == b"new"
    assert Path(res["previous"]).read_bytes() == b"old-running"


# ---------------------------------------------------------------------------
# watch sweep
# ---------------------------------------------------------------------------

def test_watch_sweep_notifies_on_health_down(tmp_path, monkeypatch):
    (tmp_path / "config.json").write_text(json.dumps({
        "events_path": str(tmp_path / "e.jsonl"),
        "degraded": False, "sensors": {"whids": {"status": "active"}}}))
    monkeypatch.setattr(health, "verdict",
                        lambda r: {"status": "down", "failed": ["whids_service"], "checks": []})
    monkeypatch.setattr(watch.observatory, "run_question",
                        lambda q, **k: {"error": "no powershell"})
    sent = {}
    monkeypatch.setattr(notify, "notify_all",
                        lambda root, title, body, score=None, min_score=None: sent.update(title=title) or {"sent": 1})
    monkeypatch.setattr(watch, "Path", Path)  # keep real paths
    res = watch.watch_once(tmp_path)
    assert res["verdict"] == "act now" and res["top_score"] == 10
    assert "act now" in sent["title"]


def test_watch_sweep_clean_without_channels(tmp_path, monkeypatch):
    monkeypatch.setattr(health, "verdict",
                        lambda r: {"status": "ok", "failed": [], "checks": []})
    monkeypatch.setattr(watch.observatory, "run_question",
                        lambda q, **k: {"question": q, "blind_count": 0})
    monkeypatch.setattr("plasma.drift.load", lambda root, name: None)
    monkeypatch.setattr(notify, "notify_all",
                        lambda root, title, body, score=None, min_score=None: {"sent": 0})
    res = watch.watch_once(tmp_path)
    assert res["verdict"] == "clean" and res["notify"] is None  # quiet when clean
