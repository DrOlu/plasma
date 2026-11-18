"""Measured self-update: policy, window, ring, signature and apply path."""

import json
from datetime import datetime, timedelta, timezone

from plasma import autoupdate, cli, killswitch, rings


def _config(tmp_path, **over):
    block = dict(autoupdate.DEFAULT_UPDATE)
    block.update(over)
    (tmp_path / "config.json").write_text(json.dumps({"update": block}))
    return block


def _release(tag="v9.9.9", hours_old=48):
    published = datetime.now(timezone.utc) - timedelta(hours=hours_old)
    return {"tag": tag, "assets": {},
            "published_at": published.isoformat().replace("+00:00", "Z")}


def test_default_auto_is_on():
    assert autoupdate.DEFAULT_UPDATE["auto"] is True
    assert autoupdate.DEFAULT_UPDATE["ring"] == "broad"
    assert autoupdate.DEFAULT_UPDATE["canary_hold_hours"] == 24
    assert autoupdate.DEFAULT_UPDATE["allow_unsigned"] is False


def test_config_merges_operator_block(tmp_path):
    _config(tmp_path, auto=False, ring="canary", window_start_hour=1)
    cfg = autoupdate.config(tmp_path)
    assert cfg["auto"] is False
    assert cfg["ring"] == "canary"
    assert cfg["window_start_hour"] == 1
    assert cfg["every_hours"] == 24


def test_in_window():
    cfg = dict(autoupdate.DEFAULT_UPDATE)
    assert autoupdate.in_window(cfg, datetime(2026, 11, 18, 3, 0))
    assert not autoupdate.in_window(cfg, datetime(2026, 11, 18, 6, 0))
    cfg["window_start_hour"], cfg["window_end_hour"] = 22, 2
    assert autoupdate.in_window(cfg, datetime(2026, 11, 18, 23, 0))
    assert autoupdate.in_window(cfg, datetime(2026, 11, 18, 1, 0))
    assert not autoupdate.in_window(cfg, datetime(2026, 11, 18, 12, 0))


def test_canary_hold():
    cfg = dict(autoupdate.DEFAULT_UPDATE)
    assert autoupdate.canary_hold_ok(_release(hours_old=48), cfg)
    assert not autoupdate.canary_hold_ok(_release(hours_old=1), cfg)
    cfg["ring"] = "canary"
    assert autoupdate.canary_hold_ok(_release(hours_old=1), cfg)


def test_ring_ok_broad_default(tmp_path):
    assert autoupdate.ring_ok(tmp_path, "HOST1", "broad") is True
    assert autoupdate.ring_ok(tmp_path, "HOST1", "canary") is False
    rings.assign(tmp_path, "HOST1", "canary")
    assert autoupdate.ring_ok(tmp_path, "HOST1", "canary") is True
    assert autoupdate.ring_ok(tmp_path, "HOST1", "broad") is False


def test_auto_up_to_date(tmp_path, monkeypatch):
    _config(tmp_path, window_start_hour=0, window_end_hour=0)
    from plasma import __version__
    monkeypatch.setattr(autoupdate.updater, "latest_release",
                        lambda *a, **k: {"tag": "v" + __version__,
                                         "assets": {}, "published_at": None})
    result = autoupdate.auto(tmp_path, force=False)
    assert result["status"] == "up_to_date"
    assert (tmp_path / "update-state.json").exists()


def test_auto_check_only_available(tmp_path, monkeypatch):
    _config(tmp_path, window_start_hour=0, window_end_hour=0,
            canary_hold_hours=0)
    monkeypatch.setattr(autoupdate.updater, "latest_release",
                        lambda *a, **k: _release())
    result = autoupdate.auto(tmp_path, check_only=True)
    assert result["status"] == "update_available"
    assert result["update_available"] is True


def test_auto_skips_killswitch(tmp_path):
    _config(tmp_path, window_start_hour=0, window_end_hour=0)
    killswitch.set_global(tmp_path, True, "test")
    result = autoupdate.auto(tmp_path)
    assert result["status"] == "skipped"
    assert "kill switch" in result["reason"]


def test_auto_skips_outside_window(tmp_path):
    now = datetime.now()
    _config(tmp_path,
            window_start_hour=(now.hour + 2) % 24,
            window_end_hour=(now.hour + 4) % 24)
    result = autoupdate.auto(tmp_path)
    assert result["status"] == "skipped"
    assert "outside update window" in result["reason"]


def test_auto_skips_canary_hold(tmp_path, monkeypatch):
    _config(tmp_path, window_start_hour=0, window_end_hour=0,
            canary_hold_hours=24)
    monkeypatch.setattr(autoupdate.updater, "latest_release",
                        lambda *a, **k: _release(hours_old=1))
    result = autoupdate.auto(tmp_path)
    assert result["status"] == "skipped"
    assert "canary hold" in result["reason"]


def test_auto_skips_ring(tmp_path, monkeypatch):
    _config(tmp_path, window_start_hour=0, window_end_hour=0,
            canary_hold_hours=0, ring="broad")
    rings.assign(tmp_path, "OTHER", "canary")
    monkeypatch.setattr(autoupdate.socket, "gethostname", lambda: "HOST1")
    result = autoupdate.auto(tmp_path)
    assert result["status"] == "skipped"
    assert "not in ring" in result["reason"]


def test_auto_applies_signed_release(tmp_path, monkeypatch):
    _config(tmp_path, window_start_hour=0, window_end_hour=0,
            canary_hold_hours=0)
    monkeypatch.setattr(autoupdate.socket, "gethostname", lambda: "HOST1")
    monkeypatch.setattr(autoupdate.updater, "latest_release",
                        lambda *a, **k: _release())
    monkeypatch.setattr(autoupdate.updater, "download_and_verify",
                        lambda *a, **k: {"ok": True, "sha256": "abc",
                                         "tag": "v9.9.9", "staged": "x"})
    monkeypatch.setattr(autoupdate.updater, "verify_authenticode",
                        lambda *a, **k: {"ok": True, "signer": "PIN",
                                         "status": "Valid"})
    monkeypatch.setattr(autoupdate.updater, "rotate_bin",
                        lambda *a, **k: {"ok": True, "bin": str(a[1])})
    monkeypatch.setattr(autoupdate, "_restart_serve", lambda: {"ok": True})
    monkeypatch.setattr(autoupdate.notify, "notify_all",
                        lambda *a, **k: {"configured": 0, "sent": 0})

    class _Done:
        returncode = 0
        stdout = "installed"
        stderr = ""

    monkeypatch.setattr(autoupdate.subprocess, "run",
                        lambda *a, **k: _Done())
    result = autoupdate.auto(tmp_path, force=True)
    assert result["status"] == "updated"
    assert result["to"] == "v9.9.9"
    assert result["sha256"] == "abc"
    assert (tmp_path / "update-state.json").exists()
    assert (tmp_path / "update-journal.jsonl").exists()
    journal = [json.loads(line) for line in
               (tmp_path / "update-journal.jsonl").read_text().splitlines()]
    assert journal[-1]["status"] == "updated"


def test_auto_refuses_unsigned(tmp_path, monkeypatch):
    _config(tmp_path, window_start_hour=0, window_end_hour=0,
            canary_hold_hours=0, allow_unsigned=False)
    monkeypatch.setattr(autoupdate.socket, "gethostname", lambda: "HOST1")
    monkeypatch.setattr(autoupdate.updater, "latest_release",
                        lambda *a, **k: _release())
    monkeypatch.setattr(autoupdate.updater, "download_and_verify",
                        lambda *a, **k: {"ok": True, "sha256": "abc",
                                         "tag": "v9.9.9"})
    monkeypatch.setattr(autoupdate.updater, "verify_authenticode",
                        lambda *a, **k: {"ok": False, "error": "unsigned"})
    result = autoupdate.auto(tmp_path, force=True)
    assert result["status"] == "refused"
    assert "unsigned" in result["error"]


def test_cli_update_auto_parser():
    parser = cli.build_parser()
    args = parser.parse_args(["update", "auto", "--check-only"])
    assert args.check_only is True
    assert args.func is cli.cmd_update_auto
    args = parser.parse_args(["update", "auto", "--force"])
    assert args.force is True


def test_install_parser_has_no_autoupdate():
    parser = cli.build_parser()
    assert parser.parse_args(["install", "--dry-run"]).no_autoupdate is False
    assert parser.parse_args(
        ["install", "--dry-run", "--no-autoupdate"]).no_autoupdate is True
