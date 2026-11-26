"""Behaviour profiles: bounded, deterministic, lake-less by construction."""
from __future__ import annotations

import json

from plasma import profile


def _rows(days=6, per_day=12, process="chrome.exe", parent="explorer.exe",
          user="CORP\\olu", **extra):
    rows = []
    for day in range(1, days + 1):
        for minute in range(per_day):
            row = {
                "ts": f"2026-11-{day:02d}T09:{minute:02d}:00Z",
                "host": "WS1", "kind": "process", "event_id": 1,
                "process": process, "parent": parent, "user": user,
            }
            row.update(extra)
            rows.append(row)
    return rows


def _write(tmp_path, rows, name="events.jsonl"):
    path = tmp_path / name
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    return path


def test_build_counts_images_edges_and_identity_pairs(tmp_path):
    rows = _rows() + _rows(days=1, per_day=1, process="mimikatz.exe",
                           parent="cmd.exe", user="CORP\\olu")
    built = profile.build(_write(tmp_path, rows))
    tables = built["tables"]
    assert tables["image"]["counts"]["chrome.exe"] == 72
    assert tables["parent_child"]["counts"]["explorer.exe>chrome.exe"] == 72
    assert tables["user_image"]["counts"]["corp\\olu>chrome.exe"] == 72
    assert built["n"] == 73
    assert built["host"] == "WS1"


def test_cmd_shape_removes_paths_urls_credentials_and_numbers():
    shaped = profile.cmd_shape(
        'net user bob Sup3rSecret! /add', "net.exe")
    assert "Sup3rSecret" not in shaped
    assert shaped == "net user bob <cred> /add"

    shaped = profile.cmd_shape(
        'prog --password=hunter2 --url https://x/y --n 42', "prog.exe")
    assert "hunter2" not in shaped
    assert "https://x/y" not in shaped
    assert "42" not in shaped
    assert "<cred>" in shaped and "<url>" in shaped and "<n>" in shaped

    assert profile.cmd_shape(
        "cmd /c copy C:\\Users\\olu\\a.txt C:\\Users\\Public\\b.txt",
        "cmd.exe") == "cmd /c copy <path> <path>"


def test_cmd_shape_is_stable_across_arguments():
    first = profile.cmd_shape("powershell -enc " + "QUJD" * 20)
    second = profile.cmd_shape("powershell -enc " + "REVG" * 20)
    assert first == second == "powershell -enc <b64>"


def test_registry_and_file_families_are_generic():
    assert profile.registry_family(
        "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil"
    ) == "currentversion\\run\\evil"
    assert profile.file_family(
        r"C:\Users\olu\Documents\report.ps1") == "documents.ps1"
    assert profile.file_family(r"C:\Windows\Temp\x.exe") == "windows\\temp.exe"


def test_rarity_is_one_for_unseen_and_zero_for_the_only_key(tmp_path):
    built = profile.build(_write(tmp_path, _rows()))
    seen = profile.rarity(built, "image", "chrome.exe")
    unseen = profile.rarity(built, "image", "never.exe")
    assert seen["value"] == 0.0 and seen["first_seen"] is False
    assert unseen["value"] == 1.0 and unseen["first_seen"] is True
    assert profile.rarity(built, "image", "") is None


def test_rarity_refuses_a_cold_profile(tmp_path):
    built = profile.build(_write(tmp_path, _rows(days=1, per_day=2)))
    assert built["n"] < profile.MIN_OBSERVATIONS
    assert profile.rarity(built, "image", "chrome.exe") is None


def test_profile_is_bounded_and_has_no_raw_paths_or_command_lines(tmp_path):
    rows = []
    for index in range(5000):
        rows.append({
            "ts": "2026-11-01T09:00:00Z", "host": "WS1", "kind": "process",
            "process": f"image{index}.exe", "parent": "explorer.exe",
            "user": "CORP\\olu", "event_id": 1,
            "cmdline": f"image{index}.exe --target C:\\Users\\olu\\secret{index}.txt",
        })
    built = profile.build(_write(tmp_path, rows))
    assert len(built["tables"]["image"]["counts"]) <= profile.TOP_K
    blob = json.dumps(built)
    assert "C:\\\\Users\\\\olu\\\\secret" not in blob
    assert len(blob) < 1_500_000


def test_verify_detects_tampering(tmp_path):
    path = tmp_path / "profile.json"
    built = profile.build(_write(tmp_path, _rows()))
    profile.save(path, built)
    loaded = profile.load(path)
    assert profile.verify(loaded)["ok"] is True
    loaded["tables"]["image"]["counts"]["chrome.exe"] += 1
    verdict = profile.verify(loaded)
    assert verdict["ok"] is False and "mismatch" in verdict["reason"]


def test_merge_sums_counts_and_marks_the_estate_profile(tmp_path):
    first = profile.build(_write(tmp_path, _rows(), "a.jsonl"), host="WS1")
    second = profile.build(_write(tmp_path, _rows(), "b.jsonl"), host="WS2")
    merged = profile.merge([first, second])
    assert merged["kind"] == "estate-profile"
    assert merged["hosts"] == ["WS1", "WS2"]
    assert merged["n"] == first["n"] + second["n"]
    assert merged["tables"]["image"]["counts"]["chrome.exe"] == first["n"] + second["n"]
    assert merged["hourly"] == {} and merged["merged"] is True
    assert profile.verify(merged)["ok"] is True


def test_diff_reports_new_edges_and_scores_them(tmp_path):
    base = profile.build(_write(tmp_path, _rows(), "base.jsonl"))
    extra = _rows(days=1, per_day=1, process="rundll32.exe",
                  parent="winword.exe")
    new = profile.build(_write(tmp_path, _rows() + extra, "new.jsonl"))
    result = profile.diff(base, new)
    added = {row["key"] for row in result["tables"]["parent_child"]["added"]}
    assert "winword.exe>rundll32.exe" in added
    assert result["score"] >= 1.5


def test_volume_uses_per_day_medians(tmp_path):
    built = profile.build(_write(tmp_path, _rows(days=6, per_day=12)))
    at_median = profile.volume(built, "image:chrome.exe", 9, 12)
    assert at_median is None or at_median["value"] == 0.0
    spike = profile.volume(built, "image:chrome.exe", 9, 200)
    assert spike is not None and spike["value"] > 0


def test_volume_refuses_a_thin_baseline(tmp_path):
    built = profile.build(_write(tmp_path, _rows(days=2, per_day=12)))
    assert profile.volume(built, "image:chrome.exe", 9, 12) is None


def test_summary_is_json_serialisable(tmp_path):
    built = profile.build(_write(tmp_path, _rows()))
    summary = profile.summary(built)
    json.dumps(summary)
    assert summary["tables"]["image"]["keys"] == 1
    assert summary["integrity"]["ok"] is True


def test_cli_build_and_score_round_trip(tmp_path, capsys):
    from plasma import cli

    events = _write(tmp_path, _rows())
    target = tmp_path / "profile.json"
    assert cli.main(["profile", "build", "--events", str(events),
                     "--out", str(target)]) == 0
    built = json.loads(capsys.readouterr().out)
    assert built["ok"] is True and target.exists()

    assert cli.main(["anomaly", "score", "--events", str(events),
                     "--profile", str(target), "--limit", "1"]) == 0
    scored = json.loads(capsys.readouterr().out)
    assert scored["ok"] is True and scored["profile_n"] == 72

    assert cli.main(["profile", "verify", "--profile", str(target)]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_merge_does_not_double_count_a_repeated_host(tmp_path):
    first = profile.build(_write(tmp_path, _rows(), "a.jsonl"), host="WS1")
    again = profile.build(_write(tmp_path, _rows(), "b.jsonl"), host="WS1")
    merged = profile.merge([first, again])
    assert merged["hosts"] == ["WS1"]
    assert merged["tables"]["image"]["counts"]["chrome.exe"] == first[
        "tables"]["image"]["counts"]["chrome.exe"]


def test_rarity_count_cap_resists_poisoning(tmp_path):
    crafted = {
        "kind": "host-profile", "host": "WS1", "n": 1000,
        "limits": {"min_observations": 10},
        "tables": {"image": {"counts": {"evil.exe": 500, "chrome.exe": 500},
                             "total": 1000}},
    }
    result = profile.rarity(crafted, "image", "evil.exe")
    # 500 fake runs cannot buy familiarity: the value stays on the novel
    # half of the scale (uncapped it would collapse to ~0.10).
    assert result["value"] >= 0.3


def test_quoted_command_shape_keeps_process_identity():
    sevenzip = profile.cmd_shape(
        '"C:\\Program Files\\7-Zip\\7z.exe" x a.zip -oC:\\out',
        image="7z.exe")
    evil = profile.cmd_shape(
        '"C:\\Users\\Public\\evil.exe" x b.zip -oC:\\out',
        image="evil.exe")
    assert sevenzip.startswith("7z.exe ")
    assert evil.startswith("evil.exe ")
    assert sevenzip != evil
