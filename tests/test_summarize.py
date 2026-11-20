"""Bounded summary digests."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from plasma import summarize


def _write(tmp_path):
    now = datetime.now(timezone.utc)
    rows = [
        {"ts": (now - timedelta(minutes=30)).isoformat(), "host": "WS1",
         "kind": "process", "source": "sysmon", "process": "explorer.exe",
         "parent": "userinit.exe", "user": "CORP\\olu", "score": 0.1,
         "cmdline": "explorer.exe"},
        {"ts": (now - timedelta(minutes=20)).isoformat(), "host": "WS1",
         "kind": "process", "source": "sysmon", "process": "powershell.exe",
         "parent": "explorer.exe", "user": "CORP\\olu", "score": 0.8,
         "cmdline": "powershell.exe  -enc   SQBFAFgA"},
        {"ts": (now - timedelta(minutes=10)).isoformat(), "host": "WS2",
         "kind": "alert", "source": "memory", "process": "powershell.exe",
         "parent": "explorer.exe", "user": "CORP\\admin", "score": 0.95,
         "cmdline": "powershell.exe -enc SQBFAFgA"},
    ]
    path = tmp_path / "events.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return path


def test_process_counts_and_first_last(tmp_path):
    out = summarize.summarize(_write(tmp_path))
    top = {row["process"]: row for row in out["top_processes"]}
    assert top["powershell.exe"]["count"] == 2
    assert top["powershell.exe"]["first_seen"] < top["powershell.exe"]["last_seen"]
    assert top["powershell.exe"]["parents"] == ["explorer.exe"]
    assert set(top["powershell.exe"]["users"]) == {"CORP\\olu", "CORP\\admin"}


def test_parent_child_and_bands(tmp_path):
    out = summarize.summarize(_write(tmp_path))
    edges = {(r["parent"], r["process"]): r["count"]
             for r in out["parent_child"]}
    assert edges[("explorer.exe", "powershell.exe")] == 2
    bands = {r["band"]: r["count"] for r in out["score_bands"]}
    assert bands["critical"] == 1 and bands["high"] == 1


def test_rare_commands_are_normalized(tmp_path):
    out = summarize.summarize(_write(tmp_path), rare_max=2)
    rare = out["rare_command_lines"]
    encoded = [row for row in rare if "-enc" in row["cmdline"]]
    assert len(encoded) == 1
    assert encoded[0]["count"] == 2
    assert "  " not in encoded[0]["cmdline"]


def test_since_filters_rows(tmp_path):
    out = summarize.summarize(_write(tmp_path), since="15m")
    assert out["checked"] == 1
    assert out["counts"]["processes"] == 1


def test_limit_and_truncation_are_reported(tmp_path):
    out = summarize.summarize(_write(tmp_path), limit=1)
    assert len(out["top_processes"]) == 1
    assert out["truncated"] is True


def test_cli_bad_since_is_structured(tmp_path, capsys):
    from plasma import cli
    assert cli.main(["summarize", "--root", str(tmp_path),
                     "--since", "yesterday"]) == 1
    body = json.loads(capsys.readouterr().out)
    assert body["ok"] is False and body["code"] == "QUERY_ERROR"
