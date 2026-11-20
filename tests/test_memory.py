"""Memory scanner integration: argv, parsing, events and dedupe."""
from __future__ import annotations

import json
import subprocess

from plasma import memory


def _report(pid=684, main=r"C:\Windows\notepad.exe", scan=None):
    return {
        "scan_report": {
            "pid": pid,
            "is_64_bit": 1,
            "is_managed": 0,
            "main_image_path": main,
            "scanned": {"total": 10, "skipped": 0,
                        "modified": {"total": 1, "patched": 0, "replaced": 1},
                        "errors": 0},
            "scans": [scan or {
                "headers_scan": {
                    "module": "7ff6bc950000",
                    "module_file": main,
                    "status": 1,
                    "is_pe_replaced": 1,
                }
            }],
        }
    }


def test_build_argv_default_is_bounded_and_no_dump():
    argv = memory.build_argv(
        r"C:\tools\hollows_hunter64.exe", pids=[123, 456], deep=False)
    assert argv[0].endswith("hollows_hunter64.exe")
    assert argv[1:3] == ["/pid", "123,456"]
    assert "/shellc" in argv and "/json" in argv
    assert argv[argv.index("/shellc") + 1] == "1"
    assert argv[-2:] == ["/ofilter", "2"]
    assert "/dmode" not in argv


def test_build_argv_deep_and_dump():
    argv = memory.build_argv(
        "hh.exe", pnames=["powershell.exe"], deep=True, dump=True)
    assert argv[1:3] == ["/pname", "powershell.exe"]
    assert "/threads" in argv
    assert "/dmode" in argv and "/ofilter" not in argv


def test_parse_clean_summary():
    stdout = ('HollowsHunter v.0.4.1.1 (x64)\n'
              '{\n "scanned_count" : 1,\n "suspicious_count" : 0\n}\n')
    out = memory.parse_scan(stdout)
    assert out["payload"]["suspicious_count"] == 0
    assert out["findings"] == []


def test_parse_hollowing_to_memory_event():
    out = memory.parse_scan(json.dumps(_report()))
    assert out["suspicious_count"] == 0  # summary has no suspicious_count
    assert len(out["findings"]) == 1
    event = out["findings"][0]
    assert event["source"] == "memory"
    assert event["kind"] == "alert"
    assert event["technique"] == "T1055.012"
    assert event["pid"] == 684
    assert event["process"] == "notepad.exe"
    assert event["score"] >= 0.9


def test_summary_suspicious_is_normalized():
    payload = {"suspicious_count": 1, "suspicious": [{
        "pid": 684, "name": "notepad.exe", "is_managed": 0,
        "replaced": 1, "implanted_pe": 0, "hdr_modified": 0,
        "implanted_shc": 0, "unreachable_file": 0, "other": 0,
    }]}
    out = memory.parse_scan(json.dumps(payload))
    assert out["findings"][0]["technique"] == "T1055.012"
    assert out["findings"][0]["pid"] == 684


def test_managed_jit_shellcode_is_suppressed():
    payload = {"suspicious_count": 1, "suspicious": [{
        "pid": 4916, "name": "powershell.exe", "is_managed": 1,
        "replaced": 0, "implanted_pe": 0, "hdr_modified": 0,
        "implanted_shc": 2, "unreachable_file": 0, "other": 0,
    }]}
    out = memory.parse_scan(json.dumps(payload))
    assert out["findings"] == []
    assert out["suppressed_count"] == 1


def test_parse_shellcode_and_iat():
    report = _report(scan={"workingset_scan": {
        "module": "7ff6bc950000", "status": 1,
        "has_pe": 0, "has_shellcode": 1, "mapping_type": "MEM_PRIVATE",
    }})
    out = memory.parse_scan(json.dumps(report))
    assert out["findings"][0]["technique"] == "T1055"
    assert "shellcode" in out["findings"][0]["alert_id"]


def test_scan_writes_events_once(tmp_path, monkeypatch):
    root = tmp_path / "plasma"
    root.mkdir()
    tool = tmp_path / "hh.exe"
    tool.write_bytes(b"stub")
    monkeypatch.setattr(memory, "resolve_tool",
                        lambda *a, **k: {"path": str(tool),
                                         "sha256": "x", "source": "test"})
    stdout = json.dumps(_report())
    monkeypatch.setattr(memory.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(
                            a[0], 0, stdout, ""))
    first = memory.scan(root, pids=[684], events_path=root / "events.jsonl")
    assert first["ok"] is True
    assert first["events_written"] == 1
    assert first["findings"][0]["source"] == "memory"
    rows = [json.loads(line) for line in
            (root / "events.jsonl").read_text().splitlines()]
    assert rows[-1]["source"] == "memory"
    second = memory.scan(root, pids=[684], events_path=root / "events.jsonl")
    assert second["events_written"] == 0


def test_scan_requires_target(tmp_path):
    result = memory.scan(tmp_path)
    assert result["code"] == "NO_TARGET"


def test_dump_with_all_is_refused(tmp_path):
    result = memory.scan(tmp_path, all_processes=True, dump=True)
    assert result["code"] == "REFUSED"


def test_unpinned_scanner_is_refused(tmp_path, monkeypatch):
    fake = tmp_path / "hollows.exe"
    fake.write_bytes(b"not the pinned binary")
    monkeypatch.setenv("PLASMA_HOLLOWS_HUNTER", str(fake))
    result = memory.resolve_tool(tmp_path, "64")
    assert "hash mismatch" in result["error"]


def test_status_and_list(tmp_path, monkeypatch):
    root = tmp_path / "plasma"
    root.mkdir()
    monkeypatch.setattr(memory, "resolve_tool",
                        lambda *a, **k: {"path": "hh.exe", "sha256": "x"})
    result = memory.status(root)
    assert result["version"] == memory.TOOL_VERSION
    assert result["last_scan"] is None
    assert memory.list_scans(root)["count"] == 0
