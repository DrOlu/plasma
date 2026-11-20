# ruff: noqa: ISC004
"""Plasma memory: bounded, on-demand process-memory scanning.

HollowsHunter (PE-sieve) is a user-mode scanner for implants that file and
process telemetry cannot see: hollowed/replaced PEs, reflective DLLs,
shellcode, inline hooks and in-memory patches. Plasma binds it as an
explicit probe, not a standing service:

    plasma memory scan --pid 4832
    plasma memory scan --pname powershell.exe,rundll32.exe --deep
    plasma memory scan --all --timeout 120

The binary is pinned and hash-verified. No dumps are produced by default;
``--dump`` writes them only under the Plasma root and only when asked.
Findings are normalized into the Plasma event contract and deduplicated
across repeated scans.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

from . import agentstate, redact

TOOL_VERSION = "0.4.1.1"
TOOL_URL = ("https://github.com/hasherezade/hollows_hunter/releases/"
            f"download/v{TOOL_VERSION}/")
EXPECTED = {
    "64": "56a58a8bbf2cec9a5c7c68129e8863af6181fb51dfc25226f1a756aba66b4707",
    "32": "c37b611cf14144bd15c98f696a948616aa9630b79671adcc9ac115d8ec9ab49f",
}
NAMES = {"64": "hollows_hunter64.exe", "32": "hollows_hunter32.exe"}
DEFAULT_TIMEOUT = 300
STATE_FILE = "memory-state.json"
SCANS_DIR = "memory"
EVENT_ID = 9100


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _base_name(value) -> str:
    return str(value or "").replace("\\", "/").rsplit("/", 1)[-1][:260]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _candidate_dirs(root):
    root = Path(root) if root else agentstate.base(root)
    dirs = [
        root / "current" / "sensors" / "memory",
        root / "tools" / "memory",
    ]
    instances = root / "instances"
    if instances.is_dir():
        for path in sorted(instances.iterdir(), key=lambda p: p.stat().st_mtime,
                           reverse=True):
            dirs.append(path / "sensors" / "memory")
    here = Path(__file__).resolve().parent.parent
    dirs.append(here / "sensors" / "memory")
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        dirs.append(Path(meipass) / "embedded" / "sensors" / "memory")
    return dirs


def resolve_tool(root=None, which: str = "64") -> dict:
    """Find and hash-check the scanner. Never execute an unverified binary."""
    which = str(which or "64")
    if which not in NAMES:
        return {"error": "scanner must be 64 or 32"}
    env = os.environ.get("PLASMA_HOLLOWS_HUNTER")
    candidates = []
    if env and which == "64":
        candidates.append((Path(env), "env"))
    for directory in _candidate_dirs(root):
        for name in (NAMES[which], NAMES[which] + ".gz"):
            candidates.append((directory / name, str(directory)))
    root_path = Path(root) if root else agentstate.base(root)
    materialized = root_path / "tools" / "memory" / NAMES[which]
    for path, source in candidates:
        if not path.exists() or not path.is_file():
            continue
        try:
            if path.suffix == ".gz":
                materialized.parent.mkdir(parents=True, exist_ok=True)
                if not materialized.exists() or \
                        _sha256(materialized) != EXPECTED[which]:
                    tmp = materialized.with_suffix(".tmp")
                    with gzip.open(path, "rb") as src, tmp.open("wb") as dst:
                        shutil.copyfileobj(src, dst)
                    os.replace(tmp, materialized)
                candidate = materialized
            else:
                candidate = path
            digest = _sha256(candidate)
        except OSError:
            continue
        if digest != EXPECTED[which]:
            return {"error": "scanner hash mismatch", "path": str(candidate),
                    "expected": EXPECTED[which], "actual": digest}
        return {"path": str(candidate), "sha256": digest, "source": source,
                "version": TOOL_VERSION, "scanner": which}
    return {"error": f"HollowsHunter {which}-bit scanner not found",
            "hint": "install a bundle that includes sensors/memory, or set "
                    "PLASMA_HOLLOWS_HUNTER to the pinned binary",
            "expected": EXPECTED[which]}


def build_argv(tool: str, pids=None, pnames=None, dump=False,
               deep=False) -> list[str]:
    argv = [tool]
    if pids:
        values = [str(p).strip() for p in pids if str(p).strip()]
        if not values or any(not re.fullmatch(r"\d{1,10}", v) for v in values):
            raise ValueError("pids must be numeric")
        argv += ["/pid", ",".join(values)]
    elif pnames:
        values = [str(n).strip() for n in pnames if str(n).strip()]
        if not values or any(not re.fullmatch(
                r"[A-Za-z0-9._-]{1,120}", v) for v in values):
            raise ValueError("pnames must be plain process names")
        argv += ["/pname", ",".join(values)]
    # No target means all processes; the CLI requires --all explicitly.
    # HollowsHunter expects a numeric mode for /shellc and /ofilter.
    # 3 = shellcode patterns or stats; 2 = no files; U = unmapped dumps.
    if deep:
        argv += ["/shellc", "1", "/threads"]
    else:
        argv += ["/shellc", "1"]
    argv += ["/json"]
    if dump:
        # Dumps stay under the caller-provided output directory.
        argv += ["/dmode", "U"]
    else:
        # No files from the scanner: reports are captured from stdout and
        # archived by Plasma under its own bounded scan directory.
        argv += ["/ofilter", "2"]
    return argv


def _first_json(text: str):
    dec = json.JSONDecoder()
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            obj, _ = dec.raw_decode(text[index:])
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            continue
    return None


def _walk_reports(obj, out):
    if isinstance(obj, dict):
        if "pid" in obj and ("scans" in obj or "scanned" in obj):
            out.append(obj)
            return
        for value in obj.values():
            _walk_reports(value, out)
    elif isinstance(obj, list):
        for value in obj:
            _walk_reports(value, out)


def _finding(kind: str, technique: str | None, report: dict, data: dict,
             module: str | None, score: float) -> dict:
    pid = report.get("pid")
    main = report.get("main_image_path")
    process = _base_name(main) or None
    module_file = data.get("module_file") or module or main
    base = _base_name(module_file) or "module"
    alert = f"memory:{kind}:{pid}:{base}"[:64]
    desc = f"HollowsHunter {kind}: {base}"
    if module:
        desc += f" at {module}"
    return {
        "ts": _now(), "host": socket.gethostname() or "localhost",
        "source": "memory", "kind": "alert", "event_id": EVENT_ID,
        "severity": "critical" if score >= 0.9 else "high",
        "score": score, "action": "logged", "technique": technique,
        "alert_id": alert, "process": process, "pid": pid,
        "file_path": module_file, "description": desc[:2048],
    }


def findings_from_summary(payload) -> list[dict]:
    """Handle HollowsHunter's summary-only suspicious list.

    Managed .NET processes commonly produce ``implanted_shc`` under the
    stats-based shellcode scan. They are recorded as a low-confidence
    observation, not a high-severity memory-injection alert.
    """
    if not isinstance(payload, dict):
        return []
    items = payload.get("suspicious")
    if not isinstance(items, list):
        return []
    findings = []
    for item in items:
        if not isinstance(item, dict):
            continue
        pid = item.get("pid")
        name = item.get("name") or "process"
        managed = bool(item.get("is_managed"))
        kind = technique = None
        score = 0.0
        if int(item.get("replaced") or 0) > 0:
            kind, technique, score = "hollowing", "T1055.012", 0.95
        elif int(item.get("implanted_pe") or 0) > 0:
            kind, technique, score = "implanted-pe", "T1620", 0.9
        elif int(item.get("hdr_modified") or 0) > 0:
            kind, technique, score = "header-modification", "T1055", 0.85
        elif int(item.get("implanted_shc") or 0) > 0:
            # Managed .NET JIT regions are routinely classified as shellcode
            # by the pattern/thread scan. Keep them out of the alert stream.
            if managed:
                continue
            kind, technique, score = "shellcode", "T1055", 0.8
        elif int(item.get("unreachable_file") or 0) > 0:
            kind, technique, score = "unreachable-module", "T1055", 0.8
        elif int(item.get("other") or 0) > 0:
            kind, technique, score = "memory-anomaly", "T1055", 0.75
        if not kind:
            continue
        alert = f"memory:{kind}:{pid}:{name}"[:64]
        findings.append({
            "ts": _now(), "host": socket.gethostname() or "localhost",
            "source": "memory", "kind": "alert", "event_id": EVENT_ID,
            "severity": "critical" if score >= 0.9 else "high" if score >= 0.7 else "low",
            "score": score, "action": "logged", "technique": technique,
            "alert_id": alert, "process": name, "pid": pid,
            "description": f"HollowsHunter {kind}: {name} (pid {pid})"[:2048],
        })
    return findings


def findings_from_reports(reports: list[dict]) -> list[dict]:
    """Convert HollowsHunter/PE-sieve scan reports to Plasma alert events."""
    findings = []
    seen = set()
    for report in reports:
        if not isinstance(report, dict):
            continue
        scans = report.get("scans") or []
        for item in scans:
            if not isinstance(item, dict):
                continue
            mapping = item.get("mapping_scan")
            headers = item.get("headers_scan")
            code = item.get("code_scan")
            iat = item.get("iat_scan")
            ws = item.get("workingset_scan")
            if isinstance(mapping, dict) and mapping.get("status") == 1:
                data = mapping
                kind, tech, score = "mapping-mismatch", "T1055", 0.9
            elif isinstance(headers, dict) and headers.get("status") == 1:
                data = headers
                if headers.get("is_pe_replaced"):
                    kind, tech, score = "hollowing", "T1055.012", 0.95
                else:
                    kind, tech, score = "header-modification", "T1055", 0.85
            elif isinstance(ws, dict) and ws.get("status") == 1:
                data = ws
                if ws.get("has_shellcode"):
                    kind, tech, score = "shellcode", "T1055", 0.9
                elif ws.get("has_pe"):
                    kind, tech, score = "implanted-pe", "T1620", 0.9
                else:
                    kind, tech, score = "workingset-anomaly", "T1055", 0.8
            elif isinstance(code, dict) and code.get("status") == 1:
                data = code
                kind, tech, score = "code-patch", "T1055", 0.8
            elif isinstance(iat, dict) and iat.get("status") == 1:
                data = iat
                kind, tech, score = "iat-hook", "T1055", 0.8
            else:
                continue
            module = data.get("module") if isinstance(data, dict) else None
            key = (report.get("pid"), module, kind)
            if key in seen:
                continue
            seen.add(key)
            findings.append(_finding(kind, tech, report, data, module, score))
    return findings


def parse_scan(stdout: str, report_path=None) -> dict:
    payload = _first_json(stdout)
    if payload is None and report_path:
        try:
            payload = json.loads(Path(report_path).read_text(
                encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            payload = None
    reports = []
    if payload is not None:
        _walk_reports(payload, reports)
    findings = findings_from_reports(reports)
    if not findings and payload is not None:
        findings = findings_from_summary(payload)
    suspicious = 0
    suppressed = 0
    if isinstance(payload, dict):
        try:
            suspicious = int(payload.get("suspicious_count") or 0)
        except (TypeError, ValueError):
            suspicious = 0
        for item in payload.get("suspicious") or []:
            if not isinstance(item, dict):
                continue
            if item.get("is_managed") and int(item.get("implanted_shc") or 0) > 0 \
                    and not any(int(item.get(k) or 0) > 0 for k in
                                ("replaced", "implanted_pe", "hdr_modified",
                                 "unreachable_file", "other")):
                suppressed += 1
    return {"reports": reports, "findings": findings,
            "suspicious_count": suspicious, "suppressed_count": suppressed,
            "payload": payload}


def _append_events(root, events_path, findings, no_dedupe=False) -> int:
    root = Path(root)
    state_path = root / STATE_FILE
    state = agentstate.read_json(state_path, {}) or {}
    seen = set(state.get("seen") or []) if isinstance(state, dict) else set()
    written = 0
    new_seen = set(seen)
    if not findings:
        return 0
    events_path = Path(events_path)
    events_path.parent.mkdir(parents=True, exist_ok=True)
    for event in findings:
        key = agentstate.sha256_obj({
            "pid": event.get("pid"), "alert_id": event.get("alert_id"),
            "file_path": event.get("file_path"),
        })
        if not no_dedupe and key in new_seen:
            continue
        with agentstate.lock(root / ".memory-events.lock", timeout=10,
                             stale=60):
            agentstate.ensure_trailing_newline(events_path)
            with events_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(redact.redact_event(event),
                                    sort_keys=True, ensure_ascii=False) + "\n")
        new_seen.add(key)
        written += 1
    agentstate.write_json(state_path, {"seen": list(new_seen)[-5000:]})
    return written


def scan(root, pids=None, pnames=None, all_processes=False, dump=False,
         deep=False, timeout=DEFAULT_TIMEOUT, scanner="64",
         events_path=None, no_events=False, no_dedupe=False) -> dict:
    root = Path(root)
    if not pids and not pnames and not all_processes:
        return {"error": "select a target with --pid, --pname or --all",
                "code": "NO_TARGET"}
    if dump and all_processes:
        return {"error": "refusing --dump with --all; target a PID or name",
                "code": "REFUSED"}
    tool = resolve_tool(root, scanner)
    if "error" in tool:
        return tool
    try:
        argv = build_argv(tool["path"], pids, pnames, dump=dump, deep=deep)
    except ValueError as exc:
        return {"error": str(exc), "code": "REFUSED"}
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    scan_dir = root / SCANS_DIR / stamp
    scan_dir.mkdir(parents=True, exist_ok=True)
    if dump:
        argv += ["/dir", str(scan_dir / "artifacts")]
    started = time.time()
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=max(5, int(timeout)), check=False)
    except subprocess.TimeoutExpired:
        return {"error": f"memory scan exceeded {timeout}s", "code": "TIMEOUT",
                "argv": argv}
    except OSError as exc:
        return {"error": f"cannot run scanner: {exc}", "code": "TOOL_ERROR"}
    elapsed = round((time.time() - started) * 1000, 1)
    stdout = proc.stdout or ""
    (scan_dir / "stdout.txt").write_text(stdout, encoding="utf-8")
    (scan_dir / "stderr.txt").write_text(proc.stderr or "", encoding="utf-8")
    if "Parsing the parameter failed" in stdout:
        return {"error": "HollowsHunter rejected the scan arguments",
                "detail": stdout[-1200:], "code": "ARGV_ERROR",
                "argv": argv}
    parsed = parse_scan(stdout)
    payload = parsed.get("payload")
    if payload is not None:
        (scan_dir / "report.json").write_text(
            json.dumps(payload, indent=2, default=str) + "\n",
            encoding="utf-8")
    meta = {
        "ts": _now(), "scanner": tool, "argv": argv,
        "exit_code": proc.returncode, "elapsed_ms": elapsed,
        "findings": len(parsed["findings"]),
        "suspicious_count": parsed["suspicious_count"],
        "dump": bool(dump), "deep": bool(deep),
        "targets": {"pids": pids, "pnames": pnames, "all": all_processes},
    }
    (scan_dir / "meta.json").write_text(json.dumps(meta, indent=2) + "\n",
                                        encoding="utf-8")
    written = 0
    events = events_path or root / "data" / "events.jsonl"
    if not no_events:
        written = _append_events(root, events, parsed["findings"],
                                 no_dedupe=no_dedupe)
    result = {
        "ok": proc.returncode in (0, 2, None),
        "scanner": tool,
        "argv": argv,
        "exit_code": proc.returncode,
        "elapsed_ms": elapsed,
        "suspicious_count": parsed["suspicious_count"],
        "suppressed_managed_jit": parsed.get("suppressed_count", 0),
        "findings": parsed["findings"],
        "events_written": written,
        "scan_dir": str(scan_dir),
        "stdout_tail": stdout[-1200:] if not parsed["findings"] else None,
        "stderr_tail": (proc.stderr or "")[-500:] or None,
    }
    return result


def status(root) -> dict:
    root = Path(root)
    tool64 = resolve_tool(root, "64")
    tool32 = resolve_tool(root, "32")
    scans = []
    for meta in sorted((root / SCANS_DIR).glob("*/meta.json"),
                       key=lambda p: p.stat().st_mtime, reverse=True)[:10]:
        try:
            scans.append(json.loads(meta.read_text(encoding="utf-8-sig")))
        except (OSError, json.JSONDecodeError):
            continue
    return {
        "tool": tool64,
        "tool32": tool32,
        "version": TOOL_VERSION,
        "last_scan": scans[0] if scans else None,
        "recent_scans": scans,
        "state": str(root / STATE_FILE),
    }


def list_scans(root) -> dict:
    root = Path(root)
    rows = []
    for meta in sorted((root / SCANS_DIR).glob("*/meta.json"),
                       key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            rows.append(json.loads(meta.read_text(encoding="utf-8-sig")))
        except (OSError, json.JSONDecodeError):
            continue
    return {"count": len(rows), "scans": rows[:50]}
