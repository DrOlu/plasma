"""Plasma ETW tap control plane (Python side of plasma-tap.exe).

The C++ tap (tap/plasma-tap.cpp, krabsetw) streams gap providers, scores
in memory and emits MATCHES ONLY as JSONL. This module is everything that
must remain portable and testable:

* load + validate the canonical rules (sensors/plasma-tap-rules.json);
* render the pipe-format rules file the tap consumes;
* run the tap binary for a bounded window and parse its summary;
* normalize matched events into the strict PlasmaEvent contract and
  collect them into the events store with dedupe.

Lake-less guarantees mirrored from the C++ side: no raw streams are ever
handled here, only capped match records.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

TAP_PROVIDER_ALIASES = {
    "powershell": "Microsoft-Windows-PowerShell",
    "wmi": "Microsoft-Windows-WMI-Activity",
    "dns": "Microsoft-Windows-DNS-Client",
    "dotnet": "Microsoft-Windows-DotNETRuntime",
    "schannel": "Microsoft-Windows-Schannel",
    "security": "Microsoft-Windows-Security-Auditing",
}
SEVERITY_SCORE = {"info": 0.1, "low": 0.3, "medium": 0.5, "high": 0.8, "critical": 1.0}
_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
_DURATION = re.compile(r"^(\d+)([smh]?)$")
_SECONDS = {"s": 1, "m": 60, "h": 3600, "": 1}


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------

def load_rules(path) -> list[dict]:
    blob = json.loads(Path(path).read_text(encoding="utf-8"))
    rules = blob.get("rules")
    if not isinstance(rules, list):
        raise ValueError("rules file has no 'rules' array")
    seen = set()
    for r in rules:
        name = r.get("name", "")
        if not name or name in seen:
            raise ValueError(f"rule name missing or duplicated: {name!r}")
        seen.add(name)
        if r.get("provider", "") not in TAP_PROVIDER_ALIASES and r["provider"] != "*":
            raise ValueError(f"{name}: unknown provider {r.get('provider')!r}")
        eid = r.get("event_id", 0)
        if not isinstance(eid, int) or eid < 0 or eid > 99999:
            raise ValueError(f"{name}: bad event_id {eid!r}")
        if r.get("severity") not in SEVERITY_SCORE:
            raise ValueError(f"{name}: bad severity {r.get('severity')!r}")
        if not _TECHNIQUE.match(r.get("technique", "")):
            raise ValueError(f"{name}: bad technique {r.get('technique')!r}")
        for field in ("substr", "field"):
            v = r.get(field, "")
            if "|" in v or "\n" in v:
                raise ValueError(f"{name}: {field} may not contain '|' or newlines")
    return rules


def build_rules_txt(rules: list[dict], out_path) -> int:
    """Render the 7-field pipe format plasma-tap.cpp parses."""
    lines = ["# generated from plasma-tap-rules.json — do not edit by hand"]
    for r in rules:
        lines.append("|".join([
            r["name"], r["provider"], str(r["event_id"]),
            r.get("field", ""), r.get("substr", ""), r["severity"], r["technique"],
        ]))
    Path(out_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(rules)


def parse_duration(text: str) -> int:
    m = _DURATION.match(text.strip())
    if not m:
        raise ValueError(f"bad duration {text!r} (use e.g. 90s, 5m, 1h)")
    return int(m.group(1)) * _SECONDS[m.group(2)]


# ---------------------------------------------------------------------------
# running the tap binary
# ---------------------------------------------------------------------------

def selftest(tap_exe, rules_txt: Path) -> dict:
    try:
        proc = subprocess.run(
            [str(tap_exe), "--rules", str(rules_txt), "--selftest"],
            capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": f"tap selftest failed to run: {exc}"}
    try:
        result = json.loads((proc.stdout or "").strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        return {"ok": False, "error": "tap selftest did not emit JSON",
                "rc": proc.returncode}
    result["rc"] = proc.returncode
    return result


def run(tap_exe, providers, seconds: int, out_path, rules_txt: Path,
        max_matches: int = 500) -> dict:
    """Run the tap for a bounded window. Never raises for tap-side failures."""
    try:
        proc = subprocess.run(
            [str(tap_exe),
             "--rules", str(rules_txt),
             "--out", str(out_path),
             "--providers", ",".join(providers),
             "--for", str(int(seconds)),
             "--max-matches", str(int(max_matches))],
            capture_output=True, text=True, timeout=seconds + 30)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "tap exceeded its window + grace period"}
    except OSError as exc:
        return {"ok": False, "error": f"cannot execute tap binary: {exc}"}
    try:
        summary = json.loads((proc.stdout or "").strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        return {"ok": False, "error": "tap produced no JSON summary",
                "rc": proc.returncode,
                "stderr": (proc.stderr or "")[-500:]}
    summary["rc"] = proc.returncode
    summary["matches_file"] = str(out_path)
    return summary


# ---------------------------------------------------------------------------
# normalization into the PlasmaEvent contract (source="tap")
# ---------------------------------------------------------------------------

def _clip(value, limit):
    if value is None:
        return None
    text = str(value)
    return text[:limit] if len(text) > limit else text


def normalize_match(row: dict, host: str = "localhost") -> dict:
    """Map one tap match JSON row to a strict PlasmaEvent dict."""
    props = row.get("props") or {}
    severity = row.get("severity") if row.get("severity") in SEVERITY_SCORE else "low"
    event_id = row.get("event_id") or 0
    alert_id = _clip("tap:" + str(row.get("rule", "unknown")), 64)
    cmdline = props.get("ScriptBlockText") or props.get("CommandLine")
    technique = row.get("technique")
    if not technique or not _TECHNIQUE.match(technique):
        technique = None
    description_parts = [
        f"tap match {row.get('rule')} on {row.get('provider')}"
        f"/{row.get('event_name') or event_id} ({row.get('field')})",
        _clip(row.get("snippet"), 300),
    ]
    # ASCII-only joiner: event JSONL travels through Windows pipes (WinRM,
    # console codepages) where smart punctuation gets mangled into quote
    # bytes that break line-JSON parsers on the far side.
    event = {
        "ts": row.get("ts"),
        "host": host,
        "source": "tap",
        "kind": "alert",
        "event_id": max(int(event_id), 1),
        "severity": severity,
        "score": SEVERITY_SCORE[severity],
        "action": "logged",
        "technique": technique,
        "alert_id": alert_id,
        "description": _clip(" - ".join(p for p in description_parts if p), 2048),
        "pid": int(row["pid"]) if str(row.get("pid") or "").isdigit() and
               int(row["pid"]) <= 2_147_483_647 else None,
        "process": _clip(props.get("ProcessName"), 260),
        "user": _clip(props.get("TargetUserName") or props.get("SubjectUserName"), 128),
        "cmdline": _clip(cmdline, 8192),
        "dns_query": _clip(props.get("QueryName"), 253),
        "file_path": _clip(props.get("Path") or props.get("FileName"), 4096),
    }
    return {k: v for k, v in event.items() if v is not None}


def collect(matches_path, events_path, host: str = "localhost") -> dict:
    """Normalize tap matches into the events store with content dedupe.

    Dedupe is on the normalized payload (sort_keys JSON), so re-collecting
    the same matches never duplicates rows regardless of raw-line spacing.
    """
    matches = Path(matches_path)
    if not matches.exists():
        return {"error": f"no matches file: {matches}"}
    events = Path(events_path)

    def _digest(payload: str) -> str:
        return hashlib.sha256(payload.encode()).hexdigest()

    existing = set()
    if events.exists():
        for ln in events.read_text(encoding="utf-8").splitlines():
            if not ln.strip():
                continue
            try:
                row = json.loads(ln)
                existing.add(_digest(json.dumps(row, ensure_ascii=False, sort_keys=True)))
            except json.JSONDecodeError:
                existing.add(_digest(ln.strip()))

    written = already = skipped = 0
    events.parent.mkdir(parents=True, exist_ok=True)
    with events.open("a", encoding="utf-8") as out:
        for ln in matches.read_text(encoding="utf-8").splitlines():
            if not ln.strip():
                continue
            try:
                row = json.loads(ln)
            except json.JSONDecodeError:
                skipped += 1
                continue
            event = normalize_match(row, host=host)
            payload = json.dumps(event, ensure_ascii=False, sort_keys=True)
            digest = _digest(payload)
            if digest in existing:
                already += 1
                continue
            out.write(payload + "\n")
            existing.add(digest)
            written += 1
    return {"matches_read": written + already + skipped, "written": written,
            "already_present": already, "unparsable": skipped}
