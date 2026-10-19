"""Plasma fleet: one desk, many computers — cross-host correlation.

Desk-side only. Endpoints need nothing new: their normalized events.jsonl
stores are already small, schema-identical JSONL, so the fleet command
simply pulls a capped tail from each host, drops the digests into a local
case directory, and joins them with deterministic rules.

Ethos guards, inherited from the observatory:
* pull small answers on demand — never a standing collector, never a lake;
* credentials never touch disk or the case directory (env-var indirection
  only, verified by test);
* joins are dumb, auditable rules — no model judgment in the control path.

Join rules (rmagent-so lineage):
  canary_tripped  10  a canary account appears on any host
  lateral_hop      9  same user seen on 2+ hosts inside the time window
  shared_hash      8  same file hash on 2+ hosts
  shared_domain    7  same dns_query on 2+ hosts
  shared_ip        7  same dest_ip on 2+ hosts
  blind_host       8  an attest answer in the case reports blindness
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_WINDOW = 1800          # 30 minutes, seconds
DEFAULT_CAP = 200              # most-recent rows per host
CANARY_DEFAULTS = ["plasma-canary"]

_FINDING_SCORES = {
    "canary_tripped": 10,
    "lateral_hop": 9,
    "shared_hash": 8,
    "blind_host": 8,
    "shared_domain": 7,
    "shared_ip": 7,
}


# ---------------------------------------------------------------------------
# inventory
# ---------------------------------------------------------------------------

def load_inventory(path) -> list[dict]:
    """Validate and return host entries. Passwords arrive via the
    environment (password_env) — never from the inventory file."""
    blob = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = blob.get("hosts")
    if not isinstance(entries, list) or not entries:
        raise ValueError("inventory needs a non-empty 'hosts' array")
    seen = set()
    for e in entries:
        name = e.get("name", "")
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$", name):
            raise ValueError(f"bad host name {name!r}")
        if name in seen:
            raise ValueError(f"duplicate host name {name!r}")
        seen.add(name)
        transport = e.get("transport", "file")
        if transport not in ("winrm", "file"):
            raise ValueError(f"{name}: unknown transport {transport!r}")
        if transport == "file" and not e.get("events_path"):
            raise ValueError(f"{name}: file transport needs events_path")
        if transport == "winrm":
            if not e.get("endpoint"):
                raise ValueError(f"{name}: winrm transport needs endpoint")
            if e.get("password"):
                raise ValueError(
                    f"{name}: inline passwords are forbidden — use password_env")
            if not e.get("password_env"):
                raise ValueError(f"{name}: winrm transport needs password_env")
    return entries


# ---------------------------------------------------------------------------
# pull transports
# ---------------------------------------------------------------------------

def _parse_ts(text):
    if not text:
        return None
    try:
        return datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None


def _rows_from_text(text, cap):
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue                       # banners, progress noise
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows[-cap:]


def _pull_file(entry, out_file: Path, cap) -> dict:
    src = Path(entry["events_path"])
    if not src.exists():
        return {"host": entry["name"], "error": f"file not found: {src}"}
    rows = _rows_from_text(src.read_text(encoding="utf-8", errors="replace"), cap)
    out_file.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows),
                        encoding="utf-8")
    return {"host": entry["name"], "transport": "file", "rows": len(rows)}


def _pull_winrm(entry, out_file: Path, cap) -> dict:
    """Fetch the remote events tail over WinRM. Password comes from the
    environment variable named by password_env; it is never written down.

    The primary read is byte-exact (base64 of the file): PS text output
    re-encodes through the console codepage, which mangles non-ASCII bytes
    and can inject quote characters that break JSON lines. Falls back to
    Get-Content -Tail (line mode; PS 5.1 forbids -Raw + -Tail) when the
    file cannot be read as bytes (e.g. held open by the sensor)."""
    try:
        import winrm  # optional desk-side dependency (pip install plasma-edr[desk])
    except ImportError:
        return {"host": entry["name"],
                "error": "pywinrm not installed (pip install 'plasma-edr[desk]')"}
    password = os.environ.get(entry["password_env"], "")
    if not password:
        return {"host": entry["name"],
                "error": f"environment variable {entry['password_env']} is not set"}
    target = entry.get("events_path", r"C:\ProgramData\Plasma\data\events.jsonl")
    quoted = target.replace("'", "''")
    try:
        sess = winrm.Session(entry["endpoint"],
                             auth=(entry.get("username", "Administrator"), password),
                             transport="ntlm", read_timeout_sec=120)
        rows: list[dict] = []
        via = "base64"
        try:
            res = sess.run_ps(f"[IO.File]::ReadAllBytes('{quoted}').Length | Out-Null; "
                              f"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{quoted}'))")
            token = max(res.std_out.decode(errors="replace").split(), key=len)
            raw = base64.b64decode(token).decode("utf-8")
            rows = _rows_from_text(raw, cap)
        except Exception:  # locked file / no bytes API — fall back to line mode
            via = "tail-text"
            res = sess.run_ps(f"Get-Content -LiteralPath '{quoted}' -Tail "
                              + str(int(cap * 4)))
            if res.status_code != 0:
                return {"host": entry["name"], "error":
                        (res.std_err.decode(errors="replace")
                         or "remote failed")[:200]}
            rows = _rows_from_text(res.std_out.decode(errors="replace"), cap)
    except Exception as exc:  # noqa: BLE001 — endpoint failures are data
        return {"host": entry["name"], "error": f"winrm failed: {str(exc)[:200]}"}
    out_file.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows),
                        encoding="utf-8")
    return {"host": entry["name"], "transport": "winrm", "rows": len(rows),
            "read_via": via}


# ---------------------------------------------------------------------------
# case directories
# ---------------------------------------------------------------------------

def case_dir(root, name) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
    return Path(root) / "fleet-cases" / safe


def init_case(root, name, window_seconds=DEFAULT_WINDOW, canaries=None) -> Path:
    cd = case_dir(root, name)
    (cd / "answers").mkdir(parents=True, exist_ok=True)
    meta_file = cd / "case.json"
    if not meta_file.exists():
        meta_file.write_text(json.dumps({
            "case": name,
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "window_seconds": window_seconds,
            "canaries": canaries or CANARY_DEFAULTS,
        }, indent=1) + "\n", encoding="utf-8")
    return cd


def pull(root, inventory_path, case, cap=DEFAULT_CAP, window_seconds=DEFAULT_WINDOW,
         canaries=None) -> dict:
    """Pull a capped events tail from every inventory host into the case."""
    entries = load_inventory(inventory_path)
    cd = init_case(root, case, window_seconds=window_seconds, canaries=canaries)
    results = []
    for entry in entries:
        out_file = cd / "answers" / f"{entry['name']}.events.jsonl"
        if entry.get("transport", "file") == "winrm":
            res = _pull_winrm(entry, out_file, cap)
        else:
            res = _pull_file(entry, out_file, cap)
        results.append(res)
    ok = [r for r in results if "error" not in r]
    return {"case": str(cd), "hosts": len(entries),
            "pulled": len(ok), "failed": len(results) - len(ok),
            "results": results}


# ---------------------------------------------------------------------------
# deterministic joins
# ---------------------------------------------------------------------------

def _norm_user(user):
    """DOMAIN\\user -> user; drop machine accounts and empty values."""
    if not user:
        return None
    u = str(user).split("\\")[-1].split("@")[0].strip().lower()
    if not u or u.endswith("$") or u in ("system", "local service",
                                         "network service", "-"):
        return None
    return u


def _load_case_events(cd) -> dict[str, list[dict]]:
    per_host: dict[str, list[dict]] = {}
    for f in sorted((cd / "answers").glob("*.events.jsonl")):
        host = f.name[: -len(".events.jsonl")]
        rows = []
        for ln in f.read_text(encoding="utf-8", errors="replace").splitlines():
            if ln.strip():
                try:
                    rows.append(json.loads(ln))
                except json.JSONDecodeError:
                    continue
        per_host[host] = rows
    return per_host


def _findings_for_window(cd, window_seconds):
    meta = json.loads((cd / "case.json").read_text(encoding="utf-8"))
    return float(meta.get("window_seconds", window_seconds))


def correlate(root, case, window_seconds=None, cap_findings=50) -> dict:
    """Join the pulled per-host event digests into deterministic findings."""
    cd = case_dir(root, case)
    if not (cd / "case.json").exists():
        return {"error": f"no such case: {case}",
                "hint": "run: plasma fleet pull --case " + case}
    window = window_seconds or _findings_for_window(cd, DEFAULT_WINDOW)
    canaries = {c.lower() for c in json.loads(
        (cd / "case.json").read_text(encoding="utf-8")).get("canaries", [])}
    per_host = _load_case_events(cd)
    findings: list[dict] = []

    # --- canary_tripped: any canary user, anywhere --------------------------
    for host, rows in per_host.items():
        for row in rows:
            u = _norm_user(row.get("user"))
            if u and u in canaries:
                findings.append({
                    "type": "canary_tripped", "score": 10, "hosts": [host],
                    "user": u, "ts": row.get("ts"),
                    "detail": f"canary account '{u}' seen on {host}",
                })
                break

    # --- lateral_hop: same user on 2+ hosts within the window ---------------
    user_hosts: dict[str, dict[str, list]] = {}
    for host, rows in per_host.items():
        for row in rows:
            u = _norm_user(row.get("user"))
            if not u or u in canaries:
                continue
            ts = _parse_ts(row.get("ts"))
            if ts is None:
                continue
            user_hosts.setdefault(u, {}).setdefault(host, []).append(ts)
    for u, hosts in user_hosts.items():
        if len(hosts) < 2:
            continue
        stamps = sorted(t for ts in hosts.values() for t in ts)
        span = (stamps[-1] - stamps[0]).total_seconds()
        if span <= window:
            order = sorted(
                ((min(ts), h) for h, ts in hosts.items()), key=lambda x: x[0])
            findings.append({
                "type": "lateral_hop", "score": 9,
                "hosts": [h for _, h in order], "user": u,
                "detail": f"user '{u}' on {len(hosts)} hosts within "
                          f"{int(span/60)} min: " +
                          " -> ".join(h for _, h in order),
            })

    # --- shared indicators: same hash/domain/ip on 2+ hosts -----------------
    for field, ftype, score in (("file_hash", "shared_hash", 8),
                                ("dns_query", "shared_domain", 7),
                                ("dest_ip", "shared_ip", 7)):
        by_value: dict[str, set] = {}
        evidence: dict[str, list] = {}
        for host, rows in per_host.items():
            for row in rows:
                v = row.get(field)
                if not v or str(v).lower() in ("-", "none"):
                    continue
                v = str(v).lower()
                by_value.setdefault(v, set()).add(host)
                evidence.setdefault(v, []).append(
                    {"host": host, "ts": row.get("ts"), field: str(v)})
        for v, hosts in by_value.items():
            if len(hosts) < 2:
                continue
            findings.append({
                "type": ftype, "score": score, "hosts": sorted(hosts),
                "indicator": v,
                "detail": f"{field} '{v}' on {len(hosts)} hosts: "
                          + ", ".join(sorted(hosts)),
            })

    # --- blind_host: attest answers carried in the case ---------------------
    for f in sorted((cd / "answers").glob("*.attest.json")):
        try:
            answer = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if answer.get("blind_count", 0) > 0 or \
                answer.get("whids_service") not in (None, "Running"):
            findings.append({
                "type": "blind_host", "score": 8,
                "hosts": [f.name[: -len(".attest.json")]],
                "detail": f"blind subcategories: "
                          f"{answer.get('blind_subcategories')}; "
                          f"whids={answer.get('whids_service')}",
            })

    findings.sort(key=lambda f: (-f.get("score", 0), f["type"]))
    top = max((f["score"] for f in findings), default=0)
    out = {
        "case": case,
        "hosts": sorted(per_host),
        "rows": {h: len(rows) for h, rows in per_host.items()},
        "window_seconds": int(window),
        "findings": findings[:cap_findings],
        "findings_total": len(findings),
        "top_score": top,
        "verdict": ("clean" if top == 0 else
                    "investigate" if top < 8 else "act now"),
    }
    (cd / "findings.json").write_text(
        json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# one-page report
# ---------------------------------------------------------------------------

def report(root, case) -> dict:
    cd = case_dir(root, case)
    findings_file = cd / "findings.json"
    if not findings_file.exists():
        return {"error": f"case '{case}' has no findings — run correlate first"}
    data = json.loads(findings_file.read_text(encoding="utf-8"))
    lines = [
        f"# Plasma fleet case: {data['case']}",
        "",
        f"Hosts: {', '.join(data['hosts'])}",
        f"Window: {data['window_seconds']}s | "
        f"Rows: {data['rows']} | Verdict: **{data['verdict']}** "
        f"(top {data['top_score']}/10)",
        "",
    ]
    for f in data["findings"]:
        lines.append(f"## [{f['score']}/10] {f['type']}")
        lines.append(f"- {f['detail']}")
        lines.append("")
    text = "\n".join(lines)
    (cd / "report.md").write_text(text, encoding="utf-8")
    return {"report": str(cd / "report.md"), "verdict": data["verdict"],
            "findings": data["findings_total"], "markdown": text}
