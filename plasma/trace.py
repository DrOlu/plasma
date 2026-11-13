"""Plasma trace: DTrace as the on-demand kernel microscope.

DTrace (Microsoft, v2.0 MSI or built-in from Windows Server 2025) is the
opposite of a monitoring agent: you pick it up, trace for a bounded window,
and put it down. Plasma integrates it the same way as the ETW tap:

* reviewed D scripts only (``sensors/dtrace/*.d``, metadata in comments);
* no destructive mode — ``-w`` is never passed and ``system()`` is refused;
* bounded runs — wall-clock window + row cap, then the process is killed;
* output normalizes into the same events contract (``kind: "trace"``), so
  chains/fleet/drift consume it unchanged;
* provisioning is explicit (``plasma trace provision``): DTrace is a kernel
  tracer that needs ``bcdedit /set dtrace on`` and a reboot, so it is never
  installed silently by the EDR installer.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

MARKER = "plasma|"
ALLOWED_PROBES = ("syscall", "fbt", "pid", "profile", "etw", "sched")
FORBIDDEN = ("system(", "exec(", "raise(", "panic(", "abort(")
DEFAULT_MAX_ROWS = 2000
DOWNLOADS_URL = "https://www.microsoft.com/en-us/download/details.aspx?id=100441"
WINGET_ID = "Microsoft.DTrace"
# Official Microsoft DTrace 2.0 MSI (amd64). winget is absent on Server
# 2022 by default, so provision downloads this directly.
MSI_URL = ("https://download.microsoft.com/download/7/9/d/"
           "79d6b79a-5836-4118-a9b7-60bc77c97bf7/DTrace.amd64.msi")


def _is_v2(version: str | None) -> bool:
    """True for Microsoft DTrace 2.x; the old Sun D 1.13.1 preview is not."""
    return bool(version) and re.search(r"(?<!\d)2\.\d", version) is not None

# Metadata uses C-style block comments: the Windows DTrace compiler rejects
# `//` line comments outright ("syntax error near /", field-found on WS1).
_META_RE = re.compile(
    r"^\s*/\*\s*(name|technique|score|kind|summary):\s*(.+?)\s*\*/\s*$")


class ScriptError(ValueError):
    pass


def _scripts_dir(root: str | Path | None = None) -> Path:
    """Find the reviewed script library on a dev checkout or installed node.

    v1.5.0 shipped without sensors/dtrace inside the bundle, so every
    `trace` command failed on installed hosts ("not found (repo or
    embedded)"); the builder now stages the payload and this resolver
    looks in the frozen bundle, the instance root, and the repo.
    """
    import sys
    candidates = []
    if root:
        candidates += [Path(root) / "sensors" / "dtrace",
                        Path(root) / "embedded" / "sensors" / "dtrace"]
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / "embedded" / "sensors" / "dtrace")
    candidates += [Path(__file__).resolve().parent.parent / "sensors" / "dtrace",
                   Path(__file__).resolve().parent / "sensors" / "dtrace",
                   Path.cwd() / "sensors" / "dtrace",
                   Path.cwd() / "embedded" / "sensors" / "dtrace"]
    for cand in candidates:
        if cand.is_dir():
            return cand
    raise FileNotFoundError("sensors/dtrace not found (repo or embedded)")


def parse_metadata(text: str) -> dict:
    meta = {}
    for line in text.splitlines():
        m = _META_RE.match(line.strip())
        if m:
            meta[m.group(1)] = m.group(2).strip()
    return meta


def validate_script(text: str, name: str = "") -> dict:
    """Refuse destructive D and require the strict row marker."""
    if "system(" in text:
        raise ScriptError(f"{name}: D system() is forbidden")
    for token in FORBIDDEN:
        if token in text:
            raise ScriptError(f"{name}: forbidden construct {token!r}")
    if MARKER not in text:
        raise ScriptError(f"{name}: script must emit rows prefixed {MARKER!r}")
    if len(text) > 20000:
        raise ScriptError(f"{name}: script too large")
    probes = {p for p in ALLOWED_PROBES if re.search(rf"\b{p}(-|::|:)", text)}
    if not probes:
        raise ScriptError(f"{name}: no allowlisted provider "
                          f"({', '.join(ALLOWED_PROBES)}) found")
    meta = parse_metadata(text)
    try:
        score = int(meta.get("score", "5"))
    except ValueError:
        raise ScriptError(f"{name}: score must be an integer 0-10")
    if not 0 <= score <= 10:
        raise ScriptError(f"{name}: score out of range")
    return {"name": meta.get("name") or name,
            "technique": meta.get("technique", ""),
            "score": score,
            "kind": meta.get("kind", "trace"),
            "summary": meta.get("summary", ""),
            "providers": sorted(probes)}


def load_scripts(root: str | Path | None = None) -> list[dict]:
    """Load + validate the reviewed script library (metadata included)."""
    directory = _scripts_dir(root)
    scripts = []
    for path in sorted(directory.glob("*.d")):
        text = path.read_text(encoding="utf-8")
        info = validate_script(text, path.stem)
        info["file"] = str(path)
        info["sha256"] = hashlib.sha256(text.encode()).hexdigest()
        scripts.append(info)
    if not scripts:
        raise FileNotFoundError(f"no .d scripts in {directory}")
    return scripts


def find_dtrace() -> str | None:
    """Locate dtrace.exe on PATH or in its default install directory.

    The Microsoft.DTrace MSI does not add itself to PATH, so a PATH-only
    probe reported "not installed" on a host that had it (WS2, field-found).
    """
    path = shutil.which("dtrace")
    if path:
        return path
    bases = [os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"),
             os.environ.get("ProgramW6432"), r"C:\Program Files"]
    for base in dict.fromkeys(b for b in bases if b):
        cand = Path(base) / "DTrace" / "dtrace.exe"
        if cand.is_file():
            return str(cand)
    return None


def _run_ps(script: str, timeout: int = 60) -> str:
    exe = shutil.which("powershell.exe") or shutil.which("pwsh")
    if not exe:
        return ""
    try:
        proc = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout)
        return (proc.stdout or "").strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def check() -> dict:
    """Is DTrace present and enabled on this host? Read-only."""
    path = find_dtrace()
    result = {"available": bool(path), "path": path, "enabled": None,
              "version": None, "hint": None}
    if not path:
        result["hint"] = ("DTrace not found. Server 2025 ships it built-in; "
                          "else install Microsoft.DTrace (v2.0 MSI) and run "
                          f"`plasma trace provision`. {DOWNLOADS_URL}")
        return result
    version = _run_ps("dtrace -V", timeout=30) or ""
    result["version"] = version.splitlines()[0].strip() if version else None
    if not _is_v2(result["version"]):
        result["hint"] = ("DTrace 1.x is installed; Plasma requires Microsoft "
                          "DTrace 2.0 — run `plasma trace provision` to upgrade.")
    state = _run_ps("bcdedit /enum '{current}' | Select-String -SimpleMatch dtrace",
                    timeout=30)
    # `bcdedit /enum` prints "dtrace Yes", not "dtrace on" — matching only
    # "on" made a provisioned host look disabled after every reboot.
    lowered = state.lower()
    if re.search(r"dtrace\s+(yes|on)\b", lowered):
        result["enabled"] = True
    elif re.search(r"dtrace\s+(no|off)\b", lowered):
        result["enabled"] = False
        result["hint"] = ("DTrace is installed but not enabled: run "
                          "`plasma trace provision` and restart.")
    elif state:
        result["enabled"] = False
        result["hint"] = ("DTrace is installed but not enabled: run "
                          "`plasma trace provision` and restart.")
    else:
        # An empty bcdedit result is the normal "setting absent" case, not an
        # admin failure — the field run showed how misleading that hint was.
        result["enabled"] = False
        result["hint"] = ("DTrace boot setting is absent: run "
                          "`plasma trace provision` and restart.")
    return result


def selftest(root: str | Path | None = None) -> dict:
    """Compile every reviewed script with `dtrace -e` (no probes enabled)."""
    path = find_dtrace()
    if not path:
        return {"ok": False, "error": "dtrace not installed", "hint": check()["hint"]}
    results = []
    for info in load_scripts(root):
        proc = subprocess.run([path, "-e", "-s", info["file"]],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=120)
        results.append({
            "script": info["name"],
            "ok": proc.returncode == 0,
            "stderr": (proc.stderr or "").strip()[:300],
        })
    return {"ok": all(r["ok"] for r in results), "scripts": results}


def parse_output(text: str, max_rows: int = DEFAULT_MAX_ROWS) -> list[dict]:
    """Extract `plasma|{json}` rows; everything else is DTrace noise."""
    rows = []
    for line in text.splitlines():
        line = line.strip()
        pos = line.find(MARKER)
        if pos < 0:
            continue
        try:
            row = json.loads(line[pos + len(MARKER):])
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
        if len(rows) >= max_rows:
            break
    return rows


def normalize(row: dict, info: dict, host: str) -> dict:
    """One traced row -> strict PlasmaEvent (kind=trace)."""
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    detail = {k: v for k, v in row.items()
              if k not in ("probe", "pid", "comm") and v not in (None, "")}
    event = {
        "ts": ts,
        "host": host,
        "source": "dtrace",
        "kind": "trace",
        "event_id": 0,
        "severity": ("critical" if info.get("score", 5) >= 9 else
                     "high" if info.get("score", 5) >= 7 else "medium"),
        "score": min(1.0, max(0.0, info.get("score", 5) / 10)),
        "action": "observed",
        "process": str(row.get("comm") or "")[:260] or None,
        "pid": int(row["pid"]) if str(row.get("pid", "")).isdigit() else None,
        "description": (f"dtrace {info['name']}: {row.get('probe', 'event')}"
                        + (f" {json.dumps(detail, sort_keys=True)[:200]}"
                           if detail else ""))[:512],
    }
    if info.get("technique"):
        event["technique"] = info["technique"]
    return {k: v for k, v in event.items() if v is not None}


def run(script_name: str, events_path, seconds: int = 10,
        max_rows: int = DEFAULT_MAX_ROWS, out=None, root=None,
        host: str | None = None) -> dict:
    """Run one reviewed script for a bounded window and normalize the rows."""
    import socket
    scripts = load_scripts(root)
    info = next((s for s in scripts
                 if s["name"] == script_name or Path(s["file"]).stem == script_name),
                None)
    if info is None:
        return {"error": f"unknown script {script_name!r}",
                "scripts": [s["name"] for s in scripts]}
    if seconds < 1 or seconds > 300:
        return {"error": "seconds must be between 1 and 300"}
    path = find_dtrace()
    if not path:
        return {"error": "dtrace not installed", "hint": check()["hint"]}

    proc = subprocess.Popen([path, "-q", "-s", info["file"]],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8", errors="replace")
    killed = False
    try:
        stdout, stderr = proc.communicate(timeout=seconds)
    except subprocess.TimeoutExpired:
        killed = True
        proc.kill()
        stdout, stderr = proc.communicate()

    rows = parse_output(stdout or "", max_rows=max_rows)
    host = host or socket.gethostname()
    events = [normalize(r, info, host) for r in rows]

    written = 0
    out_path = Path(out) if out else None
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("".join(json.dumps(r, sort_keys=True) + "\n"
                                    for r in rows), encoding="utf-8")

    from pathlib import Path as _P
    store = _P(events_path)
    store.parent.mkdir(parents=True, exist_ok=True)
    existing = set()
    if store.exists():
        for ln in store.read_text(encoding="utf-8", errors="replace").splitlines():
            if ln.strip():
                try:
                    existing.add(hashlib.sha256(
                        json.dumps(json.loads(ln), ensure_ascii=False,
                                   sort_keys=True).encode()).hexdigest())
                except json.JSONDecodeError:
                    continue
    with store.open("a", encoding="utf-8") as fh:
        for ev in events:
            payload = json.dumps(ev, ensure_ascii=False, sort_keys=True)
            digest = hashlib.sha256(payload.encode()).hexdigest()
            if digest in existing:
                continue
            fh.write(payload + "\n")
            existing.add(digest)
            written += 1

    return {"script": info["name"], "technique": info.get("technique"),
            "seconds": seconds, "killed": killed, "rows": len(rows),
            "written": written, "store": str(store),
            "raw": str(out_path) if out_path else None,
            "stderr": (stderr or "").strip()[:300] or None}


def _install_msi(dest_dir) -> dict:
    """Download and silently install the official DTrace 2.0 MSI."""
    import urllib.request
    dest = Path(dest_dir) / "DTrace.amd64.msi"
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        urllib.request.urlretrieve(MSI_URL, dest)
    except Exception as exc:  # noqa: BLE001 — network failure is data
        return {"ok": False, "error": f"download failed: {exc}"[:200]}
    try:
        proc = subprocess.run(
            ["msiexec", "/i", str(dest), "/qn", "/norestart"],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=900)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": str(exc)[:200], "msi": str(dest)}
    # 3010 = success, restart required
    return {"ok": proc.returncode in (0, 3010), "rc": proc.returncode,
            "msi": str(dest)}


def provision() -> dict:
    """Install/upgrade Microsoft DTrace 2.0 and enable it. Explicit, never silent.

    Server 2025 ships dtrace built-in; older Windows needs the v2.0 MSI.
    winget is absent on Server 2022 by default, so the MSI is downloaded
    directly. Either way, kernel probes require `bcdedit /set dtrace on`
    plus a reboot.
    """
    state = check()
    if (state["available"] and state.get("enabled")
            and _is_v2(state.get("version"))):
        return {"ok": True, "already": "available and enabled (2.x)"}
    actions = []
    if not state["available"] or not _is_v2(state.get("version")):
        winget = shutil.which("winget")
        if winget:
            proc = subprocess.run(
                [winget, "install", "--id", WINGET_ID, "--exact", "--silent",
                 "--accept-package-agreements", "--accept-source-agreements"],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=900)
            actions.append({"action": "winget install Microsoft.DTrace",
                            "rc": proc.returncode,
                            "detail": (proc.stdout or "")[-400:]})
            state = check()
        if not state["available"] or not _is_v2(state.get("version")):
            msi = _install_msi(
                Path(os.environ.get("ProgramData", r"C:\ProgramData"))
                / "Plasma" / "tools")
            actions.append({"action": "install DTrace 2.0 MSI", **msi})
            state = check()
        if not state["available"]:
            return {"ok": False,
                    "error": "DTrace install failed",
                    "actions": actions,
                    "manual": f"Install Microsoft DTrace 2.0 MSI: {MSI_URL}"}
    enable = _run_ps("bcdedit /set dtrace on", timeout=60)
    actions.append({"action": "bcdedit /set dtrace on", "detail": enable[:200]})
    return {"ok": True, "reboot_required": True, "actions": actions,
            "version": state.get("version"),
            "next": "reboot, then run: plasma trace check && plasma trace selftest"}
