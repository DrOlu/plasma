"""Plasma command line.

    plasma manifest create --dir BUNDLE --version X
    plasma manifest verify --dir BUNDLE
    plasma bundle build --out dist --version X [--engines DIR] [--platform NAME]
    plasma ask --bundle BUNDLE --prompt "what happened on WS1?"
    plasma probe --bundle BUNDLE --tool plasma_overview
    plasma status --bundle BUNDLE
"""
from __future__ import annotations

import argparse
import json
import os
import platform as _platform
import shutil
import subprocess
import sys
from pathlib import Path

from . import __version__, whids, observatory, actuate, drift, tap, fleet, identity, notify, health, watch, chain, coverage, store, deep, playbooks, canary, trace
from . import update as updater
from .bundle import build_bundle
from .manifest import create_manifest, sha256_file, verify_manifest

MENU = "instance/needle_menu.json"


def _frozen() -> bool:
    """True when running from a PyInstaller one-file executable."""
    return bool(getattr(sys, "frozen", False))


def _embedded_root() -> Path | None:
    """Root of the payload embedded in a one-file executable, if any."""
    base = getattr(sys, "_MEIPASS", None)
    if not base:
        return None
    root = Path(base) / "embedded"
    return root if root.is_dir() else None


def _instance_dir(bundle: str | None) -> Path:
    if bundle in (None, "", "embedded"):
        root = _embedded_root()
        if root is not None:
            return root / "instance"
        # Developer fallback: the repo's instance directory.
        return Path(__file__).resolve().parent.parent / "instance"
    return Path(bundle) / "instance"


def _engine_names() -> list[str]:
    return ["needle.exe", "neural.exe", "needle", "neural"] if os.name == "nt" else [
        "needle", "neural", "needle.exe", "neural.exe"
    ]


def _current_platform() -> str:
    system = _platform.system().lower()
    machine = _platform.machine().lower()
    if system == "windows":
        return "windows-arm64" if "arm" in machine else "windows-x86_64"
    if system == "darwin":
        return "macos-arm64" if "arm" in machine or "aarch64" in machine else "macos-x86_64"
    if system == "linux":
        if "aarch64" in machine or "arm64" in machine:
            return "linux-arm64"
        return "linux-x86_64"
    return f"{system}-{machine}"


def _same_bytes(a: Path, b: Path) -> bool:
    """True when both files exist and hold identical bytes."""
    try:
        return a.is_file() and b.is_file() and a.read_bytes() == b.read_bytes()
    except OSError:
        return False


def _whids_files_to_stage(install_dir: Path, whids_dir: Path,
                          exe_src: Path | None = None) -> dict[Path, Path]:
    """Target -> bundled source map for one converged WHIDS install.

    The map is built from the bundle, never from what is already installed,
    so a stale config.toml or a missing baseline rule cannot survive an
    upgrade (both were field-found on WS1/WS2 in v1.5.0).
    """
    wanted = {}
    if exe_src is not None:
        wanted[install_dir / "whids.exe"] = exe_src
    for name in ("whids.toml", "plasma-iocs.gen", "LICENSE"):
        src = whids_dir / name
        if src.exists():
            wanted[install_dir / name] = src
    # v1.7.0 loads config.toml next to the binary.
    if (whids_dir / "whids.toml").exists():
        wanted[install_dir / "config.toml"] = whids_dir / "whids.toml"
    rules_db = install_dir / "Database" / "Rules"
    for name in whids.RULE_FILES:
        src = whids_dir / name
        if src.exists():
            wanted[rules_db / name] = src
    return wanted


def _materialize_gzip(gz: Path, name: str) -> Path:
    """Decompress an embedded executable to a writable runtime directory.

    Native binaries are stored gzipped because PyInstaller rewrites Mach-O/PE
    payloads it recognises, which would invalidate the frozen manifest. As
    opaque .gz data they stay byte-identical; we unpack them here.
    """
    import gzip
    import tempfile

    base = Path(getattr(sys, "_MEIPASS", tempfile.gettempdir())) / "plasma-runtime"
    base.mkdir(parents=True, exist_ok=True)
    out = base / name
    if not out.exists() or out.stat().st_size == 0:
        with gzip.open(gz, "rb") as src, open(out, "wb") as dst:
            shutil.copyfileobj(src, dst)
        if os.name != "nt":
            out.chmod(0o755)
    return out


def _locate_tap_rules() -> Path | None:
    """Bundled tap rules (embedded in the frozen exe, or the repo checkout)."""
    embedded = _embedded_root()
    if embedded:
        p = embedded / "sensors" / "plasma-tap-rules.json"
        if p.exists():
            return p
    dev = Path(__file__).resolve().parent.parent / "sensors" / "plasma-tap-rules.json"
    return dev if dev.exists() else None


def _locate_tap_exe() -> Path | None:
    """The krabsetw sidecar: embedded (materialized on demand), dev build, or PATH."""
    embedded = _embedded_root()
    if embedded:
        gz = embedded / "sensors" / "tap" / "plasma-tap.exe.gz"
        if gz.exists():
            return _materialize_gzip(gz, "plasma-tap.exe")
    dev = Path(__file__).resolve().parent.parent / "sensors" / "tap" / (
        "plasma-tap.exe" if os.name == "nt" else "plasma-tap")
    if dev.exists():
        return dev
    found = shutil.which("plasma-tap.exe") or shutil.which("plasma-tap")
    return Path(found) if found else None


def _engine_from_dir(directory: Path) -> Path | None:
    for name in _engine_names():
        candidate = directory / name
        if candidate.is_file():
            return candidate
    gz = directory / "needle.gz"
    if gz.is_file():
        return _materialize_gzip(gz, "needle.exe" if os.name == "nt" else "needle")
    return None


def _find_engine(bundle: str | None, explicit: str | None) -> Path | None:
    if explicit and Path(explicit).is_file():
        return Path(explicit)
    env = os.environ.get("PLASMA_ENGINE")
    if env and Path(env).is_file():
        return Path(env)

    directories = []
    embedded = _embedded_root()
    if embedded is not None:
        directories.append(embedded / "engines" / _current_platform())
        directories += [p for p in sorted((embedded / "engines").glob("*")) if p.is_dir()]
    if bundle not in (None, "", "embedded"):
        root = Path(bundle) / "engines"
        if root.is_dir():
            directories.append(root / _current_platform())
            directories += [p for p in sorted(root.iterdir()) if p.is_dir()]
    for directory in directories:
        engine = _engine_from_dir(directory)
        if engine is not None:
            return engine
    return None


def _find_model(bundle: str | None, engine: Path | None, explicit: str | None) -> Path | None:
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    env = os.environ.get("PLASMA_MODEL")
    if env:
        candidates.append(Path(env))
    if engine:
        candidates += [engine.parent / "needle3.cact", engine.parent / "neuralOS.engine"]
    embedded = _embedded_root()
    if embedded is not None:
        candidates += [
            embedded / "engines" / _current_platform() / "needle3.cact",
            embedded / "needle3.cact",
        ]
    if bundle not in (None, "", "embedded"):
        candidates += [
            Path(bundle) / "engines" / _current_platform() / "needle3.cact",
            Path(bundle) / "needle3.cact",
        ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _run_bridge(bundle: str | None, tool: str, args: dict, events: str | None) -> dict:
    inst = _instance_dir(bundle)
    payload = json.dumps(args or {}, separators=(",", ":"))
    py_bridge = inst / "bridge.py"
    ps_bridge = inst / "bridge.ps1"
    if _frozen():
        # A one-file executable contains Python + Pydantic; re-enter itself
        # through the hidden `_bridge` subcommand instead of spawning python.
        cmd = [sys.executable, "_bridge", "--dir", str(inst), "--tool", tool, "--args", payload]
        if events:
            cmd += ["--events", events]
    elif py_bridge.exists():
        cmd = [sys.executable, str(py_bridge), "--tool", tool, "--args", payload]
        if events:
            cmd += ["--events", events]
    elif ps_bridge.exists():
        cmd = ["pwsh", "-NoProfile", "-File", str(ps_bridge), "-Tool", tool, "-ArgsJson", payload]
        if events:
            cmd += ["-EventsPath", events]
    else:
        return {"error": "no bridge found in bundle instance/"}
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, env=env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": f"bridge execution failed: {exc}"}
    if proc.returncode != 0 and not proc.stdout.strip():
        return {"error": f"bridge exited {proc.returncode}: {proc.stderr.strip()[:300]}"}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"error": "bridge returned non-JSON", "stdout": proc.stdout[:300]}


def cmd_manifest(args) -> int:
    if args.action == "create":
        m = create_manifest(args.dir, args.version)
        print(json.dumps({"ok": True, "files": m["file_count"], "version": m["version"]}, indent=2))
        return 0
    result = verify_manifest(args.dir)
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 2


def cmd_bundle(args) -> int:
    platforms = args.platform or None
    result = build_bundle(
        args.out, args.version, engines_dir=args.engines,
        platforms=platforms, whids_payload=args.whids_payload,
        binaries=args.binary, make_zip=not args.no_zip,
    )
    print(json.dumps(result, indent=2))
    return 0


def cmd_probe(args) -> int:
    try:
        payload = json.loads(args.args)
    except json.JSONDecodeError as exc:
        print(json.dumps({"error": f"bad --args JSON: {exc}"}))
        return 2
    result = _run_bridge(args.bundle, args.tool, payload, args.events)
    print(json.dumps(result, indent=2))
    return 0 if "error" not in result else 1


def cmd_ask(args) -> int:
    bundle = args.bundle or "embedded"
    engine = _find_engine(bundle, args.engine)
    if engine is None:
        print(json.dumps({
            "error": "selection engine not found",
            "hint": "pass --engine PATH or set PLASMA_ENGINE; the embedded build carries its engine",
        }, indent=2))
        return 2
    model = _find_model(bundle, engine, args.model)
    if model is None:
        print(json.dumps({"error": "weights not found (needle3.cact)"}, indent=2))
        return 2
    menu = _instance_dir(bundle) / "needle_menu.json"
    cmd = [str(engine), "--model", str(model), "--tools", str(menu), "--prompt", args.prompt]
    if args.system:
        cmd += ["--system", args.system]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"error": f"engine failed: {exc}"}, indent=2))
        return 2
    try:
        selected = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(json.dumps({"error": "engine returned non-JSON", "stdout": proc.stdout[:300],
                          "stderr": proc.stderr[:300]}, indent=2))
        return 2
    calls = selected.get("function_calls") or []
    if not calls:
        print(json.dumps({"prompt": args.prompt, "selection": selected, "result": None,
                          "note": "no probe selected"}, indent=2))
        return 0
    call = calls[0]
    result = _run_bridge(bundle, call["name"], call.get("arguments", {}), args.events)
    print(json.dumps({
        "prompt": args.prompt,
        "selection": {"probe": call["name"], "arguments": call.get("arguments", {}),
                      "confidence": selected.get("confidence")},
        "result": result,
    }, indent=2, default=str))
    return 0 if "error" not in result else 1


def cmd_status(args) -> int:
    bundle = args.bundle or "embedded"
    if bundle == "embedded":
        root = _embedded_root()
        if root is not None and (root / "manifest.json").exists():
            result = verify_manifest(root)
        else:
            result = {"ok": root is not None, "embedded": True,
                      "note": "no embedded manifest (development build)"}
        result["embedded"] = True
    else:
        result = verify_manifest(bundle)
    inst = _instance_dir(bundle)
    menu = inst / "needle_menu.json"
    probes = None
    try:
        probes = [p["name"] for p in json.loads(menu.read_text())]
    except (OSError, json.JSONDecodeError, KeyError):
        pass
    coverage = None
    py_bridge = inst / "bridge.py"
    if py_bridge.exists():
        if _frozen():
            cmd = [sys.executable, "_bridge", "--dir", str(inst), "--coverage"]
        else:
            cmd = [sys.executable, str(py_bridge), "--coverage"]
        if args.events:
            cmd += ["--events", args.events]
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60, env=env)
            coverage = json.loads(proc.stdout) if proc.stdout.strip() else None
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            coverage = None
    print(json.dumps({
        "bundle": str(Path(bundle).resolve()) if bundle != "embedded" else "embedded",
        "verified": result,
        "probes": probes,
        "coverage": coverage,
        "engine": str(_find_engine(bundle, None) or "not bundled"),
    }, indent=2))
    return 0 if result.get("ok") else 2


def _service_present(pattern: str) -> bool:
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             "Get-Service | Where-Object { $_.Name -like '" + pattern + "' -or "
             "$_.DisplayName -like '" + pattern + "' } | Select-Object -First 1 "
             "-ExpandProperty Name"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20,
        )
        return bool(proc.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        return False


# ---------------------------------------------------------------------------
# Intelligent WHIDS/Sysmon provisioning (v0.10.0)
#
# The installer incubates two paths and picks the right one at install time:
#   FULL   — WHIDS + Sysmon: WHIDS travels inside the signed bundle (no
#            internet needed); Sysmon cannot be redistributed (Microsoft
#            EULA), so with internet the installer downloads it from
#            Sysinternals and accepts the EULA via -accepteula on the
#            operator's behalf.
#   MINIMAL — no internet / download failure / operator opt-out: WHIDS and
#            Sysmon are skipped and the node still runs fully operational
#            (tap + identity + instance + drift + actuate + fleet). The
#            decision and its reason are recorded in config.json and the
#            install report; `observe attest` will surface the coverage gap.
# ---------------------------------------------------------------------------

SYSMON_BASELINE_CONFIG = (
    '<Sysmon schemaversion="4.90"><EventFiltering>'
    '<ProcessCreate onmatch="exclude"/>'
    '<FileCreateTime onmatch="exclude"/>'
    '<NetworkConnect onmatch="exclude"/>'
    '<ProcessTerminate onmatch="exclude"/>'
    '<ImageLoad onmatch="exclude"/>'
    '<FileCreate onmatch="exclude"/>'
    '<RegistryEvent onmatch="exclude"/>'
    '<DnsQuery onmatch="exclude"/>'
    # FileDelete is opt-in in Sysmon. Log deletions of executable/archive
    # artifacts only — enough for T1070.004 without flooding the channel.
    '<FileDelete onmatch="include">'
    '<TargetFilename condition="end with">.exe</TargetFilename>'
    '<TargetFilename condition="end with">.dll</TargetFilename>'
    '<TargetFilename condition="end with">.ps1</TargetFilename>'
    '<TargetFilename condition="end with">.bat</TargetFilename>'
    '<TargetFilename condition="end with">.cmd</TargetFilename>'
    '<TargetFilename condition="end with">.vbs</TargetFilename>'
    '<TargetFilename condition="end with">.js</TargetFilename>'
    '<TargetFilename condition="end with">.jse</TargetFilename>'
    '<TargetFilename condition="end with">.wsf</TargetFilename>'
    '<TargetFilename condition="end with">.hta</TargetFilename>'
    '<TargetFilename condition="end with">.scr</TargetFilename>'
    '<TargetFilename condition="end with">.msi</TargetFilename>'
    '<TargetFilename condition="end with">.zip</TargetFilename>'
    '<TargetFilename condition="end with">.7z</TargetFilename>'
    '<TargetFilename condition="end with">.rar</TargetFilename>'
    '</FileDelete>'
    '</EventFiltering></Sysmon>'
)
SYSMON_URLS = (
    "https://download.sysinternals.com/files/Sysmon.zip",
    "https://live.sysinternals.com/Sysmon64.exe",
)


def internet_available(prober=None, timeout: int = 5) -> bool:
    """Best-effort reachability probe for the Sysmon download source.
    `prober` is injectable for tests: callable(url) -> bool."""
    import urllib.request

    def _default(url: str) -> bool:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "plasma-installer"})
        urllib.request.urlopen(req, timeout=timeout)
        return True

    probe = prober or _default
    try:
        return bool(probe(SYSMON_URLS[0]))
    except Exception:  # noqa: BLE001 — unreachable source means "no internet"
        return False


def whids_install_decision(sysmon_present: bool, whids_present: bool,
                           payload_present: bool, skip_whids: bool,
                           internet_ok: bool = True,
                           sysmon_install_ok: bool | None = None) -> dict:
    """Pure decision: FULL (whids+sysmon) where feasible, MINIMAL otherwise.

    WHIDS cannot start without Sysmon, so "WHIDS present but Sysmon absent"
    is a broken state the installer must REPAIR (acquire Sysmon) rather than
    honor as already_present."""
    if skip_whids:
        return {"decision": "skipped", "degraded": True,
                "reason": "--skip-whids requested"}
    if sysmon_present:
        if whids_present:
            return {"decision": "already_present", "degraded": False}
        if not payload_present:
            return {"decision": "skipped", "degraded": True,
                    "reason": "no WHIDS payload in bundle"}
        return {"decision": "full", "degraded": False}
    # Sysmon absent: acquire it (repairing a WHIDS-without-Sysmon box too)
    if sysmon_install_ok is True:
        return {"decision": "full", "degraded": False,
                "sysmon": "installed at install time (EULA accepted via -accepteula)",
                "repair": whids_present}
    if sysmon_install_ok is False:
        return {"decision": "skipped", "degraded": True,
                "reason": ("Sysmon download/install failed — WHIDS present but "
                           "cannot start without Sysmon" if whids_present else
                           "Sysmon download/install failed")}
    if not internet_ok:
        return {"decision": "skipped", "degraded": True,
                "reason": "no internet: Sysmon cannot be downloaded and may not "
                          "be redistributed with Plasma"
                          + (" — WHIDS present but cannot start" if whids_present else "")}
    return {"decision": "attempt_sysmon_install", "degraded": False}


def _trace_status() -> str:
    """Record whether DTrace can be used on this node (never fails install)."""
    try:
        state = trace.check()
        if state.get("available") and state.get("enabled"):
            return "available"
        if state.get("available"):
            return "installed_not_enabled"
        return "unavailable"
    except Exception:  # noqa: BLE001 — capability detection is data
        return "unknown"


def _service_state_name(name: str) -> str:
    """Current service state as a plain string ('' when absent)."""
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
             f"(Get-Service -Name '{name}' -ErrorAction SilentlyContinue).Status"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
        return (proc.stdout or "").strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _try_install_sysmon(tools_dir: Path) -> tuple[bool, str]:
    """Download + install Sysmon with the baseline config. Windows only.
    Returns (ok, detail). EULA is accepted via -accepteula on behalf of the
    installing operator."""
    import io
    import time
    import urllib.request
    import zipfile

    target_exe = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Sysmon64.exe"
    last_err = ""
    for url in SYSMON_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "plasma-installer"})
            data = urllib.request.urlopen(req, timeout=120).read()
            if url.endswith(".zip"):
                zf = zipfile.ZipFile(io.BytesIO(data))
                member = next(n for n in zf.namelist() if n.endswith("Sysmon64.exe"))
                exe_bytes = zf.read(member)
            else:
                exe_bytes = data
            target_exe.write_bytes(exe_bytes)
            tools_dir.mkdir(parents=True, exist_ok=True)
            cfg = tools_dir / "sysmon-baseline.xml"
            cfg.write_text(SYSMON_BASELINE_CONFIG, encoding="ascii")
            subprocess.run(
                [str(target_exe), "-accepteula", "-i", str(cfg)],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300,
            )
            for _ in range(15):
                if _service_present("Sysmon*"):
                    return True, "Sysmon installed (EULA accepted via -accepteula)"
                time.sleep(2)
            return False, "Sysmon service did not appear within 30s"
        except Exception as exc:  # noqa: BLE001 — download failures are data
            last_err = f"{url}: {str(exc)[:160]}"
            continue
    return False, f"Sysmon download failed: {last_err}"


def _is_junction(path: Path) -> bool:
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             f"(Get-Item -LiteralPath '{path}' -Force).LinkType"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15,
        )
        return proc.stdout.strip().lower() in ("junction", "symboliclink")
    except (OSError, subprocess.TimeoutExpired):
        return False


def cmd_install(args) -> int:
    """Install the embedded payload on this Windows host (single-exe flow)."""
    if os.name != "nt":
        print(json.dumps({"error": "install is Windows-only; this build targets Windows x64"}))
        return 2
    embedded = _embedded_root()
    if embedded is None:
        print(json.dumps({
            "error": "install requires the embedded one-file build",
            "hint": "use the plasma-*-windows-x64.exe release artifact",
        }))
        return 2

    verification = verify_manifest(embedded)
    if not verification.get("ok"):
        print(json.dumps({"ok": False, "stage": "integrity", "verification": verification}, indent=2))
        return 2
    manifest = json.loads((embedded / "manifest.json").read_text(encoding="utf-8"))
    version = manifest["version"]

    default_root = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Plasma"
    root = Path(args.root) if args.root else default_root
    target = root / "instances" / f"plasma-{version}"
    current = root / "current"
    config_path = root / "config.json"
    events_path = Path(args.events) if args.events else root / "data" / "events.jsonl"

    whids_present = _service_present("Whids*")
    sysmon_present = _service_present("Sysmon*")
    whids_dir = embedded / "sensors" / "whids"
    whids_gz = whids_dir / "whids.exe.gz"

    # Intelligent WHIDS/Sysmon decision: FULL where feasible (auto-Sysmon
    # download + EULA acceptance when internet allows), MINIMAL otherwise.
    decision = whids_install_decision(sysmon_present, whids_present,
                                      whids_gz.exists(), args.skip_whids)
    if decision["decision"] == "attempt_sysmon_install":
        if args.skip_sysmon_check:
            decision = {"decision": "skipped", "degraded": True,
                        "reason": "--skip-sysmon-check: Sysmon download skipped"}
        elif not internet_available():
            decision = whids_install_decision(
                sysmon_present, whids_present, whids_gz.exists(),
                args.skip_whids, internet_ok=False)
        else:
            ok, detail = _try_install_sysmon(root / "tools")
            # re-decide with the ORIGINAL sysmon_present so the repair path
            # (Sysmon fixed on a WHIDS box) yields full/repair — passing the
            # updated flag would short-circuit to already_present and skip
            # the WHIDS (re)start entirely
            decision = whids_install_decision(
                sysmon_present, whids_present, whids_gz.exists(),
                args.skip_whids, sysmon_install_ok=ok)
            sysmon_present = sysmon_present or ok
            decision["sysmon_detail"] = detail
    # A present sensor is not a converged sensor: `install --force` re-stages
    # config and rules from the bundle instead of trusting whatever is on disk.
    whids_planned = decision["decision"] in ("full", "already_present")
    degraded = bool(decision.get("degraded"))
    whids_hung = False
    degradation_reason = None
    if degraded and getattr(args, "require_whids", False):
        print(json.dumps({"ok": False, "error": "WHIDS required but not feasible",
                          "decision": decision}, indent=2))
        return 3

    plan = {
        "ok": True,
        "dry_run": bool(args.dry_run),
        "version": version,
        "install_root": str(root),
        "target": str(target),
        "current": str(current),
        "config": str(config_path),
        "events_path": str(events_path),
        "files_verified": verification["checked"],
        "whids_present": whids_present,
        "sysmon_present": sysmon_present,
        "whids_will_install": bool(whids_planned),
        "whids_decision": decision,
        "degraded": degraded,
        "actions": [
            f"create {target}",
            "extract embedded instance + engines",
            f"copy {Path(sys.executable).name} to {root / 'bin'}",
            f"write {config_path}",
            f"point {current} -> {target}",
        ] + ([f"install Sysmon from Sysinternals (EULA accepted via -accepteula)"]
             if decision.get("sysmon") == "installed at install time (EULA accepted via -accepteula)" else [])
          + ([f"install or refresh WHIDS config/rules from embedded payload "
              f"(service '{whids.SERVICE_NAME}')"] if whids_planned else [])
          + ([f"MINIMAL MODE: {decision.get('reason')}"] if degraded else []),
    }
    if args.dry_run:
        print(json.dumps(plan, indent=2))
        return 0

    # 1. Stage the version.
    if target.exists() and not args.force:
        print(json.dumps({"ok": False, "error": f"target exists: {target} (use --force)"}, indent=2))
        return 4
    target.mkdir(parents=True, exist_ok=True)
    for sub in ("instance", "engines", "sensors"):
        src = embedded / sub
        if src.is_dir():
            shutil.copytree(src, target / sub, dirs_exist_ok=True)
    bindir = root / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    me = Path(sys.executable)
    shutil.copy2(me, bindir / me.name)

    # 2. Config — sensor state reflects the ACTUAL decision, not hopes.
    config = {
        "product": "Plasma",
        "version": version,
        "instance": str(target),
        "events_path": str(events_path),
        "retention_days": 7,
        "response": {"mode": "advisory", "require_human_approval": True},
        "degraded": degraded,
        "sensors": {
            "whids": {"required": False, "min_version": "1.7.0",
                      "status": ("active" if whids_present else
                                 "installing" if whids_planned else "skipped"),
                      "reason": decision.get("reason")},
            "sysmon": {"required": False,
                       "status": ("active" if sysmon_present else "absent")},
            "tap": {"required": True, "mode": "on-demand",
                    "providers": "powershell,wmi,dns,dotnet,schannel,security"},
            "trace": {"required": False, "mode": "on-demand",
                      "status": (_trace_status())},
            "identity": {"required": True, "mode": "on-demand"},
            "sealighter": {"required": False, "mode": "on-demand"},
        },
    }
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

    # 3. WHIDS (materialize, configure, register service, fail closed).
    # v1.7.0 has no `-install` verb: the agent is service-less by design and
    # its default config path is `<dir>\config.toml`. Registration goes
    # through the SCM (New-Service) with failure-restart recovery.
    if whids_planned:
        install_dir = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Whids"
        install_dir.mkdir(parents=True, exist_ok=True)
        exe = install_dir / "whids.exe"
        whids_exe_gz = _materialize_gzip(whids_gz, "whids.exe")
        rules_db = install_dir / "Database" / "Rules"

        # What a converged install looks like, target -> bundled source.
        # config.toml is always rewritten: a field upgrade left a stale Whids
        # default config (crash loop) and an old compact Plasma config (wrong
        # channels) in place on live nodes.
        wanted = _whids_files_to_stage(install_dir, whids_dir, whids_exe_gz)

        drift = [str(dst) for dst, src in wanted.items()
                 if not _same_bytes(dst, src)]
        was_running = _service_state_name("Whids") == "Running"
        prev_config = install_dir / "config.toml.plasma-prev"
        if was_running and not drift:
            # Already converged: don't disturb a healthy sensor on reinstall.
            pass
        else:
            if _service_present("Whids*"):
                subprocess.run(
                    ["powershell.exe", "-NoProfile", "-Command",
                     "Stop-Service -Name 'Whids' -Force -ErrorAction SilentlyContinue"],
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=60,
                )
                deadline = __import__("time").time() + 30
                while (_service_state_name("Whids") == "Running"
                       and __import__("time").time() < deadline):
                    __import__("time").sleep(1)
            if (install_dir / "config.toml").exists():
                shutil.copy2(install_dir / "config.toml", prev_config)
            for dst, src in wanted.items():
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
            # baseline + IOC rules both belong in the engine's database;
            # copying only the IOC file left live nodes loading 1-2 rules.
            whids.deploy_rules(whids_dir, rules_db)
            # Directories the config points at must exist before the first
            # cleanup/dump cycle, or the sensor logs errors it never explains.
            for sub in ("Sysmon",):
                (Path(os.environ.get("SystemDrive", "C:") + "\\") / sub).mkdir(
                    parents=True, exist_ok=True)
            for sub in ("Logs", "Dumps"):
                (install_dir / sub).mkdir(parents=True, exist_ok=True)

        bin_path = f'"{exe}" -c "{install_dir}\\config.toml"'
        if not _service_present("Whids*"):
            try:
                setup_proc = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-Command",
                     f"New-Service -Name Whids -BinaryPathName '{bin_path}' "
                     f"-DisplayName 'WHIDS (Plasma sensor)' -StartupType Automatic | Out-Null; "
                     f"sc.exe failure Whids reset= 9999 actions= restart/5000 | Out-Null"],
                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                print(json.dumps({"ok": False, "stage": "whids_install", "error": str(exc)[:300]}, indent=2))
                return 3
            if setup_proc.returncode != 0 or _service_present("Whids*") is False:
                print(json.dumps({
                    "ok": False, "stage": "whids_install",
                    "error": "New-Service registration failed",
                    "stderr": (setup_proc.stderr or setup_proc.stdout or "")[:300],
                }, indent=2))
                return 3
        deadline = __import__("time").time() + 60
        while not _service_present("Whids*") and __import__("time").time() < deadline:
            __import__("time").sleep(2)
        if not _service_present("Whids*"):
            print(json.dumps({"ok": False, "stage": "whids_install",
                              "error": "WHIDS service did not appear within 60s"}, indent=2))
            return 3
        wait_s = int(os.environ.get("PLASMA_WHIDS_START_TIMEOUT", "60"))
        if was_running and not drift:
            whids_state = "Running"
        else:
            try:
                subprocess.run(
                    ["powershell.exe", "-NoProfile", "-Command",
                     "Start-Service -Name 'Whids' -ErrorAction Stop"],
                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass

            # Supervised start. WHIDS 1.7.0 can sit in StartPending forever on
            # some Server 2022 builds (field issue). Wait boundedly; if it
            # never reaches Running, try the previous config once, then
            # force-stop and record a documented MINIMAL posture.
            whids_state = _service_state_name("Whids")
            deadline = __import__("time").time() + wait_s
            while (whids_state in ("StartPending", "Stopping", "Unknown", "")
                   and __import__("time").time() < deadline):
                __import__("time").sleep(3)
                whids_state = _service_state_name("Whids")
            if whids_state != "Running" and prev_config.exists():
                shutil.copy2(prev_config, install_dir / "config.toml")
                subprocess.run(
                    ["powershell.exe", "-NoProfile", "-Command",
                     "Start-Service -Name 'Whids' -ErrorAction SilentlyContinue"],
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=60,
                )
                deadline = __import__("time").time() + 30
                whids_state = _service_state_name("Whids")
                while (whids_state in ("StartPending", "Stopping", "Unknown", "")
                       and __import__("time").time() < deadline):
                    __import__("time").sleep(3)
                    whids_state = _service_state_name("Whids")
                if whids_state == "Running":
                    config["sensors"]["whids"]["config_rollback"] = (
                        "bundled config failed to start; previous config restored")
                    config_path.write_text(json.dumps(config, indent=2) + "\n",
                                           encoding="utf-8")
        if whids_state != "Running":
            subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command",
                 "Stop-Service -Name 'Whids' -Force -ErrorAction SilentlyContinue"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
            )
            whids_hung = True
            degradation_reason = (f"WHIDS start timeout ({wait_s}s, state "
                                  f"{whids_state or 'unknown'}) — stopped and "
                                  f"marked skipped; run `plasma whids diagnose`")
            degraded = True
            config["degraded"] = True
            config["sensors"]["whids"].update(
                {"status": "skipped", "reason": degradation_reason})
            config_path.write_text(json.dumps(config, indent=2) + "\n",
                                   encoding="utf-8")

    # 4. Flip current (only replace an existing link).
    # _is_junction is checked unconditionally: a DANGLING junction (target
    # deleted by hand) reports exists()=False and is_symlink()=False, yet a
    # New-Item against the reparse point would still explode.
    if current.exists() or current.is_symlink() or _is_junction(current):
        if not (_is_junction(current) or args.force):
            print(json.dumps({"ok": False, "stage": "current",
                              "error": f"{current} exists and is not a link"}, indent=2))
            return 4
        # PS5.1's Remove-Item hangs non-interactively on reparse points;
        # a junction is removed with its own single-purpose verb instead.
        subprocess.run(
            ["cmd.exe", "/c", "rmdir", str(current)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20,
        )
        if current.exists() or _is_junction(current):
            print(json.dumps({"ok": False, "stage": "current",
                              "error": f"could not replace link {current} "
                                       "(remove it manually and re-run)"}, indent=2))
            return 4
    try:
        subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             f"New-Item -ItemType Junction -Path '{current}' -Target '{target}' | Out-Null"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
            check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        print(json.dumps({"ok": False, "stage": "current",
                          "error": f"junction creation failed: {exc}"}, indent=2))
        return 4

    print(json.dumps({
        "ok": True,
        "installed": str(target),
        "current": str(current),
        "config": str(config_path),
        "whids_installed": (whids_planned or whids_present) and not whids_hung,
        "degraded": degraded,
        "degradation_reason": degradation_reason,
        "files_verified": verification["checked"],
    }, indent=2))
    return 0


def cmd_whids_pull(args) -> int:
    result = whids.pull(args.root, args.out, args.host)
    print(json.dumps(result, indent=2))
    return 0 if "error" not in result else 1


def cmd_whids_push(args) -> int:
    result = whids.push(
        events_path=args.events, root=args.root,
        min_confidence=args.min_confidence, max_indicators=args.max_indicators,
        apply=args.apply, restart_service=args.restart_service, reason=args.reason,
    )
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 1


def cmd_whids_status(args) -> int:
    print(json.dumps(whids.status(args.root, args.events), indent=2))
    return 0


def _canaries(args):
    return tuple(args.canary) if getattr(args, "canary", None) else ()


def cmd_observe(args) -> int:
    answer = observatory.run_question(args.question, canaries=_canaries(args))
    print(json.dumps(answer, indent=2, default=str))
    print(observatory.summarize(answer), file=sys.stderr)
    return 0 if "error" not in answer else 1


def cmd_drift_record(args) -> int:
    answer = observatory.run_question(args.question, canaries=_canaries(args))
    result = drift.record(args.root, args.question, answer)
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 1


def cmd_drift_score(args) -> int:
    answer = observatory.run_question(args.question, canaries=_canaries(args))
    result = drift.score(args.root, args.question, answer)
    print(json.dumps(result, indent=2, default=str))
    if "error" in result:
        return 1
    return 0 if result.get("top_score", 0) == 0 else 2


def cmd_drift_list(args) -> int:
    rows = drift.baselines(args.root)
    print(json.dumps({"root": str(args.root), "baselines": rows}, indent=2))
    return 0


def cmd_actuate_actions(args) -> int:
    print(json.dumps(actuate.actions(), indent=2))
    return 0


def cmd_actuate_apply(args) -> int:
    result = actuate.execute(
        args.action, args.root, target=args.target, reason=args.reason,
        apply=args.apply, timeout=args.timeout, plan=args.plan)
    print(json.dumps(result, indent=2, default=str))
    # dry-runs succeed by definition; applied actions report via "error"/rc
    if "error" in result:
        return 1
    if args.apply:
        run = result.get("result") or {}
        if run.get("error") or run.get("rc") not in (None, 0):
            return 3
        ver = result.get("verification") or {}
        if isinstance(ver, dict) and (ver.get("error") or
                                      ver.get("rc") not in (None, 0)):
            return 3
    return 0


def cmd_actuate_journal(args) -> int:
    rows = actuate.journal_read(args.root, last=args.last)
    print(json.dumps(rows, indent=2, default=str))
    return 0


def cmd_actuate_undo(args) -> int:
    result = actuate.undo(args.root, args.id, apply=args.apply, timeout=args.timeout)
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 1


def cmd_chain_score(args) -> int:
    result = chain.scan_store(args.events, max_rows=args.max_rows,
                              gap_seconds=args.window)
    print(json.dumps(result, indent=2, default=str))
    if "error" in result:
        return 1
    return 0 if result.get("top_score", 0) == 0 else 2


def cmd_coverage(args) -> int:
    try:
        result = coverage.coverage(args.sensors)
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"error": str(exc)[:300]}, indent=2))
        return 1
    print(json.dumps(result, indent=2, default=str))
    return 0


def cmd_store_rotate(args) -> int:
    result = store.rotate(args.events, max_mb=args.max_mb, keep=args.keep)
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 1


def cmd_store_compact(args) -> int:
    result = store.compact(args.events, out_path=args.out)
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 1


def cmd_store_stats(args) -> int:
    result = store.stats(args.events)
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 1


def cmd_deep_persistence(args) -> int:
    result = deep.run(out=args.json_out, cap=args.cap)
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 1


def cmd_playbook_list(args) -> int:
    print(json.dumps(playbooks.actions(), indent=2))
    return 0


def cmd_playbook_apply(args) -> int:
    result = playbooks.execute(args.root, args.name, target=args.target,
                               reason=args.reason, apply=args.apply,
                               plan=args.plan, timeout=args.timeout)
    print(json.dumps(result, indent=2, default=str))
    if "error" in result:
        return 1
    if args.apply:
        if result.get("aborted_at"):
            return 3
        for s in result.get("steps", []):
            if s.get("ok") is False:
                return 3
    return 0


def cmd_playbook_undo(args) -> int:
    result = playbooks.undo(args.root, args.id, apply=args.apply,
                            timeout=args.timeout)
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 1


def cmd_trace_list(args) -> int:
    try:
        scripts = trace.load_scripts(args.root)
    except (FileNotFoundError, trace.ScriptError) as exc:
        print(json.dumps({"error": str(exc)[:300]}, indent=2))
        return 1
    print(json.dumps(scripts, indent=2))
    return 0


def cmd_trace_check(args) -> int:
    result = trace.check()
    print(json.dumps(result, indent=2, default=str))
    return 0


def cmd_trace_selftest(args) -> int:
    result = trace.selftest(args.root)
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


def cmd_trace_run(args) -> int:
    try:
        seconds = tap.parse_duration(args.for_)
    except ValueError as exc:
        print(json.dumps({"error": str(exc)}, indent=2))
        return 2
    try:
        result = trace.run(args.script, args.events, seconds=seconds,
                           max_rows=args.max_rows, out=args.out,
                           root=args.root, host=args.host)
    except (FileNotFoundError, trace.ScriptError) as exc:
        print(json.dumps({"error": str(exc)[:300]}, indent=2))
        return 1
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 1


def cmd_trace_provision(args) -> int:
    result = trace.provision()
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("ok") else 1


def cmd_whids_diagnose(args) -> int:
    result = whids.diagnose(args.root)
    print(json.dumps(result, indent=2, default=str))
    return 0


def cmd_canary_deploy(args) -> int:
    result = canary.deploy(args.root, extra_dirs=args.dir)
    print(json.dumps(result, indent=2, default=str))
    return 0


def cmd_canary_verify(args) -> int:
    result = canary.verify(args.root)
    print(json.dumps(result, indent=2, default=str))
    if "error" in result:
        return 1
    return 2 if result.get("tripped") else 0


def cmd_canary_status(args) -> int:
    try:
        result = canary.status(args.root)
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)[:200]}, indent=2))
        return 1
    print(json.dumps(result, indent=2, default=str))
    return 0


def cmd_tap_list(args) -> int:
    rules_path = _locate_tap_rules()
    info = {
        "providers": tap.TAP_PROVIDER_ALIASES,
        "rules_file": str(rules_path) if rules_path else None,
        "rule_count": len(tap.load_rules(rules_path)) if rules_path else 0,
        "tap_exe": str(_locate_tap_exe() or "") or None,
        "default_providers": "powershell,wmi,dns",
        "ethos": "on-demand window, in-memory scoring, matches-only output",
    }
    print(json.dumps(info, indent=2))
    return 0


def cmd_tap_selftest(args) -> int:
    rules_path = Path(args.rules) if args.rules else _locate_tap_rules()
    if not rules_path or not rules_path.exists():
        print(json.dumps({"error": "tap rules file not found"}))
        return 1
    try:
        tap.load_rules(rules_path)
    except (ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": f"tap rules invalid: {exc}"}, indent=2))
        return 2
    exe = Path(args.tap_exe) if args.tap_exe else _locate_tap_exe()
    if not exe or not Path(exe).exists():
        print(json.dumps({"error": "plasma-tap.exe not available",
                          "hint": "compile it (tap/README.md) or use a release bundle"}))
        return 1
    import tempfile
    rules_txt = Path(tempfile.mkdtemp()) / "plasma-tap-rules.txt"
    tap.build_rules_txt(tap.load_rules(rules_path), rules_txt)
    result = tap.selftest(exe, rules_txt)
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


def cmd_tap_run(args) -> int:
    try:
        seconds = tap.parse_duration(args.for_)
    except ValueError as exc:
        print(json.dumps({"error": str(exc)}, indent=2))
        return 2
    providers = [p.strip() for p in args.providers.split(",") if p.strip()]
    unknown = [p for p in providers if p not in tap.TAP_PROVIDER_ALIASES]
    if unknown:
        print(json.dumps({"error": f"unknown providers: {unknown}",
                          "providers": sorted(tap.TAP_PROVIDER_ALIASES)}, indent=2))
        return 1
    rules_path = Path(args.rules) if args.rules else _locate_tap_rules()
    if not rules_path or not rules_path.exists():
        print(json.dumps({"error": "tap rules file not found"}))
        return 1
    exe = Path(args.tap_exe) if args.tap_exe else _locate_tap_exe()
    if not exe or not Path(exe).exists():
        print(json.dumps({"error": "plasma-tap.exe not available",
                          "hint": "compile it (tap/README.md) or use a release bundle"}))
        return 1
    if args.out_dir:
        out_dir = Path(args.out_dir)
    elif os.name == "nt":
        out_dir = Path(os.environ.get("ProgramData", ".")) / "Plasma" / "tap"
    else:
        out_dir = Path.cwd() / "plasma-tap"
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        rules = tap.load_rules(rules_path)
    except (ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": f"tap rules invalid: {exc}"}, indent=2))
        return 2
    rules_txt = out_dir / "plasma-tap-rules.txt"
    tap.build_rules_txt(rules, rules_txt)
    st = tap.selftest(exe, rules_txt)
    if not st.get("ok"):
        print(json.dumps({"error": "tap selftest failed", "selftest": st}, indent=2))
        return 1

    matches = out_dir / "matches.jsonl"
    summary = tap.run(exe, providers, seconds, matches, rules_txt,
                      max_matches=args.max_matches)
    result = {
        "providers": providers,
        "window_seconds": seconds,
        "rules": len(rules),
        "matches_file": str(matches),
        "summary": summary,
    }
    if args.events:
        result["collected"] = tap.collect(matches, args.events,
                                          host=_platform.node() or "localhost")
    print(json.dumps(result, indent=2, default=str))
    if not summary.get("ok"):
        return 1
    if summary.get("rc") != 0:
        return 3
    return 0


def cmd_tap_collect(args) -> int:
    result = tap.collect(args.matches, args.events,
                         host=args.host or _platform.node() or "localhost")
    print(json.dumps(result, indent=2))
    return 0 if "error" not in result else 1


def cmd_health(args) -> int:
    result = health.verdict(args.root)
    print(json.dumps(result, indent=2, default=str))
    return 0 if result["status"] == "ok" else 2 if result["status"] == "down" else 1


def cmd_watch_once(args) -> int:
    result = watch.watch_once(args.root, quiet_clean=not args.notify_clean)
    print(json.dumps({k: v for k, v in result.items() if k != "notify"}, indent=2, default=str))
    n = result.get("notify")
    if n is not None:
        print(json.dumps({"notify": n}, indent=2))
    return 0 if result["top_score"] == 0 else 2


def cmd_watch_loop(args) -> int:
    import time as _time
    while True:
        result = watch.watch_once(args.root, quiet_clean=True)
        print(json.dumps({"at": result["at"], "verdict": result["verdict"],
                          "top_score": result["top_score"]}, default=str))
        _time.sleep(args.every)


def cmd_notify_test(args) -> int:
    result = notify.notify_all(args.root, "Plasma notify test",
                               f"delivery check from {args.host or _platform.node()}")
    print(json.dumps(result, indent=2))
    return 0 if result["configured"] and result["sent"] == result["configured"] else 1


def cmd_notify_show(args) -> int:
    try:
        cfg = notify.load_config(args.root)
    except (ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": f"notify config invalid: {exc}"}, indent=2))
        return 2
    print(json.dumps({"channels": len(cfg["channels"]),
                      "types": [ch.get("type") for ch in cfg["channels"]],
                      "min_score": cfg["min_score"]}, indent=2))
    return 0


def cmd_update_check(args) -> int:
    # public repo: anonymous works; a token is optional (private forks)
    token = os.environ.get(args.token_env, "")
    rel = updater.latest_release(args.repo, token)
    newer = updater.is_newer(__version__, rel["tag"])
    print(json.dumps({"current": __version__, "latest": rel["tag"], "update_available": newer},
                     indent=2))
    return 2 if newer else 0   # scriptable: 0 = up to date, 2 = update available


def cmd_update_apply(args) -> int:
    # public repo: anonymous works; a token is optional (private forks)
    token = os.environ.get(args.token_env, "")
    root = Path(args.root)
    staged = root / "tools" / "plasma-update-staged.exe"
    res = updater.download_and_verify(args.repo, "", token, staged)
    print(json.dumps({"stage": "download", **{k: v for k, v in res.items() if k != 'ok'}}, indent=2, default=str))
    if not res["ok"]:
        return 1
    # SECOND trust anchor: the exe must be signed by a pinned certificate
    # before we execute it. SHA256SUMS + exe share one origin (the release);
    # the signer thumbprint is baked into THIS binary.
    sig = updater.verify_authenticode(staged)
    print(json.dumps({"stage": "signature", **sig}, indent=2, default=str))
    if not sig.get("ok") and not getattr(args, "allow_unsigned", False):
        print(json.dumps({"ok": False,
                          "error": "refusing to execute an update with an unverified signer",
                          "hint": "dev builds may pass --allow-unsigned"},
                         indent=2))
        return 2
    # forward the root: a node installed at a custom root must not have its
    # new version configured under the default location (split-brain install)
    inst = subprocess.run([str(staged), "install", "--force", "--root", str(root)],
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)
    print(inst.stdout[-800:] if inst.stdout else "")
    if inst.returncode != 0:
        print(inst.stderr[-400:], file=sys.stderr)
        return 3
    bin_exe = Path(args.bin) if args.bin else root / "bin" / Path(sys.executable).name
    rot = updater.rotate_bin(staged, bin_exe)
    print(json.dumps({"stage": "bin_rotation", **rot}, indent=2, default=str))
    print(json.dumps({"ok": True, "updated_to": res.get("tag")}, indent=2))
    return 0


def cmd_identity_pull(args) -> int:
    result = identity.pull(args.events, host=args.host or _platform.node() or "localhost",
                           since_minutes=args.since)
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 1


def cmd_fleet_pull(args) -> int:
    try:
        result = fleet.pull(args.root, args.inventory, args.case,
                            cap=args.cap, window_seconds=args.window,
                            canaries=args.canary or None)
    except (ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)[:300],
                          "hint": "check --inventory json"}, indent=2))
        return 2
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("pulled") == result.get("hosts") else 1


def cmd_fleet_correlate(args) -> int:
    result = fleet.correlate(args.root, args.case, window_seconds=args.window)
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("top_score", 0) == 0 and "error" not in result else 2


def cmd_fleet_report(args) -> int:
    result = fleet.report(args.root, args.case)
    if "error" not in result:
        print(result["markdown"])
        print(f"[report written: {result['report']}]", file=sys.stderr)
        return 0
    print(json.dumps(result, indent=2))
    return 1


def cmd_fleet_scan(args) -> int:
    pulled = fleet.pull(args.root, args.inventory, args.case,
                        cap=args.cap, window_seconds=args.window,
                        canaries=args.canary or None)
    print(json.dumps({"stage": "pull", **pulled}, indent=2, default=str))
    if pulled.get("pulled", 0) == 0:
        return 1
    correlated = fleet.correlate(args.root, args.case, window_seconds=args.window)
    print(json.dumps({"stage": "correlate", **correlated}, indent=2, default=str))
    if "error" in correlated:
        return 1
    reported = fleet.report(args.root, args.case)
    print(json.dumps({"stage": "report", **{
        k: v for k, v in reported.items() if k != "markdown"}}, indent=2))
    print(reported.get("markdown", ""), file=sys.stderr)
    return 0 if correlated.get("top_score", 0) == 0 else 2


def cmd_internal_bridge(args) -> int:
    """Hidden entry point used by the frozen executable (`plasma _bridge`)."""
    import importlib.util

    inst = Path(args.dir)
    bridge_file = inst / "bridge.py"
    if not bridge_file.exists():
        print(json.dumps({"error": f"bridge not found: {bridge_file}"}))
        return 2
    if args.events:
        os.environ["PLASMA_EVENTS"] = args.events
    sys.path.insert(0, str(inst))
    try:
        spec = importlib.util.spec_from_file_location("plasma_frozen_bridge", bridge_file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if args.coverage:
            result = module.coverage()
        else:
            result = module.run_tool(args.tool, json.loads(args.args))
    except Exception as exc:  # noqa: BLE001 - errors are data
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"[:300]}))
        return 1
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="plasma", description="Plasma EDR bundle tooling")
    p.add_argument("--version", action="version", version=f"plasma {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    m = sub.add_parser("manifest", help="create or verify a bundle manifest")
    m.add_argument("action", choices=["create", "verify"])
    m.add_argument("--dir", required=True)
    m.add_argument("--version", default=__version__)
    m.set_defaults(func=cmd_manifest)

    b = sub.add_parser("bundle", help="build a deployable bundle")
    bs = b.add_subparsers(dest="action", required=True)
    bb = bs.add_parser("build")
    bb.add_argument("--out", default="dist")
    bb.add_argument("--version", default=__version__)
    bb.add_argument("--engines", default=None, help="directory of <platform>/ engine bundles")
    bb.add_argument("--platform", action="append", default=None)
    bb.add_argument("--whids-payload", default=None,
                    help="directory with the WHIDS payload (whids.exe, LICENSE)")
    bb.add_argument("--binary", action="append", default=None,
                    help="Plasma executable to include under bin/ (repeatable)")
    bb.add_argument("--no-zip", action="store_true")
    bb.set_defaults(func=cmd_bundle)

    pr = sub.add_parser("probe", help="execute one frozen probe")
    pr.add_argument("--bundle", default=None, help="bundle directory (default: embedded)")
    pr.add_argument("--tool", required=True)
    pr.add_argument("--args", default="{}")
    pr.add_argument("--events", default=None)
    pr.set_defaults(func=cmd_probe)

    a = sub.add_parser("ask", help="select a probe with the engine and execute it")
    a.add_argument("--bundle", default=None, help="bundle directory (default: embedded)")
    a.add_argument("--prompt", required=True)
    a.add_argument("--engine", default=None)
    a.add_argument("--model", default=None)
    a.add_argument("--system", default=None)
    a.add_argument("--events", default=None)
    a.set_defaults(func=cmd_ask)

    s = sub.add_parser("status", help="verify a bundle and report coverage")
    s.add_argument("--bundle", default=None, help="bundle directory (default: embedded)")
    s.add_argument("--events", default=None)
    s.set_defaults(func=cmd_status)

    ins = sub.add_parser("install", help="install the embedded payload on this Windows host")
    ins.add_argument("--root", default=None, help="install root (default: C:\\ProgramData\\Plasma)")
    ins.add_argument("--events", default=None, help="event store path")
    ins.add_argument("--dry-run", action="store_true")
    ins.add_argument("--skip-whids", action="store_true",
                     help="force MINIMAL mode: no WHIDS/Sysmon (tap+identity remain)")
    ins.add_argument("--skip-sysmon-check", action="store_true",
                     help="do not attempt the Sysmon download (forces MINIMAL if Sysmon absent)")
    ins.add_argument("--require-whids", action="store_true",
                     help="fail closed when WHIDS/Sysmon are not feasible (old strict behavior)")
    ins.add_argument("--force", action="store_true")
    ins.set_defaults(func=cmd_install)

    sn = sub.add_parser("whids", help="WHIDS integration: pull alerts, push IOC gene rules")
    sns = sn.add_subparsers(dest="whids_action", required=True)

    sp = sns.add_parser("pull", help="normalize WHIDS alerts into the Plasma event store")
    sp.add_argument("--root", default=None, help="WHIDS install root (default: C:\\Program Files\\Whids)")
    sp.add_argument("--out", default=None)
    sp.add_argument("--host", default=None)
    sp.set_defaults(func=cmd_whids_pull)

    spu = sns.add_parser("push", help="push high-confidence indicators as a WHIDS gene rule")
    spu.add_argument("--root", default=None)
    spu.add_argument("--events", default=None)
    spu.add_argument("--min-confidence", type=int, default=whids.DEFAULT_MIN_CONFIDENCE,
                     help="criticality threshold on the gene 0-10 scale (default 8)")
    spu.add_argument("--max-indicators", type=int, default=whids.DEFAULT_MAX_INDICATORS)
    spu.add_argument("--reason", default="")
    spu.add_argument("--restart-service", action="store_true")
    spu.add_argument("--apply", action="store_true", help="write the rule file (default is dry-run)")
    spu.set_defaults(func=cmd_whids_push)

    sps = sns.add_parser("status", help="show WHIDS + Plasma integration state")
    sps.add_argument("--root", default=None)
    sps.add_argument("--events", default=None)
    sps.set_defaults(func=cmd_whids_status)

    spd = sns.add_parser("diagnose", help="explain why a WHIDS service is not Running")
    spd.add_argument("--root", default=None, help="WHIDS install root (default: C:\\Program Files\\Whids)")
    spd.set_defaults(func=cmd_whids_diagnose)

    cn = sub.add_parser("canary", help="decoys for impact detection (T1486)")
    cns = cn.add_subparsers(dest="canary_action", required=True)
    cnd = cns.add_parser("deploy", help="create canary files and record their hashes")
    cnd.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cnd.add_argument("--dir", action="append", default=[],
                     help="extra directory for canaries (repeatable)")
    cnd.set_defaults(func=cmd_canary_deploy)
    cnv = cns.add_parser("verify", help="check canaries (exit 2 when tripped)")
    cnv.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cnv.set_defaults(func=cmd_canary_verify)
    cnsx = cns.add_parser("status", help="manifest + current canary state")
    cnsx.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cnsx.set_defaults(func=cmd_canary_status)

    tr = sub.add_parser("trace", help="DTrace on-demand kernel tracing (bounded, reviewed scripts)")
    trs = tr.add_subparsers(dest="trace_action", required=True)
    trl = trs.add_parser("list", help="reviewed D scripts with metadata + hashes")
    trl.add_argument("--root", default=None, help="Plasma root containing sensors/dtrace")
    trl.set_defaults(func=cmd_trace_list)
    trc = trs.add_parser("check", help="is dtrace present and enabled?")
    trc.set_defaults(func=cmd_trace_check)
    trt = trs.add_parser("selftest", help="compile every script with dtrace -e")
    trt.add_argument("--root", default=None)
    trt.set_defaults(func=cmd_trace_selftest)
    trr = trs.add_parser("run", help="run one script for a bounded window")
    trr.add_argument("script", help="script name (see: plasma trace list)")
    trr.add_argument("--events", required=True, help="Plasma event store to append to")
    trr.add_argument("--for", dest="for_", default="10s", help="window, e.g. 5s, 2m (max 5m)")
    trr.add_argument("--max-rows", type=int, default=trace.DEFAULT_MAX_ROWS)
    trr.add_argument("--out", default=None, help="raw capture file (JSONL)")
    trr.add_argument("--root", default=None)
    trr.add_argument("--host", default=None)
    trr.set_defaults(func=cmd_trace_run)
    trp = trs.add_parser("provision", help="install Microsoft.DTrace and enable it (requires a restart)")
    trp.set_defaults(func=cmd_trace_provision)

    # Hidden: the frozen executable re-enters itself to execute the bundle's
    # bridge with the Python runtime embedded in the one-file binary.
    ob = sub.add_parser("observe", help="run a read-only observatory question on this host (rmagent-so lineage)")
    ob.add_argument("question", choices=observatory.questions(),
                    help="attest|sketch|edges|explain|pslogs|attackmap|regedges|flowstats|canary|sysmon_health")
    ob.add_argument("--canary", nargs="*", default=[],
                    help="canary usernames for the canary question")
    ob.set_defaults(func=cmd_observe)

    dr = sub.add_parser("drift", help="baseline and diff observatory answers (what changed since I last looked)")
    drs = dr.add_subparsers(dest="drift_action", required=True)
    drp = drs.add_parser("record", help="record a question's answer as the new baseline")
    drp.add_argument("question", choices=observatory.questions())
    drp.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    drp.add_argument("--canary", nargs="*", default=[])
    drp.set_defaults(func=cmd_drift_record)
    drsc = drs.add_parser("score", help="re-run a question and score drift against the baseline")
    drsc.add_argument("question")
    drsc.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    drsc.add_argument("--canary", nargs="*", default=[])
    drsc.set_defaults(func=cmd_drift_score)
    drl = drs.add_parser("list", help="list stored baselines")
    drl.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    drl.set_defaults(func=cmd_drift_list)

    ac = sub.add_parser("actuate", help="scoped, journaled, reversible response actions (dry-run by default)")
    acs = ac.add_subparsers(dest="actuate_action", required=True)
    aca = acs.add_parser("actions", help="list the allowlisted actions")
    aca.set_defaults(func=cmd_actuate_actions)
    acx = acs.add_parser("apply", help="dry-run (default) or apply (--apply) one action")
    acx.add_argument("action", choices=sorted(actuate.ACTIONS))
    acx.add_argument("--target", default=None, help="ip | user | service | pid | path | task (per action)")
    acx.add_argument("--reason", required=True, help="mandatory: why this action")
    acx.add_argument("--apply", action="store_true", help="actually execute (default: dry-run only)")
    acx.add_argument("--plan", type=int, default=None,
                     help="required with --apply: the id of the earlier dry-run "
                          "entry for this exact action+target")
    acx.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    acx.add_argument("--timeout", type=int, default=60)
    acx.set_defaults(func=cmd_actuate_apply)
    acj = acs.add_parser("journal", help="read the actuate journal")
    acj.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    acj.add_argument("--last", type=int, default=None)
    acj.set_defaults(func=cmd_actuate_journal)
    acu = acs.add_parser("undo", help="undo a journaled applied action (dry-run by default)")
    acu.add_argument("--id", type=int, required=True)
    acu.add_argument("--apply", action="store_true")
    acu.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    acu.add_argument("--timeout", type=int, default=60)
    acu.set_defaults(func=cmd_actuate_undo)

    chs = sub.add_parser("chain", help="deterministic story detection over the events store")
    chsp = chs.add_subparsers(dest="chain_action", required=True)
    chsc = chsp.add_parser("score", help="scan the events tail for chain matches")
    chsc.add_argument("--events", required=True)
    chsc.add_argument("--window", type=int, default=chain.DEFAULT_WINDOW,
                      help="max seconds between adjacent chain steps")
    chsc.add_argument("--max-rows", type=int, default=chain.DEFAULT_MAX_ROWS)
    chsc.set_defaults(func=cmd_chain_score)

    cov = sub.add_parser("coverage", help="ATT&CK technique coverage of the shipped rules")
    cov.add_argument("--sensors", default=None, help="sensors dir (default: bundled)")
    cov.set_defaults(func=cmd_coverage)

    st = sub.add_parser("store", help="events store hygiene: rotate / compact / stats")
    sts = st.add_subparsers(dest="store_action", required=True)
    stro = sts.add_parser("rotate", help="rotate the store when it exceeds --max-mb")
    stro.add_argument("--events", required=True)
    stro.add_argument("--max-mb", type=float, default=store.DEFAULT_MAX_MB)
    stro.add_argument("--keep", type=int, default=store.DEFAULT_KEEP)
    stro.set_defaults(func=cmd_store_rotate)
    stc = sts.add_parser("compact", help="drop exact duplicate rows (atomic)")
    stc.add_argument("--events", required=True)
    stc.add_argument("--out", default=None, help="write compacted copy here instead of in place")
    stc.set_defaults(func=cmd_store_compact)
    stst = sts.add_parser("stats", help="row counts, kinds, time span")
    stst.add_argument("--events", required=True)
    stst.set_defaults(func=cmd_store_stats)

    dp = sub.add_parser("deep", help="deep probes (run on the endpoint)")
    dps = dp.add_subparsers(dest="deep_action", required=True)
    dpp = dps.add_parser("persistence", help="every auto-start location + signature status")
    dpp.add_argument("--json-out", default=None, help="also write the full result here")
    dpp.add_argument("--cap", type=int, default=40)
    dpp.set_defaults(func=cmd_deep_persistence)

    pb = sub.add_parser("playbook", help="named plan-gated action sequences")
    pbs = pb.add_subparsers(dest="playbook_action", required=True)
    pbl = pbs.add_parser("list", help="list playbooks")
    pbl.set_defaults(func=cmd_playbook_list)
    pba = pbs.add_parser("apply", help="dry-run (default) or apply a playbook as one unit")
    pba.add_argument("name", choices=sorted(playbooks.PLAYBOOKS))
    pba.add_argument("--target", default=None)
    pba.add_argument("--reason", required=True)
    pba.add_argument("--apply", action="store_true", help="execute (requires --plan)")
    pba.add_argument("--plan", type=int, default=None,
                     help="required with --apply: the playbook dry-run entry id")
    pba.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    pba.add_argument("--timeout", type=int, default=60)
    pba.set_defaults(func=cmd_playbook_apply)
    pbu = pbs.add_parser("undo", help="reverse a playbook's succeeded steps, last-first")
    pbu.add_argument("--id", type=int, required=True)
    pbu.add_argument("--apply", action="store_true")
    pbu.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    pbu.add_argument("--timeout", type=int, default=60)
    pbu.set_defaults(func=cmd_playbook_undo)

    tp = sub.add_parser("tap", help="ETW tap over gap providers (krabsetw) — on-demand, matches-only")
    tps = tp.add_subparsers(dest="tap_action", required=True)
    tpl = tps.add_parser("list", help="show providers, rules and sidecar availability")
    tpl.set_defaults(func=cmd_tap_list)
    tpt = tps.add_parser("selftest", help="validate the sidecar + rules without opening a trace")
    tpt.add_argument("--tap-exe", default=None)
    tpt.add_argument("--rules", default=None)
    tpt.set_defaults(func=cmd_tap_selftest)
    tpr = tps.add_parser("run", help="run a bounded capture window (admin required)")
    tpr.add_argument("--providers", default="powershell,wmi,dns",
                     help="comma list: powershell|wmi|dns|dotnet|schannel")
    tpr.add_argument("--for", dest="for_", default="5m", help="window: 90s | 5m | 1h")
    tpr.add_argument("--out-dir", default=None, help="where matches + rules land")
    tpr.add_argument("--events", default=None,
                     help="also normalize matches into this events store")
    tpr.add_argument("--max-matches", type=int, default=500)
    tpr.add_argument("--tap-exe", default=None)
    tpr.add_argument("--rules", default=None)
    tpr.set_defaults(func=cmd_tap_run)
    tpc = tps.add_parser("collect", help="normalize an existing matches.jsonl into the events store")
    tpc.add_argument("--matches", required=True)
    tpc.add_argument("--events", required=True)
    tpc.add_argument("--host", default=None)
    tpc.set_defaults(func=cmd_tap_collect)

    fl = sub.add_parser("fleet", help="one desk, many computers — cross-host correlation (desk-side only)")
    fls = fl.add_subparsers(dest="fleet_action", required=True)
    _fleet_root = "C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma"
    flp = fls.add_parser("pull", help="pull a capped events tail from every inventory host into a case")
    flp.add_argument("--inventory", required=True, help="fleet inventory JSON")
    flp.add_argument("--case", required=True)
    flp.add_argument("--root", default=_fleet_root)
    flp.add_argument("--cap", type=int, default=fleet.DEFAULT_CAP)
    flp.add_argument("--window", type=int, default=fleet.DEFAULT_WINDOW,
                     help="correlation window in seconds")
    flp.add_argument("--canary", nargs="*", default=None)
    flp.set_defaults(func=cmd_fleet_pull)
    flc = fls.add_parser("correlate", help="join pulled digests into deterministic findings")
    flc.add_argument("--case", required=True)
    flc.add_argument("--root", default=_fleet_root)
    flc.add_argument("--window", type=int, default=None)
    flc.set_defaults(func=cmd_fleet_correlate)
    flr = fls.add_parser("report", help="render the one-page case report")
    flr.add_argument("--case", required=True)
    flr.add_argument("--root", default=_fleet_root)
    flr.set_defaults(func=cmd_fleet_report)
    fls2 = fls.add_parser("scan", help="pull + correlate + report in one shot")
    fls2.add_argument("--inventory", required=True)
    fls2.add_argument("--case", required=True)
    fls2.add_argument("--root", default=_fleet_root)
    fls2.add_argument("--cap", type=int, default=fleet.DEFAULT_CAP)
    fls2.add_argument("--window", type=int, default=fleet.DEFAULT_WINDOW)
    fls2.add_argument("--canary", nargs="*", default=None)
    fls2.set_defaults(func=cmd_fleet_scan)

    idp = sub.add_parser("identity", help="identity plane: logon events into the store (Event Log API)")
    idps = idp.add_subparsers(dest="identity_action", required=True)
    idpp = idps.add_parser("pull", help="pull recent 4624/4625 logons into the events store")
    idpp.add_argument("--events", required=True)
    idpp.add_argument("--host", default=None)
    idpp.add_argument("--since", type=int, default=15, help="minutes to look back")
    idpp.set_defaults(func=cmd_identity_pull)

    hp = sub.add_parser("health", help="is this node's Plasma stack actually alive?")
    hp.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    hp.set_defaults(func=cmd_health)

    wp = sub.add_parser("watch", help="self-check sweep with notifications (health + drift + alerts)")
    wps = wp.add_subparsers(dest="watch_action", required=True)
    wpo = wps.add_parser("once", help="one sweep (cron/Task Scheduler friendly)")
    wpo.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    wpo.add_argument("--notify-clean", action="store_true", help="notify even when clean")
    wpo.set_defaults(func=cmd_watch_once)
    wpl = wps.add_parser("loop", help="sweep forever every N seconds")
    wpl.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    wpl.add_argument("--every", type=int, default=3600)
    wpl.set_defaults(func=cmd_watch_loop)

    np_ = sub.add_parser("notify", help="alert channel configuration and delivery")
    nps = np_.add_subparsers(dest="notify_action", required=True)
    npt = nps.add_parser("test", help="send a test message to every configured channel")
    npt.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    npt.add_argument("--host", default=None)
    npt.set_defaults(func=cmd_notify_test)
    npsh = nps.add_parser("show", help="validate and show channel config")
    npsh.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    npsh.set_defaults(func=cmd_notify_show)

    up = sub.add_parser("update", help="self-update from GitHub releases")
    ups = up.add_subparsers(dest="update_action", required=True)
    upc = ups.add_parser("check", help="compare against the latest release")
    upc.add_argument("--repo", default="DrOlu/plasma")
    upc.add_argument("--token-env", default="PLASMA_GITHUB_TOKEN")
    upc.set_defaults(func=cmd_update_check)
    upa = ups.add_parser("apply", help="download, verify, install, rotate bin")
    upa.add_argument("--repo", default="DrOlu/plasma")
    upa.add_argument("--token-env", default="PLASMA_GITHUB_TOKEN",
                     help="optional (public repo works anonymously)")
    upa.add_argument("--allow-unsigned", action="store_true",
                     help="development only: execute an update whose signer "
                          "does not match the pinned thumbprints")
    upa.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    upa.add_argument("--bin", default=None, help="canonical exe copy to rotate (default <root>/bin)")
    upa.set_defaults(func=cmd_update_apply)

    hb = sub.add_parser("_bridge", help=argparse.SUPPRESS)
    hb.add_argument("--dir", required=True)
    hb.add_argument("--tool", default=None)
    hb.add_argument("--args", default="{}")
    hb.add_argument("--events", default=None)
    hb.add_argument("--coverage", action="store_true")
    hb.set_defaults(func=cmd_internal_bridge)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
