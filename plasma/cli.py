# ruff: noqa: ISC004
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

from . import (
    __version__,
    actuate,
    agentstate,
    anomaly,
    assurance,
    autoupdate,
    canary,
    canary_pipe,
    canary_shield,
    canary_tokens,
    chain,
    coverage,
    deep,
    drift,
    enforce,
    evals,
    evidence,
    fim,
    fleet,
    health,
    identity,
    intercept,
    killswitch,
    ledger,
    memory,
    netguard,
    notify,
    observatory,
    playbooks,
    plugin_actions,
    plugin_api,
    plugin_host,
    plugin_io,
    plugins,
    prevent,
    profile,
    protect,
    rings,
    sigma,
    statemachine,
    store,
    tap,
    tenants,
    trace,
    watch,
    whids,
)
from . import (
    case as case_mod,
)
from . import (
    detect as detect_mod,
)
from . import help as helpmod
from . import mcp as mcp_server
from . import policy as agent_policy
from . import (
    query as query_mod,
)
from . import (
    summarize as summarize_mod,
)
from . import update as updater
from .bundle import build_bundle
from .manifest import create_manifest, verify_manifest

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
    for name in ("plasma-iocs.gen", "plasma-baseline.gen",
                 "plasma-sigma.gen", "sigma-sources.json",
                 "SIGMA-DRL-1.1.md", "LICENSE"):
        src = whids_dir / name
        if src.exists():
            wanted[install_dir / name] = src
    # The shared config lives at sensors/whids.toml (the builder stages it a
    # level above the WHIDS payload). Accept either layout, and copy it as
    # both whids.toml and config.toml — v1.7.0 loads config.toml next to the
    # binary, and a stale one was surviving every upgrade.
    toml_src = next((p for p in (whids_dir / "whids.toml",
                                 whids_dir.parent / "whids.toml")
                     if p.exists()), None)
    if toml_src is not None:
        wanted[install_dir / "whids.toml"] = toml_src
        wanted[install_dir / "config.toml"] = toml_src
    rules_db = install_dir / "Database" / "Rules"
    for name in whids.RULE_FILES:
        # shared rule files live at sensors/, the WHIDS payload at
        # sensors/whids/ — accept either staging layout
        src = next((p for p in (whids_dir / name, whids_dir.parent / name)
                    if p.exists()), None)
        if src is not None:
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
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, env=env, check=False)
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
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, check=False)
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
            proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60, env=env, check=False)
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
        proc = subprocess.run(["powershell.exe", "-NoProfile", "-Command",
             "Get-Service | Where-Object { $_.Name -like '" + pattern + "' -or "
             "$_.DisplayName -like '" + pattern + "' } | Select-Object -First 1 "
             "-ExpandProperty Name"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20, check=False
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

_SYSMON_TEMPLATE = (
    '<Sysmon schemaversion="4.90"><EventFiltering>'
    '<ProcessCreate onmatch="exclude"/>'
    '<FileCreateTime onmatch="exclude"/>'
    '<NetworkConnect onmatch="exclude"/>'
    '<ProcessTerminate onmatch="exclude"/>'
    # ImageLoad is high volume; log only unsigned images, which is the
    # security-relevant subset the Sigma image_load rules care about.
    '<ImageLoad onmatch="include">'
    '<Signed condition="is">false</Signed>'
    '</ImageLoad>'
    # DriverLoad is low volume and closes the unsigned-driver rule.
    '<DriverLoad onmatch="include">'
    '<ImageLoaded condition="begin with">C:\\</ImageLoaded>'
    '</DriverLoad>'
    # LSASS access only: the canonical credential-dump signal, bounded.
    '<ProcessAccess onmatch="include">'
    '<TargetImage condition="is">C:\\Windows\\System32\\lsass.exe</TargetImage>'
    '</ProcessAccess>'
    # Named pipes: creation only, not every connect.
    '<PipeEvent onmatch="include">'
    '<EventType condition="is">CreatePipe</EventType>'
    '<EventType condition="is">ConnectPipe</EventType>'
    '</PipeEvent>'
    '<FileCreate onmatch="exclude"/>'
    '<RegistryEvent onmatch="exclude"/>'
    '{dns}'
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


def sysmon_baseline_config(dns_suffixes=None) -> str:
    """Build the Sysmon baseline; optionally add a narrow DnsQuery include.

    DNS query logging is high-volume, so the default remains excluded.  The
    canary path adds only the token suffixes: a query for an ordinary domain
    never reaches the channel.  Suffixes are validated by the caller and
    XML-escaped here so a token domain cannot break the config.
    """
    from xml.sax.saxutils import escape

    suffixes = []
    for value in dns_suffixes or []:
        text = str(value).strip().lower().rstrip(".")
        if text and text not in suffixes:
            suffixes.append(text)
    if not suffixes:
        dns = '<DnsQuery onmatch="exclude"/>'
    else:
        rules = "".join(
            '<QueryName condition="end with">'
            f'{escape("." + suffix)}</QueryName>'
            for suffix in suffixes[:32]
        )
        dns = f'<DnsQuery onmatch="include">{rules}</DnsQuery>'
    return _SYSMON_TEMPLATE.format(dns=dns)


SYSMON_BASELINE_CONFIG = sysmon_baseline_config()
SYSMON_URLS = (
    "https://download.sysinternals.com/files/Sysmon.zip",
    "https://live.sysinternals.com/Sysmon64.exe",
)


def write_sysmon_config(tools_dir: Path, dns_suffixes=None) -> Path:
    """Materialize the Plasma baseline Sysmon config under the install root."""
    tools_dir.mkdir(parents=True, exist_ok=True)
    path = tools_dir / "plasma-sysmon-baseline.xml"
    path.write_text(sysmon_baseline_config(dns_suffixes), encoding="utf-8")
    return path


WATCHDOG_TASK = "PlasmaWhidsWatchdog"
WATCH_TASK = "PlasmaWatch"
UPDATE_TASK = "PlasmaUpdate"


def _register_update(bin_exe: Path, root: Path, start_hour: int = 3) -> dict:
    """Register the daily SYSTEM task that runs the measured self-update.

    A random minute inside the maintenance window staggers the fleet: every
    host does not wake up at 03:00. The command itself re-checks the window,
    ring, signature and kill switch.
    """
    exe_q = str(bin_exe).replace("'", "''")
    root_q = str(root).replace("'", "''")
    log_q = str(root / "logs" / "update.log").replace("'", "''")
    inner = (f"& '{exe_q}' update auto --root '{root_q}' "
             f"*> '{log_q}'; exit 0")
    argument = ("-NoProfile -ExecutionPolicy Bypass -Command "
                f"\"{inner}\"").replace("'", "''")
    script = (
        f"$logDir = Split-Path '{log_q}' -Parent; "
        f"New-Item -ItemType Directory -Force -Path $logDir | Out-Null; "
        f"$offset = Get-Random -Minimum 0 -Maximum 60; "
        f"$at = (Get-Date).Date.AddHours({int(start_hour) % 24}).AddMinutes($offset); "
        f"if ($at -lt (Get-Date)) {{ $at = $at.AddDays(1) }}; "
        f"$a = New-ScheduledTaskAction -Execute 'powershell.exe' "
        f"-Argument '{argument}'; "
        f"$t = New-ScheduledTaskTrigger -Daily -At $at; "
        f"$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' "
        f"-LogonType ServiceAccount -RunLevel Highest; "
        f"$s = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew "
        f"-ExecutionTimeLimit (New-TimeSpan -Hours 1); "
        f"Register-ScheduledTask -TaskName '{UPDATE_TASK}' -Action $a "
        f"-Trigger $t -Principal $p -Settings $s -Force | Out-Null"
    )
    rc, out = whids._ps(script, timeout=120)
    return {"ok": rc == 0, "task": UPDATE_TASK, "detail": out[:200]}


def _register_watch(bin_exe: Path, root: Path,
                    every_minutes: int = 5) -> dict:
    """Register the SYSTEM task that runs the measured enforcement sweep.

    The policy is armed by default, but nothing acts unless a sweep feeds
    findings to `enforce.run`. This task is that sweep: it runs
    `watch once --enforce` every few minutes, so automatic containment is
    live out of the box while the policy still gates every action.
    """
    minutes = max(1, min(int(every_minutes), 60))
    exe_q = str(bin_exe).replace("'", "''")
    root_q = str(root).replace("'", "''")
    # `watch once` returns 2 when it finds something. Task Scheduler would
    # call that a failure, so wrap it: run, discard output, exit 0. The
    # decision is already in the enforce journal.
    inner = (f"& '{exe_q}' watch once --root '{root_q}' --enforce "
             f"*> $null; exit 0")
    argument = ("-NoProfile -ExecutionPolicy Bypass -Command "
                f"\"{inner}\"").replace("'", "''")
    script = (
        f"$a = New-ScheduledTaskAction -Execute 'powershell.exe' "
        f"-Argument '{argument}'; "
        f"$t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) "
        f"-RepetitionInterval (New-TimeSpan -Minutes {minutes}) "
        f"-RepetitionDuration (New-TimeSpan -Days 3650); "
        f"$b = New-ScheduledTaskTrigger -AtStartup; "
        f"$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' "
        f"-LogonType ServiceAccount -RunLevel Highest; "
        f"$s = New-ScheduledTaskSettingsSet -StartWhenAvailable "
        f"-RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) "
        f"-ExecutionTimeLimit (New-TimeSpan -Minutes 15) "
        f"-MultipleInstances IgnoreNew; "
        f"Register-ScheduledTask -TaskName '{WATCH_TASK}' -Action $a "
        f"-Trigger @($t,$b) -Principal $p -Settings $s -Force | Out-Null"
    )
    rc, out = whids._ps(script, timeout=120)
    return {"ok": rc == 0, "task": WATCH_TASK, "every_minutes": minutes,
            "detail": out[:200]}


def _register_whids_watchdog(bin_exe: Path, root: Path) -> dict:
    """Register the SYSTEM task that heals a hung/stopped WHIDS every 2 min.

    WHIDS 1.7.0 can hang in StartPending or stop after a manual restart;
    SCM failure actions only cover crashes, not hangs. `whids ensure`
    force-stops and restarts, and this task runs it as SYSTEM.
    """
    exe_q = str(bin_exe).replace("'", "''")
    root_q = str(root).replace("'", "''")
    script = (
        f"$a = New-ScheduledTaskAction -Execute '{exe_q}' "
        f"-Argument 'whids ensure --root \"{root_q}\"'; "
        f"$t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) "
        f"-RepetitionInterval (New-TimeSpan -Minutes 2) "
        f"-RepetitionDuration (New-TimeSpan -Days 3650); "
        f"$b = New-ScheduledTaskTrigger -AtStartup; "
        f"$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' "
        f"-LogonType ServiceAccount -RunLevel Highest; "
        f"$s = New-ScheduledTaskSettingsSet -StartWhenAvailable "
        f"-RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) "
        f"-ExecutionTimeLimit (New-TimeSpan -Minutes 5) "
        f"-MultipleInstances IgnoreNew; "
        f"Register-ScheduledTask -TaskName '{WATCHDOG_TASK}' -Action $a "
        f"-Trigger @($t,$b) -Principal $p -Settings $s -Force | Out-Null"
    )
    rc, out = whids._ps(script, timeout=120)
    return {"ok": rc == 0, "task": WATCHDOG_TASK, "detail": out[:200]}


def _apply_sysmon_config(tools_dir: Path, dns_suffixes=None) -> dict:
    """Re-apply the baseline config to an existing Sysmon (hot reload).

    Sysmon keeps whatever config it was installed with. Detection content
    added since then (FileDelete for T1070.004, registry/service rules) is
    silent on an old node unless the config is refreshed on upgrade.
    """
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    exe = next((system_root / name for name in ("Sysmon64.exe", "Sysmon.exe")
                if (system_root / name).exists()), None)
    if exe is None:
        return {"ok": False, "reason": "sysmon binary not found"}
    cfg = write_sysmon_config(tools_dir, dns_suffixes=dns_suffixes)
    try:
        proc = subprocess.run([str(exe), "-c", str(cfg)],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "config": str(cfg), "reason": str(exc)[:200]}
    return {"ok": proc.returncode == 0, "config": str(cfg),
            "detail": (proc.stderr or proc.stdout or "").strip()[:200]}


def internet_available(prober=None, timeout: int = 5) -> bool:
    """Best-effort reachability probe for the Sysmon download source.
    `prober` is injectable for tests: callable(url) -> bool."""
    import urllib.request

    def _default(url: str) -> bool:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "plasma-installer"})
        netguard.require_https(req.full_url)
        urllib.request.urlopen(req, timeout=timeout)  # nosec B310
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
        proc = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
             f"(Get-Service -Name '{name}' -ErrorAction SilentlyContinue).Status"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, check=False)
        return (proc.stdout or "").strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _verify_microsoft_signature(path: Path) -> dict:
    """Require a valid Authenticode signature from Microsoft."""
    quoted = str(path).replace("'", "''")
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
             f"$s = Get-AuthenticodeSignature -LiteralPath '{quoted}'; "
             "if ($s.SignerCertificate) { $s.Status + '|' + $s.SignerCertificate.Subject } "
             "else { 'NOSIG|' }"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": f"signature check failed: {exc}"}
    line = ((proc.stdout or "").strip().splitlines() or [""])[-1]
    status, _, subject = line.partition("|")
    if status.strip() != "Valid":
        return {"ok": False, "error": f"signature status is {status.strip() or 'unknown'}"}
    if "microsoft" not in subject.lower():
        return {"ok": False, "error": "Sysmon is not signed by Microsoft"}
    return {"ok": True, "subject": subject.strip()[:200]}


def _try_install_sysmon(tools_dir: Path) -> tuple[bool, str]:
    """Download, verify and install Sysmon with the baseline config.

    The download is written to an exclusive temporary file, verified as a
    Microsoft-signed executable, then moved into place and executed. A
    compromised mirror or proxy therefore cannot get SYSTEM execution.
    """
    import io
    import tempfile
    import time
    import urllib.request
    import zipfile

    target_exe = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Sysmon64.exe"
    tools_dir.mkdir(parents=True, exist_ok=True)
    last_err = ""
    for url in SYSMON_URLS:
        staged = None
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "plasma-installer"})
            netguard.require_https(req.full_url)
            with urllib.request.urlopen(req, timeout=120) as resp:  # nosec B310
                data = resp.read()
            if url.endswith(".zip"):
                zf = zipfile.ZipFile(io.BytesIO(data))
                member = next(n for n in zf.namelist() if n.endswith("Sysmon64.exe"))
                exe_bytes = zf.read(member)
            else:
                exe_bytes = data
            fd, staged_name = tempfile.mkstemp(
                prefix="sysmon-", suffix=".exe", dir=str(tools_dir))
            staged = Path(staged_name)
            with os.fdopen(fd, "wb") as fh:
                fh.write(exe_bytes)
                fh.flush()
                os.fsync(fh.fileno())
            signature = _verify_microsoft_signature(staged)
            if not signature.get("ok"):
                return False, f"Sysmon signature refused: {signature.get('error')}"
            os.replace(staged, target_exe)
            staged = None
            cfg = tools_dir / "sysmon-baseline.xml"
            cfg.write_text(SYSMON_BASELINE_CONFIG, encoding="ascii")
            proc = subprocess.run(
                [str(target_exe), "-accepteula", "-i", str(cfg)],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=300, check=False)
            if proc.returncode != 0:
                return False, (f"Sysmon installer exited {proc.returncode}: "
                               f"{(proc.stderr or proc.stdout or '')[:200]}")
            for _ in range(15):
                if _service_present("Sysmon*"):
                    return True, "Sysmon installed (Microsoft signature verified)"
                time.sleep(2)
            return False, "Sysmon service did not appear within 30s"
        except Exception as exc:  # noqa: BLE001 — download failures are data
            last_err = f"{url}: {str(exc)[:160]}"
            continue
        finally:
            if staged is not None:
                try:
                    staged.unlink()
                except OSError:
                    pass
    return False, f"Sysmon download failed: {last_err}"


def _is_junction(path: Path) -> bool:
    quoted = str(path).replace("'", "''")
    try:
        proc = subprocess.run(["powershell.exe", "-NoProfile", "-Command",
             f"(Get-Item -LiteralPath '{quoted}' -Force).LinkType"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15, check=False
        )
        return proc.stdout.strip().lower() in ("junction", "symboliclink")
    except (OSError, subprocess.TimeoutExpired):
        return False


def _harden_root_acl(root) -> dict:
    """Restrict the Plasma root to SYSTEM and Administrators.

    Policy, kill-switch state, approvals, ledger and events are security
    data; inherited ProgramData permissions can leave them readable (and in
    some layouts writable) by standard users. Use well-known SIDs so the
    command works on non-English Windows.
    """
    if os.name != "nt":
        return {"ok": True, "skipped": "non-windows host"}
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    commands = _acl_commands(root)
    results = []
    try:
        for cmd in commands:
            proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=300, check=False)
            results.append({"rc": proc.returncode,
                            "detail": ((proc.stderr or proc.stdout or "")[:200]
                                       or None)})
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": str(exc)[:300], "steps": results}
    return {"ok": all(r["rc"] == 0 for r in results),
            "rc": results[-1]["rc"], "steps": results}


def _acl_commands(root) -> list[list[str]]:
    """Two-step ACL command list (separated for testability).

    Step 1 replaces inherited ACEs on the root with SYSTEM/Administrators
    container ACEs, so new files inherit correctly. Step 2 adds explicit
    Full Control to every EXISTING child. Passing an inheritable (OI)(CI)
    ACE recursively with /T leaves existing files with an inherit-only ACE
    — i.e. an empty effective DACL — and Windows then refuses to execute
    them (field-found on the 1.9.0 upgrade).
    """
    exe = shutil.which("icacls") or r"C:\Windows\System32\icacls.exe"
    return [
        [exe, str(root), "/inheritance:r", "/grant:r",
         "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"],
        [exe, str(root), "/T", "/C", "/grant",
         "*S-1-5-18:F", "*S-1-5-32-544:F"],
    ]


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
        elif args.dry_run:
            # Dry-run must not download or execute Sysmon. Keep the planned
            # decision so the operator sees what a real install would do.
            decision = whids_install_decision(
                sysmon_present, whids_present, whids_gz.exists(),
                args.skip_whids)
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
            ("automatic protection: snapshot + kill_process at score 9+, "
             "approval for isolation and all other actions"
             if not getattr(args, "no_autoprotect", False)
             else "automatic protection disabled (dry-run only)"),
            ("register the PlasmaWatch SYSTEM task (watch once --enforce "
             "every 5 minutes)"
             if not getattr(args, "no_autoprotect", False)
             else "remove the PlasmaWatch task"),
            ("register the PlasmaUpdate SYSTEM task (daily signed self-update)"
             if not getattr(args, "no_autoupdate", False)
             else "remove the PlasmaUpdate task"),
        ] + (["install Sysmon from Sysinternals (EULA accepted via -accepteula)"]
             if decision.get("sysmon") == "installed at install time (EULA accepted via -accepteula)" else [])
          + ([f"install or refresh WHIDS config/rules from embedded payload "
              f"(service '{whids.SERVICE_NAME}')"] if whids_planned else [])
          + ([f"MINIMAL MODE: {decision.get('reason')}"] if degraded else []),
    }
    if args.dry_run:
        print(json.dumps(plan, indent=2))
        return 0

    # Dry-run returns above this line: a plan must not create the root,
    # rewrite ACLs, download Sysmon, or start any service.
    root_acl = _harden_root_acl(root)

    # 1. Stage the version into a sibling, then swap. A failed copy never
    # leaves a half-populated target, and --force replaces stale files rather
    # than merging them.
    if target.exists() and not args.force:
        print(json.dumps({"ok": False, "error": f"target exists: {target} (use --force)"}, indent=2))
        return 4
    staging = target.with_name(target.name + f".staging-{os.getpid()}")
    backup = target.with_name(target.name + f".old-{os.getpid()}")
    for stale in (staging, backup):
        if stale.exists():
            shutil.rmtree(stale, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)
    for sub in ("instance", "engines", "sensors"):
        src = embedded / sub
        if src.is_dir():
            shutil.copytree(src, staging / sub, dirs_exist_ok=True)
    moved_old = False
    try:
        if target.exists():
            os.replace(target, backup)
            moved_old = True
        os.replace(staging, target)
        if moved_old:
            shutil.rmtree(backup, ignore_errors=True)
    except OSError as exc:
        if moved_old and not target.exists() and backup.exists():
            os.replace(backup, target)
        shutil.rmtree(staging, ignore_errors=True)
        print(json.dumps({"ok": False, "stage": "instance",
                          "error": f"could not stage the instance: {exc}"},
                         indent=2))
        return 4
    bindir = root / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    me = Path(sys.executable)
    dest = bindir / me.name
    try:
        if not _same_bytes(me, dest):
            shutil.copy2(me, dest)
    except OSError:
        # A running or staged exe can be locked while the updater rotates
        # it. The rotation that follows the install is authoritative; a
        # locked copy must not abort the whole install.
        pass
    # Scheduled tasks must point at a stable name, not the transient
    # `plasma-update-staged.exe` the updater re-enters during an install.
    task_exe = bindir / ("plasma.exe" if me.name.startswith("plasma-update")
                         else me.name)

    # 2. Config — sensor state reflects the ACTUAL decision, not hopes.
    config = {
        "product": "Plasma",
        "version": version,
        "root_acl": root_acl,
        "instance": str(target),
        "events_path": str(events_path),
        "retention_days": 7,
        "response": {"mode": "advisory", "require_human_approval": True},
        # Measured protection: armed by default, but only snapshot + kill
        # at score 9+, with a per-run cap and cooldown. Every other action
        # requires approval. --no-autoprotect installs the old off posture.
        "enforcement": (dict(protect.LEGACY_ENFORCEMENT)
                        if getattr(args, "no_autoprotect", False)
                        else dict(protect.MEASURED_ENFORCEMENT)),
        "prevention": dict(protect.DEFAULT_PREVENTION),
        "update": (dict(autoupdate.DEFAULT_UPDATE)
                   if not getattr(args, "no_autoupdate", False)
                   else {**autoupdate.DEFAULT_UPDATE, "auto": False,
                         "task": "disabled"}),
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
    # An operator's enforcement/prevention decisions must not be reset by a
    # routine upgrade: carry the existing blocks across the rewrite.
    try:
        previous = json.loads(config_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        previous = {}
    if isinstance(previous, dict):
        if getattr(args, "no_autoprotect", False):
            config["enforcement"] = dict(protect.LEGACY_ENFORCEMENT)
        else:
            # Replace exactly the old "off by default" block; preserve a
            # custom operator block.
            config["enforcement"] = protect.migrate_enforcement(
                previous.get("enforcement"))
        if isinstance(previous.get("prevention"), dict):
            config["prevention"] = previous["prevention"]
        if isinstance(previous.get("update"), dict):
            config["update"] = previous["update"]
        if getattr(args, "no_autoupdate", False):
            config["update"]["auto"] = False
            config["update"]["task"] = "disabled"
        # A routine --force upgrade must not reset operator data paths or
        # retention. Only an explicit --events changes the store.
        if args.events is None:
            old_events = previous.get("events_path")
            if isinstance(old_events, str) and old_events.strip():
                config["events_path"] = old_events
        old_retention = previous.get("retention_days")
        if isinstance(old_retention, int) and 1 <= old_retention <= 3650:
            config["retention_days"] = old_retention
        if isinstance(previous.get("response"), dict):
            config["response"] = previous["response"]
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
        # Gene loads every *.gen; an obsolete backup is drift too, so a
        # converged-looking node still gets a cleanup pass.
        drift += [str(p) for p in rules_db.glob("*.bak.gen")]
        was_running = _service_state_name("Whids") == "Running"
        prev_config = install_dir / "config.toml.plasma-prev"
        if was_running and not drift:
            # Already converged: don't disturb a healthy sensor on reinstall.
            pass
        else:
            if _service_present("Whids*"):
                subprocess.run(["powershell.exe", "-NoProfile", "-Command",
                     "Stop-Service -Name 'Whids' -Force -ErrorAction SilentlyContinue"],
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=60, check=False
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
            # Detect-only nodes do not keep process dumps; bound any tree a
            # previous build or hook configuration left behind.
            pruned = whids.prune_dumps(install_dir)
            if pruned.get("removed_files"):
                config["sensors"]["whids"]["dumps_pruned"] = {
                    "files": pruned["removed_files"],
                    "mb": round(pruned["removed_bytes"] / (1024 * 1024), 1),
                }

        bin_path = f'"{exe}" -c "{install_dir}\\config.toml"'
        if not _service_present("Whids*"):
            try:
                setup_proc = subprocess.run(["powershell.exe", "-NoProfile", "-Command",
                     f"New-Service -Name Whids -BinaryPathName '{bin_path}' "
                     f"-DisplayName 'WHIDS (Plasma sensor)' -StartupType Automatic | Out-Null; "
                     f"sc.exe failure Whids reset= 9999 actions= restart/5000 | Out-Null"],
                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, check=False
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
                subprocess.run(["powershell.exe", "-NoProfile", "-Command",
                     "Start-Service -Name 'Whids' -ErrorAction Stop"],
                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60, check=False
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
                subprocess.run(["powershell.exe", "-NoProfile", "-Command",
                     "Start-Service -Name 'Whids' -ErrorAction SilentlyContinue"],
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=60, check=False
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
            subprocess.run(["powershell.exe", "-NoProfile", "-Command",
                 "Stop-Service -Name 'Whids' -Force -ErrorAction SilentlyContinue"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60, check=False
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

    # 3a. Watchdog: SCM failure actions restart a crashed WHIDS, but not a
    # hung StartPending. A SYSTEM task runs `whids ensure` every two minutes.
    if whids_planned:
        wd = _register_whids_watchdog(task_exe, root)
        config["sensors"]["whids"]["watchdog"] = (
            wd["task"] if wd["ok"] else "failed")
        if not wd["ok"]:
            config["sensors"]["whids"]["watchdog_error"] = wd.get("detail")
        config_path.write_text(json.dumps(config, indent=2) + "\n",
                               encoding="utf-8")

    # 3a-bis. Standing authentication pull. Watch-only HIDS misses brute
    # force between operator sweeps; a SYSTEM task keeps 4624/4625 flowing.
    ident = identity.schedule(root, every_minutes=15,
                              exe=str(task_exe))
    config["sensors"]["identity"]["schedule"] = (
        ident["task"] if ident["ok"] else "failed")
    config["sensors"]["identity"]["mode"] = (
        "scheduled" if ident["ok"] else "on-demand")
    if not ident["ok"]:
        config["sensors"]["identity"]["schedule_error"] = ident.get("detail")
    config_path.write_text(json.dumps(config, indent=2) + "\n",
                           encoding="utf-8")

    # 3a-ter. Measured enforcement sweep. The policy is armed by default;
    # this SYSTEM task feeds findings to it every few minutes. With
    # --no-autoprotect the task is removed and the policy stays dry-run.
    if not getattr(args, "no_autoprotect", False):
        watch_task = _register_watch(task_exe, root)
        config["enforcement"]["watch_task"] = (
            watch_task["task"] if watch_task["ok"] else "failed")
        config["enforcement"]["watch_every_minutes"] = \
            watch_task["every_minutes"]
        if not watch_task["ok"]:
            config["enforcement"]["watch_error"] = watch_task.get("detail")
    else:
        whids._ps(f"Unregister-ScheduledTask -TaskName '{WATCH_TASK}' "
                  "-Confirm:$false -ErrorAction SilentlyContinue", timeout=60)
        config["enforcement"]["watch_task"] = "disabled"
    config_path.write_text(json.dumps(config, indent=2) + "\n",
                           encoding="utf-8")

    # 3a-quater. Measured self-update. A daily SYSTEM task checks the latest
    # signed release, respects the ring/window/canary hold, and keeps the
    # previous binary. --no-autoupdate removes the task and disables it.
    if not getattr(args, "no_autoupdate", False) \
            and config.get("update", {}).get("auto", True):
        upd = _register_update(task_exe, root, config["update"].get("window_start_hour", 3))
        config["update"]["task"] = (
            upd["task"] if upd["ok"] else "failed")
        if not upd["ok"]:
            config["update"]["task_error"] = upd.get("detail")
    else:
        whids._ps(f"Unregister-ScheduledTask -TaskName '{UPDATE_TASK}' "
                  "-Confirm:$false -ErrorAction SilentlyContinue", timeout=60)
        config["update"]["task"] = "disabled"
    config_path.write_text(json.dumps(config, indent=2) + "\n",
                           encoding="utf-8")

    # 3b. Sysmon config convergence. `--force` is the repair verb (and what
    # `update apply` calls), so an upgrade refreshes the detection config an
    # old node was installed with. Sysmon applies it hot — no service bounce.
    if args.force and sysmon_present and not args.skip_sysmon_check and os.name == "nt":
        sysmon_cfg = _apply_sysmon_config(root / "tools")
        config["sensors"]["sysmon"]["config_applied"] = bool(sysmon_cfg.get("ok"))
        if not sysmon_cfg.get("ok"):
            config["sensors"]["sysmon"]["config_error"] = (
                sysmon_cfg.get("reason") or sysmon_cfg.get("detail"))
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
        subprocess.run(["cmd.exe", "/c", "rmdir", str(current)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20, check=False
        )
        if current.exists() or _is_junction(current):
            print(json.dumps({"ok": False, "stage": "current",
                              "error": f"could not replace link {current} "
                                       "(remove it manually and re-run)"}, indent=2))
            return 4
    current_q = str(current).replace("'", "''")
    target_q = str(target).replace("'", "''")
    try:
        subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             f"New-Item -ItemType Junction -Path '{current_q}' -Target '{target_q}' | Out-Null"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
            check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        print(json.dumps({"ok": False, "stage": "current",
                          "error": f"junction creation failed: {exc}"}, indent=2))
        return 4

    # 5. Optional canonical rotation (MSI path). A package upgrade copies the
    # new versioned binary but the running node is `bin\plasma.exe`; without
    # this the service keeps executing the previous release even though the
    # config and instance already point at the new one. `update apply` does
    # its own rotation, so this is opt-in and only the MSI passes it.
    rotation = None
    if getattr(args, "rotate", False):
        try:
            rotation = autoupdate.rotate_running(
                me, bindir / me.name,
                bool(config.get("update", {}).get("restart_serve", True)))
        except (OSError, subprocess.SubprocessError) as exc:
            print(json.dumps({"ok": False, "stage": "rotate",
                              "error": f"rotation failed: {exc}"}, indent=2))
            return 4
        if not rotation["rotation"].get("ok"):
            print(json.dumps({
                "ok": False, "stage": "rotate",
                "error": rotation["rotation"].get("error"),
                "rotation": rotation,
            }, indent=2))
            return 4
        canonical = rotation.get("canonical")
        if canonical is not None and not canonical.get("ok"):
            print(json.dumps({
                "ok": False, "stage": "rotate_canonical",
                "error": canonical.get("error"),
                "rotation": rotation,
            }, indent=2))
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
        "rotated": rotation is not None,
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
    # 2 = refused (plan/guard/kill switch), 3 = execution or verification
    # failure, 1 = malformed request or data error.
    if "error" in result:
        return 2 if result.get("code") in ("REFUSED", "KILLSWITCH") else 1
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
    result = actuate.undo(args.root, args.id, apply=args.apply,
                          plan=args.plan, timeout=args.timeout)
    print(json.dumps(result, indent=2, default=str))
    if "error" in result:
        return 2 if result.get("code") == "REFUSED" else 1
    if args.apply and result.get("ok") is False:
        return 3
    return 0


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


def cmd_store_redact(args) -> int:
    result = store.redact_secrets(args.events, out_path=args.out)
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 1


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
        return 2 if result.get("code") in ("REFUSED", "KILLSWITCH") else 1
    if args.apply:
        if result.get("aborted_at"):
            return 3
        for s in result.get("steps", []):
            if s.get("ok") is False:
                return 3
    return 0


def cmd_playbook_undo(args) -> int:
    result = playbooks.undo(args.root, args.id, apply=args.apply,
                            plan=args.plan, timeout=args.timeout)
    print(json.dumps(result, indent=2, default=str))
    if "error" in result:
        return 2 if result.get("code") == "REFUSED" else 1
    if args.apply:
        for step in result.get("steps", []):
            if step.get("error"):
                return 3
    return 0


def cmd_sigma_convert(args) -> int:
    try:
        result = sigma.convert_path(args.inp)
    except (FileNotFoundError, sigma.SigmaError) as exc:
        print(json.dumps({"error": str(exc)}, indent=2))
        return 2
    summary = {"converted": result["converted"], "files": result["files"],
               "skipped": result["skipped"]}
    if args.dry_run:
        summary["dry_run"] = True
    else:
        summary.update(sigma.write_gen(args.out, result["rules"]))
    print(json.dumps(summary, indent=2, default=str))
    return 0


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


def cmd_whids_ensure(args) -> int:
    result = whids.ensure(args.root, wait_seconds=args.wait)
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("ok") else 1


def cmd_whids_prune(args) -> int:
    result = whids.prune_dumps(args.install_dir, max_mb=args.max_mb,
                               keep_days=args.keep_days, dry_run=args.dry_run)
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 1


def cmd_canary_deploy(args) -> int:
    result = canary.deploy(args.root, extra_dirs=args.dir,
                           randomize=args.randomize, subdir=args.subdir)
    print(json.dumps(result, indent=2, default=str))
    return 2 if result.get("code") == "KILLSWITCH" else (1 if "error" in result else 0)


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


def _events_path(root) -> Path:
    cfg = agentstate.read_json(Path(root) / "config.json", {}) or {}
    configured = cfg.get("events_path") if isinstance(cfg, dict) else None
    return Path(configured) if configured else Path(root) / "data" / "events.jsonl"


def cmd_canary_token_create(args) -> int:
    try:
        token = canary_tokens.create(
            args.root, args.kind, domain=args.domain,
            base_url=args.base_url, out=args.out, name=args.name,
            label=args.label)
    except (ValueError, OSError) as exc:
        _emit({"ok": False, "error": str(exc)[:300]})
        return 1
    result = {"ok": True, "token": token}
    if token.get("kind") == "dns":
        result["next"] = ("plasma canary sysmon --root "
                          f"{args.root} --apply")
    _emit(result)
    return 0


def cmd_canary_token_list(args) -> int:
    try:
        result = canary_tokens.list_tokens(args.root)
    except (ValueError, OSError) as exc:
        _emit({"ok": False, "error": str(exc)[:300]})
        return 1
    _emit({"ok": True, **result})
    return 0


def cmd_canary_token_remove(args) -> int:
    try:
        result = canary_tokens.remove(args.root, args.token_id,
                                      delete_artifact=args.delete_artifact)
    except (ValueError, OSError) as exc:
        _emit({"ok": False, "error": str(exc)[:300]})
        return 1
    _emit({"ok": "error" not in result, **result})
    return 0 if "error" not in result else 1


def cmd_canary_serve(args) -> int:
    try:
        result = canary_tokens.serve(
            args.root, host=args.host, port=args.port,
            allow_non_loopback=args.allow_non_loopback,
            max_requests=args.max_requests)
    except (ValueError, OSError) as exc:
        _emit({"ok": False, "error": str(exc)[:300]})
        return 1
    _emit(result)
    return 0 if result.get("ok") else 1


def cmd_canary_collect(args) -> int:
    try:
        result = canary_tokens.collect_all(
            args.root, args.events or _events_path(args.root),
            since_minutes=args.since, max_events=args.max_events)
    except (ValueError, OSError) as exc:
        _emit({"ok": False, "error": str(exc)[:300]})
        return 1
    _emit(result)
    errors = [result.get("dns", {}).get("error"),
              result.get("http", {}).get("error")]
    return 1 if any(errors) else 0


def cmd_canary_hits(args) -> int:
    result = canary_tokens.hits(
        args.root, args.events or _events_path(args.root), last=args.last)
    _emit(result)
    return 0


def cmd_canary_pipe_deploy(args) -> int:
    result = canary_pipe.deploy(args.root, count=args.count)
    _emit(result)
    return 0 if "error" not in result else 2


def cmd_canary_pipe_list(args) -> int:
    _emit(canary_pipe.list_pipes(args.root))
    return 0


def cmd_canary_pipe_remove(args) -> int:
    result = canary_pipe.remove(args.root, args.pipe_id)
    _emit(result)
    return 0 if "error" not in result else 2


def cmd_canary_pipe_serve(args) -> int:
    return canary_pipe.serve(
        args.root, apply=args.apply, reason=args.reason,
        max_kills=args.max_kills, max_connections=args.max_connections)


def cmd_canary_pipe_install(args) -> int:
    result = canary_pipe.install(
        args.root, apply=args.apply, plan=args.plan, reason=args.reason)
    _emit(result)
    return 0 if "error" not in result else 2


def cmd_canary_pipe_uninstall(args) -> int:
    result = canary_pipe.uninstall(
        args.root, apply=args.apply, plan=args.plan, reason=args.reason)
    _emit(result)
    return 0 if "error" not in result else 2


def cmd_canary_pipe_status(args) -> int:
    _emit(canary_pipe.status(args.root))
    return 0


def cmd_canary_shield_status(args) -> int:
    _emit(canary_shield.status(args.root))
    return 0


def cmd_canary_shield_install(args) -> int:
    result = canary_shield.install(
        args.root, apply=args.apply, plan=args.plan, reason=args.reason)
    _emit(result)
    return 0 if "error" not in result else 2


def cmd_canary_shield_uninstall(args) -> int:
    result = canary_shield.uninstall(
        args.root, apply=args.apply, plan=args.plan, reason=args.reason)
    _emit(result)
    return 0 if "error" not in result else 2


def cmd_canary_shield_sweep(args) -> int:
    result = canary_shield.sweep(
        args.root, since_minutes=args.since_minutes, apply=args.apply,
        reason=args.reason, max_kills=args.max_kills)
    _emit(result)
    return 0 if "error" not in result else 2


def cmd_canary_registry_deploy(args) -> int:
    result = canary_shield.registry_deploy(
        args.root, hive=args.hive, count=args.count)
    _emit(result)
    return 0 if "error" not in result else 2


def cmd_canary_registry_list(args) -> int:
    _emit(canary_shield.registry_list(args.root))
    return 0


def cmd_canary_registry_remove(args) -> int:
    result = canary_shield.registry_remove(args.root, args.canary_id)
    _emit(result)
    return 0 if "error" not in result else 2


def cmd_canary_sysmon(args) -> int:
    try:
        domains = list(args.domain or canary_tokens.dns_domains(args.root))
        domains = [canary_tokens.validate_domain(d) for d in domains]
    except ValueError as exc:
        _emit({"ok": False, "error": str(exc)[:300]})
        return 1
    if not domains:
        _emit({"ok": False,
               "error": "no DNS token domains — create one with "
                        "`plasma canary token create --kind dns --domain ...`"})
        return 1
    tools_dir = Path(args.root) / "tools"
    try:
        path = write_sysmon_config(tools_dir, dns_suffixes=domains)
        result = {"ok": True, "written": str(path), "domains": domains}
        if args.apply:
            result["apply"] = _apply_sysmon_config(tools_dir, dns_suffixes=domains)
            if not result["apply"].get("ok"):
                result["ok"] = False
    except OSError as exc:
        _emit({"ok": False, "error": f"cannot write Sysmon config: {exc}"})
        return 3
    _emit(result)
    return 0 if result.get("ok") else 3


def cmd_intercept_status(args) -> int:
    _emit({"ok": True, **intercept.status(args.root)})
    return 0


def cmd_intercept_rules_list(args) -> int:
    try:
        result = intercept.list_rules(args.root)
    except ValueError as exc:
        _emit({"ok": False, "error": str(exc)[:300]})
        return 1
    _emit({"ok": True, **result})
    return 0


def cmd_intercept_rules_add(args) -> int:
    try:
        blob = json.loads(Path(args.file).read_text(encoding="utf-8-sig"))
        items = blob.get("rules") if isinstance(blob, dict) else None
        rules = items if isinstance(items, list) else [blob]
        added = [intercept.add_rule(args.root, rule) for rule in rules]
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        _emit({"ok": False, "error": str(exc)[:300]})
        return 1
    _emit({"ok": True, "added": added})
    return 0


def cmd_intercept_rules_remove(args) -> int:
    try:
        result = intercept.remove_rule(args.root, args.rule_id)
    except ValueError as exc:
        _emit({"ok": False, "error": str(exc)[:300]})
        return 1
    _emit({"ok": "error" not in result, **result})
    return 0 if "error" not in result else 1


def cmd_intercept_evaluate(args) -> int:
    try:
        rules = intercept.list_rules(args.root)["rules"]
    except ValueError as exc:
        _emit({"ok": False, "error": str(exc)[:300]})
        return 1
    result = intercept.evaluate_store(
        args.events or _events_path(args.root), rules,
        max_rows=max(1, int(args.max_rows)))
    if args.out:
        try:
            Path(args.out).write_text(
                json.dumps(result, indent=2, default=str) + "\n",
                encoding="utf-8")
        except OSError as exc:
            _emit({"ok": False, "error": f"cannot write --out: {exc}"})
            return 1
    _emit({"ok": True, **result})
    return 0


def cmd_intercept_apply(args) -> int:
    try:
        result = intercept.apply_rule(
            args.root, args.rule_id, apply=args.apply, plan=args.plan,
            reason=args.reason)
    except ValueError as exc:
        _emit({"ok": False, "error": str(exc)[:500], "code": "REFUSED"})
        return 2
    _emit(result)
    return 0 if "error" not in result else 2


def cmd_intercept_rollback(args) -> int:
    try:
        result = intercept.rollback(
            args.root, args.id, apply=args.apply, plan=args.plan,
            reason=args.reason)
    except ValueError as exc:
        _emit({"ok": False, "error": str(exc)[:500], "code": "REFUSED"})
        return 2
    _emit(result)
    return 0 if "error" not in result else 2


def cmd_intercept_protect_canary(args) -> int:
    try:
        result = intercept.protect_canary(
            args.root, apply=args.apply, plan=args.plan,
            reason=args.reason, prefix=args.prefix)
    except ValueError as exc:
        _emit({"ok": False, "error": str(exc)[:300]})
        return 1
    _emit(result)
    return 0 if "error" not in result else 2


def _load_query_spec(value):
    if not value:
        return {}
    text = str(value).strip()
    path = Path(text)
    if path.exists() and path.is_file():
        text = path.read_text(encoding="utf-8-sig")
    try:
        spec = json.loads(text)
    except json.JSONDecodeError as exc:
        raise query_mod.QueryError(f"query is not valid JSON: {exc}") from exc
    if not isinstance(spec, dict):
        raise query_mod.QueryError("query must be a JSON object")
    return spec


def _query_spec_from_args(args) -> dict:
    spec = _load_query_spec(getattr(args, "spec", None))
    values = {
        "host": getattr(args, "host", None),
        "user": getattr(args, "user", None),
        "process": getattr(args, "process", None),
        "parent": getattr(args, "parent", None),
        "kind": getattr(args, "kind", None),
        "source": getattr(args, "source", None),
        "event_id": getattr(args, "event_id", None),
        "technique": getattr(args, "technique", None),
        "contains": getattr(args, "contains", None),
        "regex": getattr(args, "regex", None),
        "since": getattr(args, "since", None),
        "until": getattr(args, "until", None),
        "min_score": getattr(args, "min_score", None),
        "max_score": getattr(args, "max_score", None),
        "pid": getattr(args, "pid", None),
        "count_by": getattr(args, "count_by", None),
        "order": getattr(args, "order", None),
        "limit": getattr(args, "limit", None),
        "max_rows": getattr(args, "max_rows", None),
    }
    for key, value in values.items():
        if value is not None:
            spec[key] = value
    return spec


def cmd_query(args) -> int:
    try:
        spec = _query_spec_from_args(args)
        result = query_mod.query(
            args.events or _events_path(args.root), spec,
            max_rows=args.max_rows or query_mod.DEFAULT_MAX_ROWS)
    except (query_mod.QueryError, OSError) as exc:
        _emit({"ok": False, "error": str(exc)[:500], "code": "QUERY_ERROR"})
        return 1
    if args.out:
        try:
            Path(args.out).write_text(json.dumps(result, indent=2,
                                                 default=str) + "\n",
                                      encoding="utf-8")
            result = {**result, "out": args.out}
        except OSError as exc:
            _emit({"ok": False, "error": f"cannot write --out: {exc}"})
            return 1
    _emit(result)
    return 0


def cmd_tree(args) -> int:
    try:
        result = query_mod.tree(
            args.events or _events_path(args.root), pid=args.pid,
            process_name=args.process, depth=args.depth,
            max_rows=args.max_rows)
    except (query_mod.QueryError, OSError) as exc:
        _emit({"ok": False, "error": str(exc)[:500], "code": "QUERY_ERROR"})
        return 1
    _emit(result)
    return 0


def cmd_detect_validate(args) -> int:
    try:
        result = detect_mod.validate(args.rules)
    except detect_mod.DetectError as exc:
        _emit({"ok": False, "error": str(exc)[:500]})
        return 1
    _emit(result)
    return 0 if result.get("ok") else 2


def cmd_detect_diff(args) -> int:
    try:
        result = detect_mod.diff(args.old, args.new)
    except detect_mod.DetectError as exc:
        _emit({"ok": False, "error": str(exc)[:500]})
        return 1
    _emit(result)
    return 0


def cmd_detect_test(args) -> int:
    try:
        cases = detect_mod._load_cases(args.cases) if args.cases else None
        result = detect_mod.test_cases(cases)
    except detect_mod.DetectError as exc:
        _emit({"ok": False, "error": str(exc)[:500]})
        return 1
    _emit(result)
    return 0 if result.get("ok") else 2


def cmd_detect_replay(args) -> int:
    try:
        result = detect_mod.replay(args.events, args.rules, max_rows=args.max_rows)
    except detect_mod.DetectError as exc:
        _emit({"ok": False, "error": str(exc)[:500]})
        return 1
    _emit(result)
    return 0 if "error" not in result.get("chains", {}) else 2


def cmd_summarize(args) -> int:
    try:
        result = summarize_mod.summarize(
            args.events or _events_path(args.root), since=args.since,
            max_rows=args.max_rows, limit=args.limit, rare_max=args.rare_max)
    except (query_mod.QueryError, OSError) as exc:
        _emit({"ok": False, "error": str(exc)[:500], "code": "QUERY_ERROR"})
        return 1
    _emit(result)
    return 0


def _profile_path(args) -> str:
    if getattr(args, "profile", None):
        return args.profile
    return str(Path(args.root or profile_root()) / "profile.json")


def profile_root() -> str:
    return "C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma"


def _load_profile_arg(args):
    path = _profile_path(args)
    try:
        return profile.load(path), path
    except (OSError, ValueError, TypeError) as exc:
        _emit({"ok": False, "error": f"cannot read profile {path}: {exc}"})
        return None, path


def _plugin_error(exc) -> int:
    _emit({"ok": False, "error": str(exc)[:500]})
    return 1


def _secret(args):
    if getattr(args, "secret_env", None):
        return os.environ.get(args.secret_env)
    return getattr(args, "secret", None)


def cmd_ingest_jsonl(args) -> int:
    _emit(plugin_io.ingest_jsonl(
        args.path, args.events or _events_path(args.root),
        max_events=args.max_events, host=args.host))
    return 0


def cmd_ingest_evtx(args) -> int:
    result = plugin_io.ingest_evtx(
        args.channel, args.events or _events_path(args.root),
        since_minutes=args.since, max_events=args.max_events,
        host=args.host)
    _emit(result)
    return 0 if result.get("ok") else 2


def cmd_ingest_webhook(args) -> int:
    secret = _secret(args)
    _emit(plugin_io.serve_webhook(
        args.bind, args.port, args.path, secret,
        args.events or _events_path(args.root), max_events=args.max_events,
        seconds=args.seconds, once=args.once, host=args.host))
    return 0


def cmd_export_webhook(args) -> int:
    secret = _secret(args)
    result = plugin_io.export_webhook(
        args.url, args.events or _events_path(args.root), args.root,
        secret=secret, since=args.since, max_events=args.max_events,
        batch_size=args.batch_size)
    _emit(result)
    return 0 if result.get("ok") else 2


def cmd_export_syslog(args) -> int:
    result = plugin_io.export_syslog(
        args.host, args.port, args.protocol,
        args.events or _events_path(args.root),
        since=args.since, max_events=args.max_events)
    _emit(result)
    return 0 if result.get("ok") else 2


def cmd_plugin_actions(args) -> int:
    _emit(plugin_actions.list_actions(args.root))
    return 0


def cmd_plugin_act(args) -> int:
    try:
        payload = json.loads(args.args or "{}")
    except json.JSONDecodeError as exc:
        _emit({"ok": False, "error": f"--args is not JSON: {exc}"})
        return 1
    try:
        if args.apply:
            result = plugin_actions.apply(
                args.root, args.name, payload, args.plan, args.reason or "")
        else:
            result = plugin_actions.preview(args.root, args.name, payload)
    except (plugin_api.PluginError, OSError) as exc:
        return _plugin_error(exc)
    _emit(result)
    return 0 if result.get("ok") else 2


def cmd_plugin_undo(args) -> int:
    try:
        result = plugin_actions.undo(args.root, args.journal_id,
                                     args.reason or "")
    except (plugin_api.PluginError, OSError) as exc:
        return _plugin_error(exc)
    _emit(result)
    return 0 if result.get("ok") else 2


def cmd_plugin_list(args) -> int:
    _emit(plugins.list_plugins(args.root))
    return 0


def cmd_plugin_install(args) -> int:
    try:
        _emit(plugins.install(
            args.root, args.path, allow_unsigned=args.allow_unsigned,
            trust_key=args.pubkey, force=args.force, enable=args.enable))
    except (plugin_api.PluginError, OSError) as exc:
        return _plugin_error(exc)
    return 0


def cmd_plugin_verify(args) -> int:
    try:
        result = plugins.verify(args.root, args.name, trust_key=args.pubkey)
    except (plugin_api.PluginError, OSError) as exc:
        return _plugin_error(exc)
    _emit(result)
    return 0 if result.get("ok") else 2


def cmd_plugin_remove(args) -> int:
    try:
        _emit(plugins.uninstall(args.root, args.name))
    except (plugin_api.PluginError, OSError) as exc:
        return _plugin_error(exc)
    return 0


def cmd_plugin_enable(args) -> int:
    try:
        _emit(plugins.set_enabled(args.root, args.name, True))
    except (plugin_api.PluginError, OSError) as exc:
        return _plugin_error(exc)
    return 0


def cmd_plugin_disable(args) -> int:
    try:
        _emit(plugins.set_enabled(args.root, args.name, False))
    except (plugin_api.PluginError, OSError) as exc:
        return _plugin_error(exc)
    return 0


def cmd_plugin_run(args) -> int:
    try:
        _entry, manifest, _base = plugins.load_installed(args.root, args.name)
        if manifest.get("kind") == "detector":
            result = plugin_host.run_detector(
                args.root, args.name, out_events=args.events,
                since=args.since, max_rows=args.max_rows,
                timeout_seconds=args.timeout)
        else:
            result = plugin_host.run_sensor(
                args.root, args.name, out_events=args.events,
                max_events=args.max_events, timeout_seconds=args.timeout,
                force=args.force)
    except (plugin_api.PluginError, OSError) as exc:
        return _plugin_error(exc)
    _emit(result)
    return 0 if result.get("ok") else 2


def cmd_plugin_health(args) -> int:
    try:
        result = plugins.health(args.root, args.name)
    except (plugin_api.PluginError, OSError) as exc:
        return _plugin_error(exc)
    _emit(result)
    return 0 if result.get("ok") else 2


def cmd_plugin_new(args) -> int:
    try:
        _emit(plugins.scaffold(args.out, args.name, args.kind))
    except (plugin_api.PluginError, OSError) as exc:
        return _plugin_error(exc)
    return 0


def cmd_plugin_keygen(args) -> int:
    try:
        _emit(plugin_api.keygen(args.out))
    except (plugin_api.PluginError, OSError, ImportError) as exc:
        return _plugin_error(exc)
    return 0


def cmd_plugin_sign(args) -> int:
    try:
        _emit(plugin_api.sign(args.plugin, args.key))
    except (plugin_api.PluginError, OSError, ImportError) as exc:
        return _plugin_error(exc)
    return 0


def cmd_profile_build(args) -> int:
    try:
        built = profile.build(
            args.events or _events_path(args.root), host=args.host,
            role=args.role, max_rows=args.max_rows, since=args.since)
    except (OSError, ValueError) as exc:
        _emit({"ok": False, "error": str(exc)[:500]})
        return 1
    if args.out:
        saved = profile.save(args.out, built)
        summary = profile.summary(built)
        payload = {"ok": True, **saved, "summary": summary}
        if args.full:
            payload["profile"] = built
        _emit(payload)
        return 0
    _emit(profile.summary(built) if not args.full else built)
    return 0


def cmd_profile_show(args) -> int:
    loaded, path = _load_profile_arg(args)
    if loaded is None:
        return 1
    if args.full:
        _emit(loaded)
    else:
        _emit({"path": path, **profile.summary(loaded)})
    return 0


def cmd_profile_diff(args) -> int:
    try:
        old = profile.load(args.old)
        new = profile.load(args.new)
    except (OSError, ValueError, TypeError) as exc:
        _emit({"ok": False, "error": str(exc)[:500]})
        return 1
    result = profile.diff(old, new, limit=args.limit)
    _emit(result)
    return 0


def cmd_profile_merge(args) -> int:
    try:
        loaded = [profile.load(path) for path in args.profiles]
        merged = profile.merge(loaded, name=args.name)
    except (OSError, ValueError, TypeError) as exc:
        _emit({"ok": False, "error": str(exc)[:500]})
        return 1
    saved = profile.save(args.out, merged)
    _emit({"ok": True, **saved, "hosts": merged["hosts"],
           "n": merged["n"]})
    return 0


def cmd_profile_verify(args) -> int:
    try:
        loaded = profile.load(_profile_path(args))
    except (OSError, ValueError, TypeError) as exc:
        _emit({"ok": False, "error": str(exc)[:500]})
        return 1
    verdict = profile.verify(loaded)
    _emit({"host": loaded.get("host"), **verdict})
    return 0 if verdict.get("ok") else 2


def cmd_anomaly_score(args) -> int:
    loaded, path = _load_profile_arg(args)
    if loaded is None:
        return 1
    estate = None
    if args.estate:
        try:
            estate = profile.load(args.estate)
        except (OSError, ValueError, TypeError) as exc:
            _emit({"ok": False, "error": f"cannot read estate profile: {exc}"})
            return 1
    try:
        result = anomaly.rank(
            args.events or _events_path(args.root), loaded, estate=estate,
            since=args.since, max_rows=args.max_rows, limit=args.limit,
            include_suppressed=args.include_suppressed,
            include_self=args.include_self)
    except (OSError, ValueError) as exc:
        _emit({"ok": False, "error": str(exc)[:500]})
        return 1
    _emit({"profile_path": path, **result})
    return 0


def cmd_anomaly_explain(args) -> int:
    loaded, path = _load_profile_arg(args)
    if loaded is None:
        return 1
    estate = None
    if args.estate:
        try:
            estate = profile.load(args.estate)
        except (OSError, ValueError, TypeError) as exc:
            _emit({"ok": False, "error": f"cannot read estate profile: {exc}"})
            return 1
    try:
        result = anomaly.explain(
            args.events or _events_path(args.root), loaded,
            contains=args.contains, ts=args.ts, estate=estate,
            since=args.since, max_rows=args.max_rows)
    except (OSError, ValueError) as exc:
        _emit({"ok": False, "error": str(exc)[:500]})
        return 1
    _emit({"profile_path": path, **result})
    return 0 if result.get("ok") else 2


def cmd_anomaly_trace(args) -> int:
    loaded = None
    if args.profile:
        loaded, _path = _load_profile_arg(args)
        if loaded is None:
            return 1
    try:
        result = anomaly.traces(
            args.events or _events_path(args.root), loaded, since=args.since,
            max_rows=args.max_rows, limit=args.limit,
            min_spans=args.min_spans, gap_seconds=args.gap,
            include_self=args.include_self)
    except (OSError, ValueError) as exc:
        _emit({"ok": False, "error": str(exc)[:500]})
        return 1
    _emit(result)
    return 0


def cmd_case_open(args) -> int:
    try:
        result = case_mod.open_case(
            args.root, args.name, host=args.host, note=args.note,
            title=args.title)
    except (case_mod.CaseError, OSError) as exc:
        _emit({"ok": False, "error": str(exc)[:500]})
        return 1
    _emit(result)
    return 0


def cmd_case_list(args) -> int:
    _emit({"ok": True, **case_mod.list_cases(args.root)})
    return 0


def cmd_case_add(args) -> int:
    try:
        spec = _query_spec_from_args(args)
        if not spec:
            raise case_mod.CaseError(
                "case add requires a filter or --spec; refusing to copy "
                "the whole store")
        result = case_mod.add_query(
            args.root, args.name, spec,
            events_path=args.events or _events_path(args.root))
    except (case_mod.CaseError, query_mod.QueryError, OSError) as exc:
        _emit({"ok": False, "error": str(exc)[:500]})
        return 1
    _emit(result)
    return 0


def cmd_case_note(args) -> int:
    try:
        result = case_mod.add_note(args.root, args.name, args.text)
    except (case_mod.CaseError, OSError) as exc:
        _emit({"ok": False, "error": str(exc)[:500]})
        return 1
    _emit(result)
    return 0


def cmd_case_timeline(args) -> int:
    try:
        result = case_mod.timeline(args.root, args.name)
    except (case_mod.CaseError, OSError) as exc:
        _emit({"ok": False, "error": str(exc)[:500]})
        return 1
    _emit(result)
    return 0


def cmd_case_report(args) -> int:
    try:
        result = case_mod.report(args.root, args.name)
    except (case_mod.CaseError, OSError) as exc:
        _emit({"ok": False, "error": str(exc)[:500]})
        return 1
    if args.out:
        try:
            Path(args.out).write_text(result["markdown"], encoding="utf-8")
            result = {**result, "path": args.out}
        except OSError as exc:
            _emit({"ok": False, "error": f"cannot write --out: {exc}"})
            return 1
    _emit(result)
    return 0


def cmd_case_seal(args) -> int:
    try:
        result = case_mod.seal(args.root, args.name)
    except (case_mod.CaseError, OSError) as exc:
        _emit({"ok": False, "error": str(exc)[:500]})
        return 1
    _emit(result)
    return 0


def cmd_case_verify(args) -> int:
    try:
        result = case_mod.verify(args.root, args.name)
    except (case_mod.CaseError, OSError) as exc:
        _emit({"ok": False, "error": str(exc)[:500]})
        return 1
    _emit(result)
    return 0 if result.get("ok") else 2


def cmd_memory_scan(args) -> int:
    result = memory.scan(
        args.root, pids=args.pid, pnames=args.pname,
        all_processes=args.all, dump=args.dump, deep=args.deep,
        timeout=args.timeout, scanner=args.scanner,
        events_path=args.events or _events_path(args.root),
        no_events=args.no_events, no_dedupe=args.no_dedupe)
    _emit(result)
    if "error" in result:
        return 1
    return 2 if result.get("findings") else 0


def cmd_memory_status(args) -> int:
    _emit({"ok": True, **memory.status(args.root)})
    return 0


def cmd_memory_list(args) -> int:
    _emit({"ok": True, **memory.list_scans(args.root)})
    return 0


def cmd_memory_triage(args) -> int:
    result = memory.triage(
        args.root, events_path=args.events or _events_path(args.root),
        min_score=args.min_score, since_minutes=args.since_minutes,
        max_targets=args.max_targets, deep=not args.no_deep,
        timeout=args.timeout)
    _emit(result)
    if result.get("code") == "NO_TARGETS":
        return 0
    return 0 if result.get("ok") else 1


def cmd_fim_baseline(args) -> int:
    result = fim.baseline(args.root, args.path or None)
    print(json.dumps(result, indent=2, default=str))
    return 0


def cmd_fim_verify(args) -> int:
    result = fim.verify(args.root)
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("top_score", 0) == 0 and "error" not in result else 2


def cmd_fim_status(args) -> int:
    result = fim.status(args.root)
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("baselined") else 1

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
    result = watch.watch_once(args.root, quiet_clean=not args.notify_clean,
                              canary_accounts=args.canary_account or None)
    print(json.dumps({k: v for k, v in result.items() if k != "notify"}, indent=2, default=str))
    n = result.get("notify")
    if n is not None:
        print(json.dumps({"notify": n}, indent=2))
    if getattr(args, "enforce", False):
        # Policy decides whether anything is actually applied; watch only
        # supplies the findings. Dry-run remains the default.
        print(json.dumps({"enforce": enforce.run(
            args.root, findings=result.get("findings", []))},
            indent=2, default=str))
    return 0 if result["top_score"] == 0 else 2


def cmd_watch_loop(args) -> int:
    import time as _time
    while True:
        result = watch.watch_once(args.root, quiet_clean=True,
                                  canary_accounts=args.canary_account or None)
        line = {"at": result["at"], "verdict": result["verdict"],
                "top_score": result["top_score"]}
        if getattr(args, "enforce", False):
            line["enforce"] = enforce.run(
                args.root, findings=result.get("findings", []))
        print(json.dumps(line, default=str))
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
    try:
        rel = updater.latest_release(args.repo, token)
    except Exception as exc:  # noqa: BLE001 - update failures are data
        print(json.dumps({"ok": False, "stage": "fetch",
                          "error": f"{type(exc).__name__}: {exc}"[:300]},
                         indent=2))
        return 1
    newer = updater.is_newer(__version__, rel["tag"])
    state = statemachine.load(Path(args.root), statemachine.UPDATE_MACHINE)["state"]
    print(json.dumps({"current": __version__, "latest": rel["tag"],
                      "update_available": newer,
                      "published_at": rel.get("published_at"),
                      "state": state}, indent=2))
    return 2 if newer else 0   # scriptable: 0 = up to date, 2 = update available


def _update_apply_locked(args) -> int:
    # public repo: anonymous works; a token is optional (private forks)
    token = os.environ.get(args.token_env, "")
    root = Path(args.root)
    if getattr(args, "ring", None):
        host = autoupdate.socket.gethostname() or "localhost"
        if not autoupdate.ring_ok(root, host, args.ring):
            print(json.dumps({
                "ok": False,
                "error": f"host {host!r} is not in ring {args.ring!r}",
                "hint": "assign the host with: plasma ring assign <host> --ring <ring>",
            }, indent=2))
            return 2
    def _state(target, detail=None):
        try:
            statemachine.transition(root, statemachine.UPDATE_MACHINE, target, detail)
        except statemachine.StateError:
            pass

    try:
        if statemachine.load(root, statemachine.UPDATE_MACHINE)["state"] != "idle":
            statemachine.reset(root, statemachine.UPDATE_MACHINE, "new update run")
    except Exception:  # noqa: BLE001, S110 — state is observability, not a gate
        pass

    staged = root / "tools" / "plasma-update-staged.exe"
    try:
        res = updater.download_and_verify(args.repo, getattr(args, "tag", "") or "",
                                          token, staged)
    except Exception as exc:  # noqa: BLE001 - network failures are data
        _state("failed", "download failed")
        print(json.dumps({"ok": False, "stage": "download",
                          "error": f"{type(exc).__name__}: {exc}"[:300]},
                         indent=2))
        return 1
    print(json.dumps({"stage": "download", **{k: v for k, v in res.items() if k != 'ok'}}, indent=2, default=str))
    if not res["ok"]:
        _state("failed", "download failed")
        return 1
    _state("staged", f"tag={res.get('tag')}")
    # SECOND trust anchor: the exe must be signed by a pinned certificate
    # before we execute it. SHA256SUMS + exe share one origin (the release);
    # the signer thumbprint is baked into THIS binary.
    sig = updater.verify_authenticode(staged)
    print(json.dumps({"stage": "signature", **sig}, indent=2, default=str))
    if not sig.get("ok") and not getattr(args, "allow_unsigned", False):
        _state("failed", "signature verification failed")
        print(json.dumps({"ok": False,
                          "error": "refusing to execute an update with an unverified signer",
                          "hint": "dev builds may pass --allow-unsigned"},
                         indent=2))
        return 2
    _state("verified", sig.get("status") or "signature ok")
    # forward the root: a node installed at a custom root must not have its
    # new version configured under the default location (split-brain install)
    _state("installing")
    try:
        inst = subprocess.run(
            [str(staged), "install", "--force", "--root", str(root)],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=900, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        _state("failed", "install failed to run")
        print(json.dumps({"ok": False, "stage": "install",
                          "error": str(exc)[:300]}, indent=2))
        return 3
    if inst.stdout:
        print(inst.stdout[-800:], file=sys.stderr)
    if inst.returncode != 0:
        _state("failed", f"install rc={inst.returncode}")
        print(inst.stderr[-400:], file=sys.stderr)
        return 3
    _state("installed", f"tag={res.get('tag')}")
    bin_exe = Path(args.bin) if args.bin else root / "bin" / Path(sys.executable).name
    rotated = autoupdate.rotate_running(staged, bin_exe)
    rot = rotated["rotation"]
    print(json.dumps({"stage": "bin_rotation", **rot,
                      "canonical": rotated["canonical"],
                      "stopped": rotated["stopped"],
                      "started": rotated["started"]},
                     indent=2, default=str))
    if not rot.get("ok"):
        _state("failed", "bin rotation failed")
        return 4
    if rotated["canonical"] and not rotated["canonical"].get("ok"):
        _state("failed", "canonical bin rotation failed")
        print(json.dumps({"ok": False, "stage": "rotate_canonical",
                          "error": rotated["canonical"].get("error")},
                         indent=2))
        return 4
    _state("rotated", f"tag={res.get('tag')}")
    print(json.dumps({"ok": True, "updated_to": res.get("tag")}, indent=2))
    return 0


def cmd_update_apply(args) -> int:
    """Manual apply shares the self-update lock with the daily task."""
    root = Path(args.root)
    try:
        with agentstate.lock(root / "update-auto.lock", timeout=5, stale=3600):
            return _update_apply_locked(args)
    except TimeoutError:
        print(json.dumps({"ok": False, "status": "skipped",
                          "reason": "another update is already running"},
                         indent=2))
        return 2


def cmd_update_auto(args) -> int:
    result = autoupdate.auto(
        args.root, repo=args.repo, ring=args.ring,
        check_only=args.check_only, force=args.force,
        allow_unsigned=True if args.allow_unsigned else None,
        notify_enabled=False if args.no_notify else None,
        token=os.environ.get(args.token_env, ""),
    )
    _emit(result)
    status = result.get("status")
    if status in ("refused", "signature"):
        return 2
    if status == "failed":
        return 3
    if args.check_only and result.get("update_available"):
        return 2
    return 0


def cmd_identity_schedule(args) -> int:
    result = identity.schedule(args.root, every_minutes=args.every, exe=args.exe)
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("ok") else 1


def cmd_identity_unschedule(args) -> int:
    result = identity.unschedule()
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("ok") else 1


def cmd_identity_schedule_status(args) -> int:
    result = identity.schedule_status()
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("installed") else 1


def cmd_identity_pull(args) -> int:
    result = identity.pull(args.events, host=args.host or _platform.node() or "localhost",
                           since_minutes=args.since, ids=args.ids,
                           max_events=args.max_events)
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 1


def cmd_prevent_status(args) -> int:
    print(json.dumps(prevent.status(), indent=2, default=str))
    return 0


def cmd_prevent_posture(args) -> int:
    result = prevent.posture()
    _emit(result)
    return 0 if result.get("ok") else 2


def cmd_prevent_applocker(args) -> int:
    result = prevent.applocker(args.root, mode=args.mode,
                               allow_paths=args.allow_path,
                               apply=args.apply, plan=args.plan,
                               reason=args.reason)
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 2


def cmd_prevent_egress(args) -> int:
    result = prevent.egress(args.root, args.allow, apply=args.apply,
                            plan=args.plan, reason=args.reason)
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 2


def cmd_prevent_asr(args) -> int:
    result = prevent.asr(args.ids, action=args.action, apply=args.apply,
                         plan=args.plan, reason=args.reason, root=args.root)
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 2


def cmd_prevent_defender(args) -> int:
    result = prevent.defender_preference(
        args.control, mode=args.mode, apply=args.apply, plan=args.plan,
        reason=args.reason, root=args.root)
    _emit(result)
    return 0 if "error" not in result else 2


def cmd_prevent_driver_blocklist(args) -> int:
    result = prevent.driver_blocklist(
        apply=args.apply, plan=args.plan, reason=args.reason,
        root=args.root, enable=not args.off)
    _emit(result)
    return 0 if "error" not in result else 2


def cmd_prevent_lsa(args) -> int:
    result = prevent.lsa(apply=args.apply, plan=args.plan, reason=args.reason,
                         root=args.root, enable=not args.disable)
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 2


def cmd_prevent_rollback(args) -> int:
    result = prevent.rollback(args.root, args.id, apply=args.apply,
                              plan=args.plan, reason=args.reason)
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 2


def cmd_enforce_run(args) -> int:
    findings = None
    if args.findings:
        try:
            findings = json.loads(Path(args.findings).read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            print(json.dumps({"error": f"cannot read findings: {exc}"}, indent=2))
            return 2
        if isinstance(findings, dict):
            findings = findings.get("findings", [findings])
        if not isinstance(findings, list):
            print(json.dumps({"error": "findings file must contain a list"}, indent=2))
            return 2
    result = enforce.run(args.root, findings=findings,
                         apply=True if args.apply else
                         (False if args.dry_run else None))
    print(json.dumps(result, indent=2, default=str))
    return 0 if not any(r["status"] == "refused" for r in result["results"]) else 1


def cmd_enforce_status(args) -> int:
    print(json.dumps(enforce.status(args.root), indent=2, default=str))
    return 0


def cmd_enforce_pending(args) -> int:
    result = enforce.pending(args.root)
    print(json.dumps(result, indent=2, default=str))
    return 0


def cmd_enforce_approve(args) -> int:
    result = enforce.approve(args.root, args.id, apply=args.apply)
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 2


def cmd_protect_status(args) -> int:
    _emit(protect.status(args.root))
    return 0


def cmd_protect_arm(args) -> int:
    result = protect.arm(args.root, apply_prevention=args.apply_prevention,
                         reason=args.reason)
    _emit(result)
    return 0 if result.get("ok") else 1


def cmd_protect_disarm(args) -> int:
    _emit(protect.disarm(args.root, reason=args.reason))
    return 0


def cmd_protect_protected(args) -> int:
    _emit(protect.protected())
    return 0


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


def cmd_fleet_profiles(args) -> int:
    result = fleet.pull_profiles(
        args.inventory, args.out_dir, max_rows=args.max_rows,
        role=args.role, baseline=args.baseline)
    _emit(result)
    return 0 if result.get("ok") else 2


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


# ---------------------------------------------------------------------------
# Agent-native trust layer (v1.7.0)
# ---------------------------------------------------------------------------

def _emit(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def cmd_control_policy_show(args) -> int:
    _emit({"policy": agent_policy.load(args.root),
           "killswitch": killswitch.status(args.root)})
    return 0


def cmd_control_policy_set(args) -> int:
    current = agent_policy.load(args.root)
    if args.autonomy:
        current["autonomy"] = args.autonomy
    if args.deny is not None:
        current["deny"] = args.deny
    if args.allow is not None:
        current["allow"] = args.allow
    if args.max_actions is not None:
        current["max_actions_per_minute"] = args.max_actions
    if args.max_hosts is not None:
        current["max_hosts_per_action"] = args.max_hosts
    if args.allow_critical is not None:
        current["allow_critical"] = args.allow_critical
    try:
        _emit(agent_policy.save(args.root, current))
    except ValueError as exc:
        _emit({"error": str(exc)})
        return 1
    return 0


def cmd_control_policy_simulate(args) -> int:
    text = args.args or "{}"
    if args.args_file:
        try:
            text = Path(args.args_file).read_text(encoding="utf-8-sig")
        except OSError as exc:
            _emit({"ok": False, "error": f"cannot read --args-file: {exc}"})
            return 1
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        _emit({"ok": False, "error": f"--args is not JSON: {exc}"})
        return 1
    if not isinstance(payload, dict):
        _emit({"ok": False, "error": "--args must be a JSON object"})
        return 1
    context = {}
    if args.scopes:
        context["scopes"] = [s.strip() for s in args.scopes.split(",") if s.strip()]
    result = agent_policy.simulate(
        args.tool, payload, context=context,
        recent_actions=args.recent_actions,
        killswitch_blocked=args.killswitch_blocked)
    _emit(result)
    return 0 if result.get("ok") else 2


def cmd_control_approvals_list(args) -> int:
    _emit({"approvals": ledger.pending_approvals(args.root, limit=args.limit)})
    return 0


def _approval_action(args, approve: bool) -> int:
    try:
        row = ledger.approve(args.root, args.id, args.approver, args.note,
                             approve_action=approve)
    except ledger.LedgerError as exc:
        _emit({"error": str(exc)})
        return 1
    _emit(row)
    return 0


def cmd_control_approvals_approve(args) -> int:
    return _approval_action(args, True)


def cmd_control_approvals_deny(args) -> int:
    return _approval_action(args, False)


def cmd_control_audit_tail(args) -> int:
    _emit({"ledger": ledger.tail(args.root, args.last)})
    return 0


def cmd_control_audit_verify(args) -> int:
    result = ledger.verify(args.root)
    _emit(result)
    return 0 if result.get("ok") else 2


def cmd_control_killswitch_status(args) -> int:
    _emit(killswitch.status(args.root))
    return 0


def cmd_control_killswitch_on(args) -> int:
    if args.host:
        _emit(killswitch.set_host(args.root, args.host, True, args.reason))
    else:
        _emit(killswitch.set_global(args.root, True, args.reason))
    return 0


def cmd_control_killswitch_off(args) -> int:
    if args.host:
        _emit(killswitch.set_host(args.root, args.host, False, args.reason))
    else:
        _emit(killswitch.set_global(args.root, False, args.reason))
    return 0


def cmd_control_tenants_list(args) -> int:
    _emit({"tenants": tenants.list_tenants(args.root)})
    return 0


def cmd_control_tenants_add(args) -> int:
    try:
        _emit(tenants.add(args.root, args.tenant, args.name, args.host))
    except ValueError as exc:
        _emit({"error": str(exc)})
        return 1
    return 0


def cmd_control_tenants_remove(args) -> int:
    try:
        _emit(tenants.remove(args.root, args.tenant))
    except (ValueError, KeyError) as exc:
        _emit({"error": str(exc)})
        return 1
    return 0


def cmd_mcp_serve(args) -> int:
    return mcp_server.serve(args.root)


def cmd_serve(args) -> int:
    """HTTP API for the full CLI (alternative to WinRM/SSH)."""
    from . import serve as serve_mod
    try:
        return serve_mod.serve(
            root=args.root, host=args.host, port=args.port,
            api_key=args.api_key, api_key_file=args.api_key_file,
            read_only=args.read_only, tls_cert=args.tls_cert,
            tls_key=args.tls_key, timeout=args.timeout,
            max_body=args.max_body, max_output=args.max_output,
            audit=not args.no_audit, quiet=args.quiet,
            allow_insecure_default_key=args.allow_insecure_default_key,
        )
    except (OSError, ValueError, serve_mod.ServeError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 2


def cmd_evidence_export(args) -> int:
    try:
        result = evidence.export(args.root, args.framework or None, args.out)
    except ValueError as exc:
        _emit({"error": str(exc)})
        return 1
    _emit(result)
    return 0


def cmd_assurance_sbom(args) -> int:
    _emit(assurance.write_sbom(args.root, args.out))
    return 0


def cmd_assurance_safety(args) -> int:
    result = assurance.safety_case(args.root, args.out)
    _emit({k: v for k, v in result.items() if k != "markdown"})
    return 0 if result.get("ok") else 2


def cmd_assurance_bundle(args) -> int:
    _emit(assurance.support_bundle(args.root, args.out))
    return 0


def cmd_assurance_notices(args) -> int:
    print(assurance.third_party_notices())
    return 0


def cmd_eval_run(args) -> int:
    result = evals.run(args.root)
    _emit(result)
    return 0 if result.get("failed") == 0 else 2


def cmd_ring_status(args) -> int:
    _emit(rings.status(args.root))
    return 0


def cmd_ring_assign(args) -> int:
    try:
        _emit(rings.assign(args.root, args.host, args.ring))
    except ValueError as exc:
        _emit({"error": str(exc)})
        return 1
    return 0


def cmd_ring_promote(args) -> int:
    try:
        _emit(rings.promote(args.root, args.ring))
    except ValueError as exc:
        _emit({"error": str(exc)})
        return 1
    return 0


def cmd_rollback(args) -> int:
    bin_exe = (Path(args.bin) if args.bin else
               agentstate.base(args.root) / "bin" / Path(sys.executable).name)
    result = rings.rollback(bin_exe)
    _emit(result)
    return 0 if result.get("ok") else 1


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


def cmd_help(args) -> int:
    """Detailed help, examples and the machine-readable catalog."""
    parser = build_parser()
    if args.json:
        if args.topic:
            node = helpmod.command_json(parser, args.topic)
            if node is None:
                _emit({"ok": False,
                       "error": "unknown command path: " + " ".join(args.topic),
                       "hint": "run `plasma help --json` for the catalog"})
                return 1
            _emit(node)
        else:
            _emit(helpmod.catalog(parser))
        return 0
    if args.topic:
        target = helpmod.find_parser(parser, args.topic)
        if target is None:
            print(json.dumps({
                "ok": False,
                "error": "unknown command path: " + " ".join(args.topic),
                "hint": "run `plasma help` or `plasma help --json`",
            }), file=sys.stderr)
            return 1
        print(target.format_help())
        return 0
    print(helpmod.overview(parser))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="plasma",
        usage="plasma [-h] [--version] <command> [<args>...]",
        description="Plasma EDR bundle tooling")
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
    ins.add_argument("--rotate", action="store_true",
                     help="after install, rotate bin\\plasma.exe and restart tasks "
                          "(used by the MSI so the running node matches the package)")
    ins.add_argument("--no-autoprotect", action="store_true",
                     help="install with automatic containment off (dry-run only)")
    ins.add_argument("--no-autoupdate", action="store_true",
                     help="do not register the daily PlasmaUpdate task")
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

    spe = sns.add_parser("ensure", help="make the WHIDS service Running (heals the 1.7.0 init hang)")
    spe.add_argument("--root", default=None, help="Plasma root (watchdog log location)")
    spe.add_argument("--wait", type=int, default=30, help="seconds to wait per state transition")
    spe.set_defaults(func=cmd_whids_ensure)

    spr = sns.add_parser("prune", help="bound the WHIDS dump tree (detect-only nodes keep none)")
    spr.add_argument("--install-dir", default=None,
                     help="WHIDS install directory (default: %%ProgramFiles%%\\Whids)")
    spr.add_argument("--max-mb", type=int, default=512)
    spr.add_argument("--keep-days", type=int, default=7)
    spr.add_argument("--dry-run", action="store_true")
    spr.set_defaults(func=cmd_whids_prune)

    cn = sub.add_parser("canary", help="decoys and tokens for impact/access detection")
    cns = cn.add_subparsers(dest="canary_action", required=True)
    cnd = cns.add_parser("deploy", help="create canary files and record their hashes")
    cnd.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cnd.add_argument("--dir", action="append", default=[],
                     help="extra directory for canaries (repeatable)")
    cnd.add_argument("--randomize", action=argparse.BooleanOptionalAction,
                     default=True,
                     help="randomize subdirectories and document names (default: true)")
    cnd.add_argument("--subdir", default=None,
                     help="fixed subdirectory name instead of a random one")
    cnd.set_defaults(func=cmd_canary_deploy)
    cnv = cns.add_parser("verify", help="check canaries (exit 2 when tripped)")
    cnv.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cnv.set_defaults(func=cmd_canary_verify)
    cnsx = cns.add_parser("status", help="manifest + current canary state")
    cnsx.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cnsx.set_defaults(func=cmd_canary_status)

    ct = cns.add_parser("token", help="native DNS and HTTP canary tokens")
    cts = ct.add_subparsers(dest="token_action", required=True)
    ctc = cts.add_parser("create", help="create a DNS or HTTP token")
    ctc.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    ctc.add_argument("--kind", required=True, choices=["dns", "http"])
    ctc.add_argument("--domain", default=None,
                     help="DNS suffix for a dns token, e.g. assets.internal")
    ctc.add_argument("--base-url", default=None,
                     help="collector base URL for an http token, e.g. http://collector:8088")
    ctc.add_argument("--out", default=None,
                     help="artifact file or directory (http defaults to <root>/canary-artifacts)")
    ctc.add_argument("--name", default=None, help="plausible artifact filename")
    ctc.add_argument("--label", default=None, help="operator label (not written to the artifact)")
    ctc.set_defaults(func=cmd_canary_token_create)
    ctl = cts.add_parser("list", help="list registered tokens")
    ctl.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    ctl.set_defaults(func=cmd_canary_token_list)
    ctr = cts.add_parser("remove", help="remove a token from the registry")
    ctr.add_argument("token_id", help="token id from `canary token list`")
    ctr.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    ctr.add_argument("--delete-artifact", action="store_true",
                     help="also delete the artifact if it is under --root")
    ctr.set_defaults(func=cmd_canary_token_remove)

    cnsrv = cns.add_parser("serve", help="local HTTP token collector (blocks)")
    cnsrv.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cnsrv.add_argument("--host", default="127.0.0.1")
    cnsrv.add_argument("--port", type=int, default=8088)
    cnsrv.add_argument("--allow-non-loopback", action="store_true",
                       help="required before binding a VLAN/collector interface")
    cnsrv.add_argument("--max-requests", type=int, default=0,
                       help="stop after N valid hits (0 = run until stopped)")
    cnsrv.set_defaults(func=cmd_canary_serve)

    cnc = cns.add_parser("collect", help="collect DNS/HTTP token hits into the event store")
    cnc.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cnc.add_argument("--events", default=None)
    cnc.add_argument("--since", type=int, default=15, help="Sysmon DNS lookback minutes")
    cnc.add_argument("--max-events", type=int, default=500)
    cnc.set_defaults(func=cmd_canary_collect)

    cnh = cns.add_parser("hits", help="show recent canary alert rows")
    cnh.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cnh.add_argument("--events", default=None)
    cnh.add_argument("--last", type=int, default=50)
    cnh.set_defaults(func=cmd_canary_hits)

    cnsy = cns.add_parser("sysmon", help="write/apply a narrow Sysmon DnsQuery include")
    cnsy.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cnsy.add_argument("--domain", action="append", default=[],
                      help="DNS suffix to include (default: registered token domains)")
    cnsy.add_argument("--apply", action="store_true",
                      help="hot-reload the generated config through Sysmon64.exe -c")
    cnsy.set_defaults(func=cmd_canary_sysmon)

    cpipe = cns.add_parser("pipe",
                           help="named-pipe canaries that kill the client that connects")
    cps = cpipe.add_subparsers(dest="pipe_action", required=True)
    cpd = cps.add_parser("deploy", help="create decoy pipe names")
    cpd.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cpd.add_argument("--count", type=int, default=1)
    cpd.set_defaults(func=cmd_canary_pipe_deploy)
    cpl = cps.add_parser("list", help="list decoy pipes")
    cpl.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cpl.set_defaults(func=cmd_canary_pipe_list)
    cpr = cps.add_parser("remove", help="remove a decoy pipe")
    cpr.add_argument("pipe_id")
    cpr.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cpr.set_defaults(func=cmd_canary_pipe_remove)
    cpsv = cps.add_parser("serve", help="listen and kill connecting processes (blocks)")
    cpsv.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cpsv.add_argument("--apply", action="store_true")
    cpsv.add_argument("--reason", default=None)
    cpsv.add_argument("--max-kills", dest="max_kills", type=int, default=5)
    cpsv.add_argument("--max-connections", dest="max_connections", type=int, default=0)
    cpsv.set_defaults(func=cmd_canary_pipe_serve)
    cpi = cps.add_parser("install", help="preview/apply the SYSTEM pipe listener task")
    cpi.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cpi.add_argument("--apply", action="store_true")
    cpi.add_argument("--plan", type=int, default=None)
    cpi.add_argument("--reason", default=None)
    cpi.set_defaults(func=cmd_canary_pipe_install)
    cpu = cps.add_parser("uninstall", help="remove the pipe listener task")
    cpu.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cpu.add_argument("--apply", action="store_true")
    cpu.add_argument("--plan", type=int, default=None)
    cpu.add_argument("--reason", default=None)
    cpu.set_defaults(func=cmd_canary_pipe_uninstall)
    cpst = cps.add_parser("status", help="pipe task and last listener state")
    cpst.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cpst.set_defaults(func=cmd_canary_pipe_status)

    csh = cns.add_parser("shield",
                         help="active canary shield: kill the process that writes/deletes a canary")
    cshs = csh.add_subparsers(dest="shield_action", required=True)
    cshst = cshs.add_parser("status", help="shield task, canary counts and last sweep")
    cshst.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cshst.set_defaults(func=cmd_canary_shield_status)
    cshi = cshs.add_parser("install", help="preview/apply narrow Sysmon includes + SYSTEM task")
    cshi.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cshi.add_argument("--apply", action="store_true")
    cshi.add_argument("--plan", type=int, default=None)
    cshi.add_argument("--reason", default=None)
    cshi.set_defaults(func=cmd_canary_shield_install)
    cshu = cshs.add_parser("uninstall", help="remove the task and restore the prior Sysmon config")
    cshu.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cshu.add_argument("--apply", action="store_true")
    cshu.add_argument("--plan", type=int, default=None)
    cshu.add_argument("--reason", default=None)
    cshu.set_defaults(func=cmd_canary_shield_uninstall)
    cshw = cshs.add_parser("sweep", help="read canary events; dry-run or kill accessing processes")
    cshw.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cshw.add_argument("--since-minutes", dest="since_minutes", type=int,
                      default=canary_shield.DEFAULT_SINCE_MINUTES)
    cshw.add_argument("--apply", action="store_true")
    cshw.add_argument("--reason", default=None)
    cshw.add_argument("--max-kills", dest="max_kills", type=int,
                      default=canary_shield.MAX_KILLS)
    cshw.set_defaults(func=cmd_canary_shield_sweep)

    creg = cns.add_parser("registry", help="decoy registry keys for the active shield")
    cregs = creg.add_subparsers(dest="registry_action", required=True)
    cregd = cregs.add_parser("deploy", help="create decoy registry keys")
    cregd.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cregd.add_argument("--hive", choices=["HKCU", "HKLM"], default="HKCU")
    cregd.add_argument("--count", type=int, default=1)
    cregd.set_defaults(func=cmd_canary_registry_deploy)
    cregl = cregs.add_parser("list", help="list decoy registry keys")
    cregl.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cregl.set_defaults(func=cmd_canary_registry_list)
    cregr = cregs.add_parser("remove", help="remove a decoy registry key")
    cregr.add_argument("canary_id")
    cregr.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cregr.set_defaults(func=cmd_canary_registry_remove)

    it = sub.add_parser("intercept",
                        help="deterministic policy at native interception points")
    its = it.add_subparsers(dest="intercept_action", required=True)
    itsx = its.add_parser("status", help="intercept rules and journal summary")
    itsx.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    itsx.set_defaults(func=cmd_intercept_status)

    itr = its.add_parser("rules", help="manage intercept rules")
    itrs = itr.add_subparsers(dest="rules_action", required=True)
    itrl = itrs.add_parser("list", help="list rules")
    itrl.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    itrl.set_defaults(func=cmd_intercept_rules_list)
    itra = itrs.add_parser("add", help="add rules from a JSON file")
    itra.add_argument("--file", required=True)
    itra.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    itra.set_defaults(func=cmd_intercept_rules_add)
    itrr = itrs.add_parser("remove", help="remove a rule")
    itrr.add_argument("rule_id")
    itrr.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    itrr.set_defaults(func=cmd_intercept_rules_remove)

    ite = its.add_parser("evaluate", help="shadow-evaluate rules over the event store")
    ite.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    ite.add_argument("--events", default=None)
    ite.add_argument("--max-rows", type=int, default=5000)
    ite.add_argument("--out", default=None)
    ite.set_defaults(func=cmd_intercept_evaluate)

    ita = its.add_parser("apply", help="apply a native intercept rule (dry-run by default)")
    ita.add_argument("rule_id")
    ita.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    ita.add_argument("--apply", action="store_true")
    ita.add_argument("--plan", type=int, default=None)
    ita.add_argument("--reason", default=None)
    ita.set_defaults(func=cmd_intercept_apply)

    itc = its.add_parser("protect-canary", help="protect canary files with an NTFS deny/audit ACL")
    itc.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    itc.add_argument("--prefix", default=None)
    itc.add_argument("--apply", action="store_true")
    itc.add_argument("--plan", type=int, default=None)
    itc.add_argument("--reason", default=None)
    itc.set_defaults(func=cmd_intercept_protect_canary)

    itb = its.add_parser("rollback", help="undo an intercept apply by journal id")
    itb.add_argument("--id", type=int, required=True)
    itb.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    itb.add_argument("--apply", action="store_true")
    itb.add_argument("--plan", type=int, default=None)
    itb.add_argument("--reason", default=None)
    itb.set_defaults(func=cmd_intercept_rollback)

    qp = sub.add_parser("query",
                        help="typed, bounded queries over the local event store")
    qp.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    qp.add_argument("--events", default=None)
    qp.add_argument("--spec", default=None,
                    help="JSON query object or a path to one")
    qp.add_argument("--host")
    qp.add_argument("--user")
    qp.add_argument("--process")
    qp.add_argument("--parent")
    qp.add_argument("--kind")
    qp.add_argument("--source")
    qp.add_argument("--event-id", dest="event_id", type=int)
    qp.add_argument("--technique")
    qp.add_argument("--contains")
    qp.add_argument("--regex")
    qp.add_argument("--since", help="ISO timestamp or duration such as 15m, 1h, 2d")
    qp.add_argument("--until", help="ISO timestamp or duration")
    qp.add_argument("--min-score", dest="min_score", type=float)
    qp.add_argument("--max-score", dest="max_score", type=float)
    qp.add_argument("--pid", type=int)
    qp.add_argument("--count-by", dest="count_by", choices=query_mod.COUNT_FIELDS)
    qp.add_argument("--order", choices=("asc", "desc"), default=None)
    qp.add_argument("--limit", type=int, default=None)
    qp.add_argument("--max-rows", dest="max_rows", type=int,
                    default=query_mod.DEFAULT_MAX_ROWS)
    qp.add_argument("--out", default=None)
    qp.set_defaults(func=cmd_query)

    dt = sub.add_parser("detect",
                        help="detection-engineering harness: validate, diff, replay")
    dts = dt.add_subparsers(dest="detect_action", required=True)
    dtv = dts.add_parser("validate", help="compile regexes and check rule shape")
    dtv.add_argument("--rules", required=True)
    dtv.set_defaults(func=cmd_detect_validate)
    dtt = dts.add_parser("test",
                         help="run deterministic hit/miss regression cases")
    dtt.add_argument("--cases", default=None,
                     help="JSON case file (default: built-in suite)")
    dtt.set_defaults(func=cmd_detect_test)
    dtd = dts.add_parser("diff", help="compare two rule files by name and hash")
    dtd.add_argument("--old", required=True)
    dtd.add_argument("--new", required=True)
    dtd.set_defaults(func=cmd_detect_diff)
    dtr = dts.add_parser("replay", help="run chains and a summary over a captured store")
    dtr.add_argument("--events", required=True)
    dtr.add_argument("--rules", default=None)
    dtr.add_argument("--max-rows", dest="max_rows", type=int, default=5000)
    dtr.set_defaults(func=cmd_detect_replay)

    sm = sub.add_parser("summarize",
                        help="bounded local digest: processes, lineage, rare commands")
    sm.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    sm.add_argument("--events", default=None)
    sm.add_argument("--since", default=None,
                    help="ISO timestamp or duration such as 15m, 1h, 2d")
    sm.add_argument("--max-rows", dest="max_rows", type=int,
                    default=query_mod.DEFAULT_MAX_ROWS)
    sm.add_argument("--limit", type=int, default=20)
    sm.add_argument("--rare-max", dest="rare_max", type=int, default=2,
                    help="a command line is rare at or below this count")
    sm.set_defaults(func=cmd_summarize)

    tp = sub.add_parser("tree", help="parent/child process lineage from PID edges")
    tp.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    tp.add_argument("--events", default=None)
    tp.add_argument("--pid", type=int, default=None)
    tp.add_argument("--process", default=None)
    tp.add_argument("--depth", type=int, default=3)
    tp.add_argument("--max-rows", dest="max_rows", type=int,
                    default=query_mod.DEFAULT_MAX_ROWS)
    tp.set_defaults(func=cmd_tree)

    cp = sub.add_parser("case", help="durable local case workspace: events, notes, timeline, seal")
    cps = cp.add_subparsers(dest="case_action", required=True)
    cpo = cps.add_parser("open", help="create or reopen a case")
    cpo.add_argument("name")
    cpo.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cpo.add_argument("--host", default=None)
    cpo.add_argument("--title", default=None)
    cpo.add_argument("--note", default=None)
    cpo.set_defaults(func=cmd_case_open)
    cpl = cps.add_parser("list", help="list local cases")
    cpl.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cpl.set_defaults(func=cmd_case_list)
    cpa = cps.add_parser("add", help="run a typed query and copy matches into the case")
    cpa.add_argument("name")
    cpa.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cpa.add_argument("--events", default=None)
    cpa.add_argument("--spec", default=None)
    cpa.add_argument("--host")
    cpa.add_argument("--user")
    cpa.add_argument("--process")
    cpa.add_argument("--parent")
    cpa.add_argument("--kind")
    cpa.add_argument("--source")
    cpa.add_argument("--event-id", dest="event_id", type=int)
    cpa.add_argument("--technique")
    cpa.add_argument("--contains")
    cpa.add_argument("--regex")
    cpa.add_argument("--since")
    cpa.add_argument("--until")
    cpa.add_argument("--min-score", dest="min_score", type=float)
    cpa.add_argument("--max-score", dest="max_score", type=float)
    cpa.add_argument("--pid", type=int)
    cpa.add_argument("--limit", type=int, default=200)
    cpa.add_argument("--max-rows", dest="max_rows", type=int,
                     default=query_mod.DEFAULT_MAX_ROWS)
    cpa.set_defaults(func=cmd_case_add)
    cpn = cps.add_parser("note", help="append an operator note")
    cpn.add_argument("name")
    cpn.add_argument("text")
    cpn.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cpn.set_defaults(func=cmd_case_note)
    cpt = cps.add_parser("timeline", help="merge events, findings and notes on one timeline")
    cpt.add_argument("name")
    cpt.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cpt.set_defaults(func=cmd_case_timeline)
    cpr = cps.add_parser("report", help="render a Markdown case report")
    cpr.add_argument("name")
    cpr.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cpr.add_argument("--out", default=None)
    cpr.set_defaults(func=cmd_case_report)
    cpsl = cps.add_parser("seal", help="hash all artifacts into a sealed manifest")
    cpsl.add_argument("name")
    cpsl.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cpsl.set_defaults(func=cmd_case_seal)
    cpv = cps.add_parser("verify", help="verify a sealed case has not changed")
    cpv.add_argument("name")
    cpv.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    cpv.set_defaults(func=cmd_case_verify)

    mem = sub.add_parser("memory",
                         help="bounded on-demand process-memory scanning")
    mems = mem.add_subparsers(dest="memory_action", required=True)
    memsc = mems.add_parser("scan", help="scan targeted processes with HollowsHunter")
    memsc.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    memsc.add_argument("--pid", action="append", type=int, default=[])
    memsc.add_argument("--pname", action="append", default=[])
    memsc.add_argument("--all", action="store_true",
                       help="scan all processes (explicit; can be slow)")
    memsc.add_argument("--deep", action="store_true",
                       help="add shellcode, IAT and thread-stack scans")
    memsc.add_argument("--dump", action="store_true",
                       help="write scanner artifacts under the Plasma root (sensitive)")
    memsc.add_argument("--timeout", type=int, default=300)
    memsc.add_argument("--scanner", choices=["64", "32"], default="64")
    memsc.add_argument("--events", default=None)
    memsc.add_argument("--no-events", action="store_true")
    memsc.add_argument("--no-dedupe", action="store_true")
    memsc.set_defaults(func=cmd_memory_scan)
    memst = mems.add_parser("status", help="scanner availability and last scan")
    memst.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    memst.set_defaults(func=cmd_memory_status)
    memls = mems.add_parser("list", help="recent memory scans")
    memls.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    memls.set_defaults(func=cmd_memory_list)
    memt = mems.add_parser("triage", help="scan PIDs selected from high-signal alerts")
    memt.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    memt.add_argument("--events", default=None)
    memt.add_argument("--since-minutes", dest="since_minutes", type=int, default=60)
    memt.add_argument("--min-score", dest="min_score", type=float, default=0.7,
                      help="0-1 alert score threshold (default 0.7)")
    memt.add_argument("--max-targets", dest="max_targets", type=int, default=5)
    memt.add_argument("--no-deep", action="store_true")
    memt.add_argument("--timeout", type=int, default=300)
    memt.set_defaults(func=cmd_memory_triage)

    fm = sub.add_parser("fim", help="critical-file integrity monitoring")
    fms = fm.add_subparsers(dest="fim_action", required=True)
    fmb = fms.add_parser("baseline", help="record hashes for critical paths")
    fmb.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    fmb.add_argument("--path", action="append", default=[],
                     help="extra path or glob (repeatable)")
    fmb.set_defaults(func=cmd_fim_baseline)
    fmv = fms.add_parser("verify", help="diff critical files against the baseline")
    fmv.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    fmv.set_defaults(func=cmd_fim_verify)
    fmsx = fms.add_parser("status", help="FIM baseline summary")
    fmsx.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    fmsx.set_defaults(func=cmd_fim_status)

    sg = sub.add_parser("sigma", help="Sigma rule conversion to WHIDS gene JSONL")
    sgs = sg.add_subparsers(dest="sigma_action", required=True)
    sgc = sgs.add_parser("convert", help="convert Sigma YAML files to a .gen rule file")
    sgc.add_argument("--in", dest="inp", required=True,
                     help="Sigma file or directory")
    sgc.add_argument("--out", default="sensors/plasma-sigma.gen")
    sgc.add_argument("--dry-run", action="store_true")
    sgc.set_defaults(func=cmd_sigma_convert)
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
    acu.add_argument("--plan", type=int, default=None, help="id of the prior undo dry-run")
    acu.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    acu.add_argument("--timeout", type=int, default=60)
    acu.set_defaults(func=cmd_actuate_undo)

    ing = sub.add_parser(
        "ingest", help="bounded event ingest adapters (jsonl, evtx, webhook)")
    ings = ing.add_subparsers(dest="ingest_action", required=True)
    _ingest_root = "C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma"

    ingj = ings.add_parser("jsonl", help="ingest a bounded JSONL file")
    ingj.add_argument("path")
    ingj.add_argument("--events", default=None)
    ingj.add_argument("--root", default=_ingest_root)
    ingj.add_argument("--max-events", dest="max_events", type=int,
                      default=plugin_io.DEFAULT_MAX_EVENTS)
    ingj.add_argument("--host", default=None)
    ingj.set_defaults(func=cmd_ingest_jsonl)

    inge = ings.add_parser("evtx", help="read a Windows Event Log channel")
    inge.add_argument("--channel", required=True)
    inge.add_argument("--events", default=None)
    inge.add_argument("--root", default=_ingest_root)
    inge.add_argument("--since", type=int, default=15,
                      help="minutes of history")
    inge.add_argument("--max-events", dest="max_events", type=int,
                      default=plugin_io.DEFAULT_MAX_EVENTS)
    inge.add_argument("--host", default=None)
    inge.set_defaults(func=cmd_ingest_evtx)

    ingw = ings.add_parser("webhook", help="receive bounded JSON events over HTTP")
    ingw.add_argument("--bind", default="127.0.0.1")
    ingw.add_argument("--port", type=int, default=8787)
    ingw.add_argument("--path", default="/ingest")
    ingw.add_argument("--secret", default=None)
    ingw.add_argument("--secret-env", dest="secret_env", default=None)
    ingw.add_argument("--events", default=None)
    ingw.add_argument("--root", default=_ingest_root)
    ingw.add_argument("--max-events", dest="max_events", type=int,
                      default=plugin_io.DEFAULT_MAX_EVENTS)
    ingw.add_argument("--seconds", type=int, default=30)
    ingw.add_argument("--once", action="store_true")
    ingw.add_argument("--host", default=None)
    ingw.set_defaults(func=cmd_ingest_webhook)

    exp = sub.add_parser(
        "export", help="bounded exporters (webhook, syslog)")
    exps = exp.add_subparsers(dest="export_action", required=True)
    _export_root = "C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma"

    expw = exps.add_parser("webhook", help="POST a bounded event batch")
    expw.add_argument("--url", required=True)
    expw.add_argument("--secret", default=None)
    expw.add_argument("--secret-env", dest="secret_env", default=None)
    expw.add_argument("--events", default=None)
    expw.add_argument("--root", default=_export_root)
    expw.add_argument("--since", default=None)
    expw.add_argument("--max-events", dest="max_events", type=int,
                      default=plugin_io.DEFAULT_MAX_EVENTS)
    expw.add_argument("--batch-size", dest="batch_size", type=int, default=100)
    expw.set_defaults(func=cmd_export_webhook)

    expsl = exps.add_parser("syslog", help="send events over syslog UDP/TCP")
    expsl.add_argument("--host", required=True)
    expsl.add_argument("--port", type=int, default=514)
    expsl.add_argument("--protocol", choices=["udp", "tcp"], default="udp")
    expsl.add_argument("--events", default=None)
    expsl.add_argument("--root", default=_export_root)
    expsl.add_argument("--since", default=None)
    expsl.add_argument("--max-events", dest="max_events", type=int,
                       default=plugin_io.DEFAULT_MAX_EVENTS)
    expsl.set_defaults(func=cmd_export_syslog)

    plg = sub.add_parser(
        "plugin",
        help="install, verify and run bounded external plugins")
    plgs = plg.add_subparsers(dest="plugin_action", required=True)
    _plugin_root = "C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma"

    pla = plgs.add_parser("actions", help="list responder actions")
    pla.add_argument("--root", default=_plugin_root)
    pla.set_defaults(func=cmd_plugin_actions)

    plact = plgs.add_parser("act", help="preview or apply a responder action")
    plact.add_argument("name")
    plact.add_argument("--args", default="{}", help="JSON argument object")
    plact.add_argument("--apply", action="store_true")
    plact.add_argument("--plan", default=None, help="id from a prior preview")
    plact.add_argument("--reason", default=None)
    plact.add_argument("--root", default=_plugin_root)
    plact.set_defaults(func=cmd_plugin_act)

    plu = plgs.add_parser("undo", help="run a journaled action's rollback")
    plu.add_argument("journal_id")
    plu.add_argument("--reason", default=None)
    plu.add_argument("--root", default=_plugin_root)
    plu.set_defaults(func=cmd_plugin_undo)

    plgl = plgs.add_parser("list", help="installed plugins and enable state")
    plgl.add_argument("--root", default=_plugin_root)
    plgl.set_defaults(func=cmd_plugin_list)

    plgi = plgs.add_parser("install", help="verify and install a plugin directory")
    plgi.add_argument("path")
    plgi.add_argument("--root", default=_plugin_root)
    plgi.add_argument("--allow-unsigned", action="store_true")
    plgi.add_argument("--pubkey", default=None, help="trusted Ed25519 public key")
    plgi.add_argument("--force", action="store_true")
    plgi.add_argument("--enable", action="store_true")
    plgi.set_defaults(func=cmd_plugin_install)

    plgv = plgs.add_parser("verify", help="recompute payload hash and signature")
    plgv.add_argument("name")
    plgv.add_argument("--root", default=_plugin_root)
    plgv.add_argument("--pubkey", default=None)
    plgv.set_defaults(func=cmd_plugin_verify)

    plgr = plgs.add_parser("remove", help="stop tracking and delete a plugin")
    plgr.add_argument("name")
    plgr.add_argument("--root", default=_plugin_root)
    plgr.set_defaults(func=cmd_plugin_remove)

    plge = plgs.add_parser("enable", help="allow a plugin to run")
    plge.add_argument("name")
    plge.add_argument("--root", default=_plugin_root)
    plge.set_defaults(func=cmd_plugin_enable)

    plgd = plgs.add_parser("disable", help="block a plugin from running")
    plgd.add_argument("name")
    plgd.add_argument("--root", default=_plugin_root)
    plgd.set_defaults(func=cmd_plugin_disable)

    plgrun = plgs.add_parser("run", help="run a sensor or detector once, bounded")
    plgrun.add_argument("name")
    plgrun.add_argument("--root", default=_plugin_root)
    plgrun.add_argument("--events", default=None)
    plgrun.add_argument("--max-events", dest="max_events", type=int, default=1000)
    plgrun.add_argument("--max-rows", dest="max_rows", type=int, default=5000)
    plgrun.add_argument("--since", default=None)
    plgrun.add_argument("--timeout", type=int, default=60)
    plgrun.add_argument("--force", action="store_true")
    plgrun.set_defaults(func=cmd_plugin_run)

    plgh = plgs.add_parser("health", help="run the plugin health check")
    plgh.add_argument("name")
    plgh.add_argument("--root", default=_plugin_root)
    plgh.set_defaults(func=cmd_plugin_health)

    plgn = plgs.add_parser("new", help="scaffold a plugin directory")
    plgn.add_argument("name")
    plgn.add_argument("--out", default="examples/plugins")
    plgn.add_argument("--kind", default="sensor",
                      choices=sorted(plugin_api.KINDS))
    plgn.set_defaults(func=cmd_plugin_new)

    plgk = plgs.add_parser("keygen", help="create an Ed25519 plugin keypair")
    plgk.add_argument("--out", required=True)
    plgk.set_defaults(func=cmd_plugin_keygen)

    plgsign = plgs.add_parser("sign", help="sign a plugin payload")
    plgsign.add_argument("--plugin", required=True)
    plgsign.add_argument("--key", required=True)
    plgsign.set_defaults(func=cmd_plugin_sign)

    pf = sub.add_parser(
        "profile",
        help="bounded behavioural baselines: build, inspect, diff, merge")
    pfs = pf.add_subparsers(dest="profile_action", required=True)
    _profile_root = "C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma"
    pfb = pfs.add_parser("build", help="build a compact profile from the event tail")
    pfb.add_argument("--events", default=None)
    pfb.add_argument("--root", default=_profile_root)
    pfb.add_argument("--host", default=None)
    pfb.add_argument("--role", default="unknown",
                     help="dc, member, workstation, jump (labels the baseline)")
    pfb.add_argument("--max-rows", dest="max_rows", type=int,
                     default=profile.DEFAULT_MAX_ROWS)
    pfb.add_argument("--since", default=None,
                     help="ISO timestamp or duration such as 7d")
    pfb.add_argument("--out", default=None, help="write the profile here")
    pfb.add_argument("--full", action="store_true",
                     help="print the whole profile, not just the summary")
    pfb.set_defaults(func=cmd_profile_build)

    pfw = pfs.add_parser("show", help="inspect one profile")
    pfw.add_argument("--profile", required=True)
    pfw.add_argument("--full", action="store_true")
    pfw.set_defaults(func=cmd_profile_show)

    pfd = pfs.add_parser("diff", help="what changed between two profiles")
    pfd.add_argument("--old", required=True)
    pfd.add_argument("--new", required=True)
    pfd.add_argument("--limit", type=int, default=50)
    pfd.set_defaults(func=cmd_profile_diff)

    pfm = pfs.add_parser("merge", help="merge host profiles into an estate profile")
    pfm.add_argument("--profiles", nargs="+", required=True)
    pfm.add_argument("--out", required=True)
    pfm.add_argument("--name", default="estate")
    pfm.set_defaults(func=cmd_profile_merge)

    pfv = pfs.add_parser("verify", help="recompute the profile integrity hash")
    pfv.add_argument("--profile", required=True)
    pfv.set_defaults(func=cmd_profile_verify)

    an = sub.add_parser(
        "anomaly",
        help="explainable local anomaly scores and causal process traces")
    ans = an.add_subparsers(dest="anomaly_action", required=True)
    ansco = ans.add_parser("score", help="rank behaviours against a profile")
    ansco.add_argument("--events", default=None)
    ansco.add_argument("--root", default=_profile_root)
    ansco.add_argument("--profile", default=None,
                       help="profile path (default: <root>/profile.json)")
    ansco.add_argument("--estate", default=None,
                       help="optional merged estate profile for cross-host rarity")
    ansco.add_argument("--since", default=None)
    ansco.add_argument("--limit", type=int, default=anomaly.DEFAULT_LIMIT)
    ansco.add_argument("--max-rows", dest="max_rows", type=int, default=5000)
    ansco.add_argument("--include-suppressed", action="store_true")
    ansco.add_argument("--include-self", dest="include_self",
                       action="store_true",
                       help="include Plasma's own binaries in the ranking")
    ansco.set_defaults(func=cmd_anomaly_score)

    ansex = ans.add_parser("explain", help="why did the top row score?")
    ansex.add_argument("--events", default=None)
    ansex.add_argument("--root", default=_profile_root)
    ansex.add_argument("--profile", default=None)
    ansex.add_argument("--estate", default=None)
    ansex.add_argument("--contains", default=None,
                       help="only consider rows whose process/parent matches")
    ansex.add_argument("--ts", default=None, help="exact timestamp")
    ansex.add_argument("--since", default=None)
    ansex.add_argument("--max-rows", dest="max_rows", type=int, default=5000)
    ansex.set_defaults(func=cmd_anomaly_explain)

    anstr = ans.add_parser("trace", help="rebuild causal process trees")
    anstr.add_argument("--events", default=None)
    anstr.add_argument("--root", default=_profile_root)
    anstr.add_argument("--profile", default=None,
                       help="optional profile used to score trace edges")
    anstr.add_argument("--since", default=None)
    anstr.add_argument("--limit", type=int, default=anomaly.DEFAULT_LIMIT)
    anstr.add_argument("--max-rows", dest="max_rows", type=int, default=5000)
    anstr.add_argument("--min-spans", dest="min_spans", type=int, default=2)
    anstr.add_argument("--include-self", dest="include_self",
                       action="store_true",
                       help="include traces rooted in Plasma's own binaries")
    anstr.add_argument("--gap", type=int, default=anomaly.TRACE_GAP_SECONDS,
                       help="max seconds between a parent and its child")
    anstr.set_defaults(func=cmd_anomaly_trace)

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
    srd = sts.add_parser("redact", help="redact credential-bearing command lines")
    srd.add_argument("--events", required=True)
    srd.add_argument("--out", default=None)
    srd.set_defaults(func=cmd_store_redact)
    stst = sts.add_parser("stats", help="row counts, kinds, time span")
    stst.add_argument("--events", required=True)
    stst.set_defaults(func=cmd_store_stats)

    dp = sub.add_parser("deep", help="deep probes (run on the endpoint)")
    dps = dp.add_subparsers(dest="deep_action", required=True)
    dpp = dps.add_parser("persistence", help="every auto-start location + signature status")
    dpp.add_argument("--json-out", default=None, help="also write the full result here")
    dpp.add_argument("--cap", type=int, default=200)
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
    pbu.add_argument("--plan", type=int, default=None, help="id of the prior playbook undo dry-run")
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
    flpf = fls.add_parser(
        "profiles",
        help="pull compact host profiles and merge an estate baseline")
    flpf.add_argument("--inventory", required=True, help="fleet inventory JSON")
    flpf.add_argument("--out-dir", dest="out_dir", required=True,
                      help="directory for host profiles and estate.json")
    flpf.add_argument("--max-rows", dest="max_rows", type=int,
                      default=profile.DEFAULT_MAX_ROWS)
    flpf.add_argument("--role", default="member")
    flpf.add_argument("--baseline", default=None,
                      help="previous estate profile to diff against")
    flpf.set_defaults(func=cmd_fleet_profiles)
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

    pv = sub.add_parser("prevent", help="Tier 1 prevention: AppLocker, egress, ASR, LSA")
    pvs = pv.add_subparsers(dest="prevent_action", required=True)
    pvst = pvs.add_parser("status", help="read-only prevention posture")
    pvst.set_defaults(func=cmd_prevent_status)
    pvpo = pvs.add_parser("posture",
                          help="WDAC, CFA, Network Protection and driver blocklist state")
    pvpo.set_defaults(func=cmd_prevent_posture)
    for name, control, label in (
            ("cfa", "cfa", "Controlled Folder Access"),
            ("network", "network", "Network Protection")):
        pvd = pvs.add_parser(name, help=f"{label} (off/audit/block; dry-run first)")
        pvd.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
        pvd.add_argument("--mode", choices=["off", "audit", "block"], default="audit")
        pvd.add_argument("--apply", action="store_true")
        pvd.add_argument("--plan", type=int, default=None)
        pvd.add_argument("--reason", default=None)
        pvd.set_defaults(func=cmd_prevent_defender, control=control)
    pvdr = pvs.add_parser("driver-blocklist",
                          help="Microsoft vulnerable driver blocklist (reboot may be required)")
    pvdr.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    pvdr.add_argument("--off", action="store_true", help="disable instead of enable")
    pvdr.add_argument("--apply", action="store_true")
    pvdr.add_argument("--plan", type=int, default=None)
    pvdr.add_argument("--reason", default=None)
    pvdr.set_defaults(func=cmd_prevent_driver_blocklist)
    pva = pvs.add_parser("applocker", help="AppLocker Exe policy (audit by default)")
    pva.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    pva.add_argument("--mode", choices=["audit", "enforce"], default="audit")
    pva.add_argument("--allow-path", action="append", default=[],
                     help="additional allowed path rule (repeatable)")
    pva.add_argument("--apply", action="store_true")
    pva.add_argument("--plan", type=int, default=None)
    pva.add_argument("--reason", default=None)
    pva.set_defaults(func=cmd_prevent_applocker)
    pve = pvs.add_parser("egress", help="default-deny outbound with explicit allowlist")
    pve.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    pve.add_argument("--allow", action="append", required=True,
                     help="IP or CIDR, optionally :port (repeatable)")
    pve.add_argument("--apply", action="store_true")
    pve.add_argument("--plan", type=int, default=None)
    pve.add_argument("--reason", default=None)
    pve.set_defaults(func=cmd_prevent_egress)
    pvr = pvs.add_parser("asr", help="Defender attack surface reduction rules")
    pvr.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    pvr.add_argument("--ids", required=True, help="comma list of ASR rule GUIDs")
    pvr.add_argument("--action", choices=["Audit", "AuditMode", "Enabled",
                                          "Block", "Disabled"], default="Audit")
    pvr.add_argument("--apply", action="store_true")
    pvr.add_argument("--plan", type=int, default=None)
    pvr.add_argument("--reason", default=None)
    pvr.set_defaults(func=cmd_prevent_asr)
    pvl = pvs.add_parser("lsa", help="LSA protection (RunAsPPL); reboot to take effect")
    pvl.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    pvl.add_argument("--disable", action="store_true")
    pvl.add_argument("--apply", action="store_true")
    pvl.add_argument("--plan", type=int, default=None)
    pvl.add_argument("--reason", default=None)
    pvl.set_defaults(func=cmd_prevent_lsa)
    pvb = pvs.add_parser("rollback", help="roll back an applied prevention control")
    pvb.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    pvb.add_argument("--id", type=int, required=True)
    pvb.add_argument("--apply", action="store_true")
    pvb.add_argument("--plan", type=int, default=None,
                     help="id of the prior rollback dry-run")
    pvb.add_argument("--reason", default=None,
                     help="mandatory when --apply is used")
    pvb.set_defaults(func=cmd_prevent_rollback)
    enf = sub.add_parser("enforce", help="policy-gated automatic containment from watch findings")
    enfs = enf.add_subparsers(dest="enforce_action", required=True)
    enr = enfs.add_parser("run", help="propose containment; apply only per policy")
    enr.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    enr.add_argument("--apply", action="store_true",
                     help="arm enforcement for this run (policy still gates every action)")
    enr.add_argument("--dry-run", action="store_true",
                     help="force dry-run even if policy mode is enforce")
    enr.add_argument("--findings", default=None,
                     help="JSON file of findings to evaluate instead of a live sweep")
    enr.set_defaults(func=cmd_enforce_run)
    ens = enfs.add_parser("status", help="policy, journal and kill-switch state")
    ens.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    ens.set_defaults(func=cmd_enforce_status)
    enp = enfs.add_parser("pending", help="requests waiting for approval")
    enp.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    enp.set_defaults(func=cmd_enforce_pending)
    ena = enfs.add_parser("approve", help="execute one pending request (dry-run by default)")
    ena.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    ena.add_argument("--id", type=int, required=True)
    ena.add_argument("--apply", action="store_true", help="execute; without it only the plan is shown")
    ena.set_defaults(func=cmd_enforce_approve)

    pt = sub.add_parser("protect", help="measured protection posture: status, arm, disarm")
    pts = pt.add_subparsers(dest="protect_action", required=True)
    ptsx = pts.add_parser("status", help="show containment, prevention and protected components")
    ptsx.add_argument("--root", default=None)
    ptsx.set_defaults(func=cmd_protect_status)
    pta = pts.add_parser("arm", help="write the measured containment policy")
    pta.add_argument("--root", default=None)
    pta.add_argument("--apply-prevention", action="store_true",
                     help="also apply AppLocker in audit mode (requires --reason)")
    pta.add_argument("--reason", default=None)
    pta.set_defaults(func=cmd_protect_arm)
    ptd = pts.add_parser("disarm", help="turn automatic containment off (dry-run only)")
    ptd.add_argument("--root", default=None)
    ptd.add_argument("--reason", default=None)
    ptd.set_defaults(func=cmd_protect_disarm)
    ptp = pts.add_parser("protected", help="list protected services, processes, accounts and paths")
    ptp.set_defaults(func=cmd_protect_protected)

    idp = sub.add_parser("identity", help="identity plane: logon events into the store (Event Log API)")
    idps = idp.add_subparsers(dest="identity_action", required=True)
    idpp = idps.add_parser("pull", help="pull recent identity events into the events store")
    idpp.add_argument("--events", required=True)
    idpp.add_argument("--host", default=None)
    idpp.add_argument("--since", type=int, default=15, help="minutes to look back")
    idpp.add_argument("--ids", default=None,
                      help="comma list of Security event ids (default: "
                           "4624,4625,4688,4768,4769,4770,4771,4776)")
    idpp.add_argument("--max-events", type=int, default=2000,
                      help="bounded read per pull (default 2000)")
    idpp.set_defaults(func=cmd_identity_pull)
    idsch = idps.add_parser("schedule", help="register a SYSTEM task that pulls logons on a cadence")
    idsch.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    idsch.add_argument("--every", type=int, default=15, help="minutes between pulls")
    idsch.add_argument("--exe", default=None, help="plasma executable (default: newest in bin/)")
    idsch.set_defaults(func=cmd_identity_schedule)
    iduns = idps.add_parser("unschedule", help="remove the identity pull task")
    iduns.set_defaults(func=cmd_identity_unschedule)
    idst = idps.add_parser("schedule-status", help="is the identity pull task installed and running?")
    idst.set_defaults(func=cmd_identity_schedule_status)

    hp = sub.add_parser("health", help="is this node's Plasma stack actually alive?")
    hp.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    hp.set_defaults(func=cmd_health)

    wp = sub.add_parser("watch", help="self-check sweep with notifications (health + drift + alerts)")
    wps = wp.add_subparsers(dest="watch_action", required=True)
    wpo = wps.add_parser("once", help="one sweep (cron/Task Scheduler friendly)")
    wpo.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    wpo.add_argument("--notify-clean", action="store_true", help="notify even when clean")
    wpo.add_argument("--enforce", action="store_true",
                     help="feed findings to the enforcement policy (dry-run unless policy says enforce)")
    wpo.add_argument("--canary-account", action="append", default=[],
                     help="canary account to query (repeatable; default: config canary.accounts)")
    wpo.set_defaults(func=cmd_watch_once)
    wpl = wps.add_parser("loop", help="sweep forever every N seconds")
    wpl.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    wpl.add_argument("--every", type=int, default=3600)
    wpl.add_argument("--enforce", action="store_true",
                     help="feed each sweep to the enforcement policy")
    wpl.add_argument("--canary-account", action="append", default=[],
                     help="canary account to query (repeatable; default: config canary.accounts)")
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
    upc.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
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
    upa.add_argument("--ring", default=None, help="only update if this host is in the named ring")
    upa.add_argument("--tag", default=None,
                     help="pin a specific release tag instead of latest")
    upa.set_defaults(func=cmd_update_apply)
    upauto = ups.add_parser("auto", help="measured self-update: check and apply the latest signed release")
    upauto.add_argument("--repo", default="DrOlu/plasma")
    upauto.add_argument("--token-env", default="PLASMA_GITHUB_TOKEN")
    upauto.add_argument("--root", default="C:\\ProgramData\\Plasma" if os.name == "nt" else ".plasma")
    upauto.add_argument("--ring", default=None,
                        help="canary | broad | rollback (default: config)")
    upauto.add_argument("--check-only", action="store_true",
                        help="report availability; do not install")
    upauto.add_argument("--force", action="store_true",
                        help="apply even if the version is the same (reinstall)")
    upauto.add_argument("--allow-unsigned", action="store_true",
                        help="development only: allow an unsigned staged exe")
    upauto.add_argument("--no-notify", action="store_true")
    upauto.set_defaults(func=cmd_update_auto)

    ctl = sub.add_parser("control", help="agent control plane: policy, approvals, audit, kill switch, tenants")
    ctls = ctl.add_subparsers(dest="control_action", required=True)

    pol = ctls.add_parser("policy", help="show or change the autonomy policy")
    pols = pol.add_subparsers(dest="policy_action", required=True)
    pshow = pols.add_parser("show")
    pshow.add_argument("--root", default=None)
    pshow.set_defaults(func=cmd_control_policy_show)
    pset = pols.add_parser("set")
    pset.add_argument("--root", default=None)
    pset.add_argument("--autonomy", choices=("assist", "supervised", "autonomous"))
    pset.add_argument("--deny", nargs="*", default=None)
    pset.add_argument("--allow", nargs="*", default=None)
    pset.add_argument("--max-actions", type=int, default=None)
    pset.add_argument("--max-hosts", type=int, default=None)
    crit = pset.add_mutually_exclusive_group()
    crit.add_argument("--allow-critical", dest="allow_critical", action="store_true",
                      default=None)
    crit.add_argument("--no-allow-critical", dest="allow_critical",
                      action="store_false")
    pset.set_defaults(func=cmd_control_policy_set)
    psim = pols.add_parser("simulate",
                           help="explain a policy decision without changing state")
    psim.add_argument("tool", help="typed tool name, e.g. isolate_host")
    psim.add_argument("--args", default="{}", help="tool arguments as JSON")
    psim.add_argument("--args-file", dest="args_file", default=None,
                      help="read tool arguments from a JSON file (Windows quoting)")
    psim.add_argument("--scopes", default=None,
                      help="comma-separated scopes; default: the tool's own")
    psim.add_argument("--recent-actions", dest="recent_actions", type=int, default=0)
    psim.add_argument("--killswitch-blocked", dest="killswitch_blocked",
                      action="store_true")
    psim.add_argument("--root", default=None)
    psim.set_defaults(func=cmd_control_policy_simulate)

    appr = ctls.add_parser("approvals", help="list, approve or deny pending actions")
    apprs = appr.add_subparsers(dest="approvals_action", required=True)
    alist = apprs.add_parser("list")
    alist.add_argument("--limit", type=int, default=100)
    alist.add_argument("--root", default=None)
    alist.set_defaults(func=cmd_control_approvals_list)
    aok = apprs.add_parser("approve")
    aok.add_argument("id", type=int)
    aok.add_argument("--approver", default="operator")
    aok.add_argument("--note", default="")
    aok.add_argument("--root", default=None)
    aok.set_defaults(func=cmd_control_approvals_approve)
    ano = apprs.add_parser("deny")
    ano.add_argument("id", type=int)
    ano.add_argument("--approver", default="operator")
    ano.add_argument("--note", default="")
    ano.add_argument("--root", default=None)
    ano.set_defaults(func=cmd_control_approvals_deny)

    aud = ctls.add_parser("audit", help="read or verify the provenance ledger")
    auds = aud.add_subparsers(dest="audit_action", required=True)
    atail = auds.add_parser("tail")
    atail.add_argument("--last", type=int, default=20)
    atail.add_argument("--root", default=None)
    atail.set_defaults(func=cmd_control_audit_tail)
    aver = auds.add_parser("verify")
    aver.add_argument("--root", default=None)
    aver.set_defaults(func=cmd_control_audit_verify)

    ks = ctls.add_parser("killswitch", help="global or per-host action kill switch")
    kss = ks.add_subparsers(dest="killswitch_action", required=True)
    kst = kss.add_parser("status")
    kst.add_argument("--root", default=None)
    kst.set_defaults(func=cmd_control_killswitch_status)
    kon = kss.add_parser("on")
    kon.add_argument("--host", default=None)
    kon.add_argument("--reason", default="")
    kon.add_argument("--root", default=None)
    kon.set_defaults(func=cmd_control_killswitch_on)
    koff = kss.add_parser("off")
    koff.add_argument("--host", default=None)
    koff.add_argument("--reason", default="")
    koff.add_argument("--root", default=None)
    koff.set_defaults(func=cmd_control_killswitch_off)

    ten = ctls.add_parser("tenants", help="multi-tenant registry (MSSP isolation)")
    tens = ten.add_subparsers(dest="tenants_action", required=True)
    tlist = tens.add_parser("list")
    tlist.add_argument("--root", default=None)
    tlist.set_defaults(func=cmd_control_tenants_list)
    tadd = tens.add_parser("add")
    tadd.add_argument("tenant")
    tadd.add_argument("--name", default="")
    tadd.add_argument("--host", action="append", default=[])
    tadd.add_argument("--root", default=None)
    tadd.set_defaults(func=cmd_control_tenants_add)
    trem = tens.add_parser("remove")
    trem.add_argument("tenant")
    trem.add_argument("--root", default=None)
    trem.set_defaults(func=cmd_control_tenants_remove)

    sv = sub.add_parser("serve", help="HTTP API for the full Plasma CLI (alternative to WinRM/SSH)")
    sv.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    sv.add_argument("--port", type=int, default=9999, help="bind port (default: 9999)")
    sv.add_argument("--api-key", default=None,
                    help="bearer key (default: plasmaplasma, or PLASMA_SERVE_API_KEY)")
    sv.add_argument("--api-key-file", default=None,
                    help="read the bearer key from the first non-empty line")
    sv.add_argument("--root", default=None, help="Plasma root for the serve audit log")
    sv.add_argument("--read-only", action="store_true",
                    help="refuse every command that changes host or Plasma state")
    sv.add_argument("--tls-cert", default=None, help="PEM certificate for HTTPS")
    sv.add_argument("--tls-key", default=None, help="PEM private key for HTTPS")
    sv.add_argument("--timeout", type=int, default=300,
                    help="per-command timeout in seconds (default: 300)")
    sv.add_argument("--max-body", type=int, default=1 << 20,
                    help="maximum request body in bytes (default: 1 MiB)")
    sv.add_argument("--max-output", type=int, default=8 << 20,
                    help="maximum stdout/stderr per call in bytes (default: 8 MiB)")
    sv.add_argument("--no-audit", action="store_true",
                    help="do not write <root>/serve/audit.jsonl")
    sv.add_argument("--quiet", action="store_true", help="suppress request logging")
    sv.add_argument("--allow-insecure-default-key", action="store_true",
                    help="allow the known default key on a non-loopback bind")
    sv.set_defaults(func=cmd_serve)

    mp = sub.add_parser("mcp", help="MCP stdio server for agent harnesses")
    mps = mp.add_subparsers(dest="mcp_action", required=True)
    mserve = mps.add_parser("serve")
    mserve.add_argument("--root", default=None)
    mserve.set_defaults(func=cmd_mcp_serve)

    evd = sub.add_parser("evidence", help="machine-generated compliance evidence")
    evds = evd.add_subparsers(dest="evidence_action", required=True)
    evex = evds.add_parser("export")
    evex.add_argument("--framework", nargs="*", default=None,
                      choices=("cbn", "ndpa", "pci", "iso27001"))
    evex.add_argument("--out", default=None)
    evex.add_argument("--root", default=None)
    evex.set_defaults(func=cmd_evidence_export)

    asr = sub.add_parser("assurance", help="SBOM, safety case and support bundle")
    asrs = asr.add_subparsers(dest="assurance_action", required=True)
    asb = asrs.add_parser("sbom")
    asb.add_argument("--out", default=None)
    asb.add_argument("--root", default=None)
    asb.set_defaults(func=cmd_assurance_sbom)
    asc = asrs.add_parser("safety-case")
    asc.add_argument("--out", default=None)
    asc.add_argument("--root", default=None)
    asc.set_defaults(func=cmd_assurance_safety)
    asu = asrs.add_parser("support-bundle")
    asu.add_argument("--out", default=None)
    asu.add_argument("--root", default=None)
    asu.set_defaults(func=cmd_assurance_bundle)
    asn = asrs.add_parser("notices")
    asn.set_defaults(func=cmd_assurance_notices)

    evl = sub.add_parser("eval", help="run the agent safety eval suite")
    evls = evl.add_subparsers(dest="eval_action", required=True)
    evrun = evls.add_parser("run")
    evrun.add_argument("--root", default=None)
    evrun.set_defaults(func=cmd_eval_run)

    rng = sub.add_parser("ring", help="deployment rings: canary, broad, rollback")
    rngs = rng.add_subparsers(dest="ring_action", required=True)
    rstat = rngs.add_parser("status")
    rstat.add_argument("--root", default=None)
    rstat.set_defaults(func=cmd_ring_status)
    rass = rngs.add_parser("assign")
    rass.add_argument("host")
    rass.add_argument("--ring", default="canary")
    rass.add_argument("--root", default=None)
    rass.set_defaults(func=cmd_ring_assign)
    rprom = rngs.add_parser("promote")
    rprom.add_argument("ring")
    rprom.add_argument("--root", default=None)
    rprom.set_defaults(func=cmd_ring_promote)

    rb = sub.add_parser("rollback", help="restore the previous canonical binary")
    rb.add_argument("--bin", default=None)
    rb.add_argument("--root", default=None)
    rb.set_defaults(func=cmd_rollback)

    hb = sub.add_parser("_bridge", help=argparse.SUPPRESS)
    hb.add_argument("--dir", required=True)
    hb.add_argument("--tool", default=None)
    hb.add_argument("--args", default="{}")
    hb.add_argument("--events", default=None)
    hb.add_argument("--coverage", action="store_true")
    hb.set_defaults(func=cmd_internal_bridge)

    hp = sub.add_parser("help", help="detailed command reference, examples and JSON catalog")
    hp.add_argument("topic", nargs="*",
                    help="command path, e.g. control approvals approve")
    hp.add_argument("--json", action="store_true",
                    help="machine-readable catalog (all commands or one topic)")
    hp.set_defaults(func=cmd_help)

    helpmod.install(p)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
