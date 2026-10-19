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

from . import __version__, whids, observatory, actuate, drift, tap
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
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)
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
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
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
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)
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
            capture_output=True, text=True, timeout=20,
        )
        return bool(proc.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        return False


def _is_junction(path: Path) -> bool:
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             f"(Get-Item -LiteralPath '{path}' -Force).LinkType"],
            capture_output=True, text=True, timeout=15,
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
    whids_planned = (
        not whids_present and not args.skip_whids and whids_gz.exists()
    )
    sysmon_missing_fatal = not sysmon_present and not whids_present and not args.skip_whids

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
        "actions": [
            f"create {target}",
            "extract embedded instance + engines",
            f"copy {Path(sys.executable).name} to {root / 'bin'}",
            f"write {config_path}",
            f"point {current} -> {target}",
        ] + ([f"install WHIDS from embedded payload (service '{whids.SERVICE_NAME}')"] if whids_planned else []),
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

    # 2. Config.
    config = {
        "product": "Plasma",
        "version": version,
        "instance": str(target),
        "events_path": str(events_path),
        "retention_days": 7,
        "response": {"mode": "advisory", "require_human_approval": True},
        "sensors": {
            "whids": {"required": True, "min_version": "1.7.0"},
            "sysmon": {"required": True},
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
        shutil.copy2(whids_exe_gz, exe)
        for name in ("whids.toml", "plasma-iocs.gen", "LICENSE"):
            src = whids_dir / name
            if src.exists():
                shutil.copy2(src, install_dir / name)
        # v1.7.0 loads config.toml next to the binary
        if (install_dir / "whids.toml").exists():
            shutil.copy2(install_dir / "whids.toml", install_dir / "config.toml")
        rules_db = install_dir / "Database" / "Rules"
        rules_db.mkdir(parents=True, exist_ok=True)
        if (whids_dir / "plasma-iocs.gen").exists():
            shutil.copy2(whids_dir / "plasma-iocs.gen",
                         rules_db / "plasma-iocs.gen")
        bin_path = f'"{exe}" -c "{install_dir}\\config.toml"'
        if not _service_present("Whids*"):
            try:
                setup_proc = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-Command",
                     f"New-Service -Name Whids -BinaryPathName '{bin_path}' "
                     f"-DisplayName 'WHIDS (Plasma sensor)' -StartupType Automatic | Out-Null; "
                     f"sc.exe failure Whids reset= 9999 actions= restart/5000 | Out-Null"],
                    capture_output=True, text=True, timeout=120,
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
        try:
            subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command",
                 "Start-Service -Name 'Whids' -ErrorAction Stop"],
                capture_output=True, text=True, timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass

    # 4. Flip current (only replace an existing link).
    if current.exists() or current.is_symlink():
        if not (_is_junction(current) or args.force):
            print(json.dumps({"ok": False, "stage": "current",
                              "error": f"{current} exists and is not a link"}, indent=2))
            return 4
        subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             f"Remove-Item -LiteralPath '{current}' -Force"],
            capture_output=True, text=True, timeout=20,
        )
    subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command",
         f"New-Item -ItemType Junction -Path '{current}' -Target '{target}' | Out-Null"],
        capture_output=True, text=True, timeout=30, check=True,
    )

    print(json.dumps({
        "ok": True,
        "installed": str(target),
        "current": str(current),
        "config": str(config_path),
        "whids_installed": whids_planned or whids_present,
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
        apply=args.apply, timeout=args.timeout)
    print(json.dumps(result, indent=2, default=str))
    # dry-runs succeed by definition; applied actions report via "error"/rc
    if "error" in result:
        return 1
    if args.apply and (result.get("result", {}).get("rc") not in (None, 0)):
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
    seconds = tap.parse_duration(args.for_)
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

    rules = tap.load_rules(rules_path)
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
    ins.add_argument("--skip-whids", action="store_true")
    ins.add_argument("--skip-sysmon-check", action="store_true")
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
