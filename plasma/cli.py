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

from . import __version__, sentinel
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
        platforms=platforms, sentinel_payload=args.sentinel_payload,
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


def _windows_service_present() -> bool:
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             "Get-Service | Where-Object { $_.Name -like 'Sentinel*' -or "
             "$_.DisplayName -like '*Sentinel*' } | Select-Object -First 1 "
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

    sentinel_present = _windows_service_present()
    sentinel_dir = embedded / "sensors" / "sentinel"
    sentinel_setup = sentinel_dir / "SentinelSetup-3.3.1.exe"
    sentinel_gz = sentinel_dir / "SentinelSetup-3.3.1.exe.gz"
    pin_path = embedded / "sensors" / "sentinel.pin.json"
    sentinel_planned = (
        not sentinel_present and not args.skip_sentinel
        and (sentinel_setup.exists() or sentinel_gz.exists())
    )

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
        "sentinel_present": sentinel_present,
        "sentinel_will_install": bool(sentinel_planned),
        "actions": [
            f"create {target}",
            "extract embedded instance + engines",
            f"copy {Path(sys.executable).name} to {root / 'bin'}",
            f"write {config_path}",
            f"point {current} -> {target}",
        ] + ([f"install Sentinel {version} silently from embedded payload"] if sentinel_planned else []),
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
            "sentinel": {"required": True, "min_version": "3.3.1"},
            "sysmon": {"required": False},
            "sealighter": {"required": False, "mode": "on-demand"},
        },
    }
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

    # 3. Sentinel (silent, hash-verified, fail closed).
    if sentinel_planned:
        pin = json.loads(pin_path.read_text(encoding="utf-8"))
        setup_path = sentinel_setup
        if not setup_path.exists() and sentinel_gz.exists():
            setup_path = _materialize_gzip(sentinel_gz, sentinel_setup.name)
        actual = sha256_file(setup_path)
        expected = pin["payload"]["sha256"].lower()
        if actual != expected:
            print(json.dumps({"ok": False, "stage": "sentinel_payload",
                              "error": "hash mismatch", "expected": expected, "actual": actual}, indent=2))
            return 2
        try:
            subprocess.run(
                [str(setup_path), *pin["payload"]["silent_args"]],
                capture_output=True, text=True, timeout=600,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(json.dumps({"ok": False, "stage": "sentinel_install", "error": str(exc)[:300]}, indent=2))
            return 3
        deadline = __import__("time").time() + 60
        while not _windows_service_present() and __import__("time").time() < deadline:
            __import__("time").sleep(2)
        if not _windows_service_present():
            print(json.dumps({"ok": False, "stage": "sentinel_install",
                              "error": "Sentinel service did not appear within 60s"}, indent=2))
            return 3

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
        "sentinel_installed": sentinel_planned or sentinel_present,
        "files_verified": verification["checked"],
    }, indent=2))
    return 0


def cmd_sentinel_pull(args) -> int:
    result = sentinel.pull(args.sentinel_root, args.out, args.host)
    print(json.dumps(result, indent=2))
    return 0 if "error" not in result else 1


def cmd_sentinel_push(args) -> int:
    result = sentinel.push(
        events_path=args.events, sentinel_root=args.sentinel_root,
        min_confidence=args.min_confidence, max_iocs=args.max_iocs,
        apply=args.apply, restart_service=args.restart_service, reason=args.reason,
    )
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 1


def cmd_sentinel_status(args) -> int:
    print(json.dumps(sentinel.status(args.sentinel_root, args.events), indent=2))
    return 0


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
    bb.add_argument("--sentinel-payload", default=None,
                    help="directory with the Sentinel setup EXE, LICENSE and SHA256SUMS")
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
    ins.add_argument("--skip-sentinel", action="store_true")
    ins.add_argument("--force", action="store_true")
    ins.set_defaults(func=cmd_install)

    sn = sub.add_parser("sentinel", help="Sentinel integration: pull detections, push IOC intelligence")
    sns = sn.add_subparsers(dest="sentinel_action", required=True)

    sp = sns.add_parser("pull", help="normalize Sentinel detections into the Plasma event store")
    sp.add_argument("--sentinel-root", default=None)
    sp.add_argument("--out", default=None)
    sp.add_argument("--host", default=None)
    sp.set_defaults(func=cmd_sentinel_pull)

    spu = sns.add_parser("push", help="push high-confidence indicators into Sentinel's local IOC bundle")
    spu.add_argument("--sentinel-root", default=None)
    spu.add_argument("--events", default=None)
    spu.add_argument("--min-confidence", type=int, default=sentinel.DEFAULT_MIN_CONFIDENCE)
    spu.add_argument("--max-iocs", type=int, default=sentinel.DEFAULT_MAX_IOCS)
    spu.add_argument("--reason", default="")
    spu.add_argument("--restart-service", action="store_true")
    spu.add_argument("--apply", action="store_true", help="write the bundle (default is dry-run)")
    spu.set_defaults(func=cmd_sentinel_push)

    sps = sns.add_parser("status", help="show Sentinel + Plasma integration state")
    sps.add_argument("--sentinel-root", default=None)
    sps.add_argument("--events", default=None)
    sps.set_defaults(func=cmd_sentinel_status)

    # Hidden: the frozen executable re-enters itself to execute the bundle's
    # bridge with the Python runtime embedded in the one-file binary.
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
