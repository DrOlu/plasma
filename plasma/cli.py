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

from . import __version__
from .bundle import build_bundle
from .manifest import create_manifest, verify_manifest

MENU = "instance/needle_menu.json"


def _instance_dir(bundle: str) -> Path:
    return Path(bundle) / "instance"


def _frozen() -> bool:
    """True when running from a PyInstaller one-file executable."""
    return bool(getattr(sys, "frozen", False))


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


def _find_engine(bundle: str, explicit: str | None) -> Path | None:
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    env = os.environ.get("PLASMA_ENGINE")
    if env:
        candidates.append(Path(env))
    engine_root = Path(bundle) / "engines"
    if engine_root.is_dir():
        preferred = engine_root / _current_platform()
        for name in _engine_names():
            candidates.append(preferred / name)
        for platform_dir in sorted(engine_root.iterdir()):
            if platform_dir.is_dir():
                for name in _engine_names():
                    candidates.append(platform_dir / name)
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
        if candidate.is_file():  # Windows may not set the exec bit
            return candidate
    return None


def _find_model(bundle: str, engine: Path | None, explicit: str | None) -> Path | None:
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    env = os.environ.get("PLASMA_MODEL")
    if env:
        candidates.append(Path(env))
    if engine:
        candidates += [engine.parent / "needle3.cact", engine.parent / "neuralOS.engine"]
    candidates += [
        Path(bundle) / "engines" / _current_platform() / "needle3.cact",
        Path(bundle) / "needle3.cact",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _run_bridge(bundle: str, tool: str, args: dict, events: str | None) -> dict:
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
    bundle = args.bundle
    engine = _find_engine(bundle, args.engine)
    if engine is None:
        print(json.dumps({
            "error": "selection engine not found",
            "hint": "pass --engine PATH or set PLASMA_ENGINE; the bundle ships engines/<platform>/needle",
        }, indent=2))
        return 2
    model = _find_model(bundle, engine, args.model)
    if model is None:
        print(json.dumps({"error": "weights not found (needle3.cact)"}, indent=2))
        return 2
    cmd = [str(engine), "--model", str(model), "--tools", str(Path(bundle) / MENU), "--prompt", args.prompt]
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
    result = verify_manifest(args.bundle)
    inst = _instance_dir(args.bundle)
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
        "bundle": str(Path(args.bundle).resolve()),
        "verified": result,
        "probes": probes,
        "coverage": coverage,
        "engine": str(_find_engine(args.bundle, None) or "not bundled"),
    }, indent=2))
    return 0 if result.get("ok") else 2


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
    pr.add_argument("--bundle", required=True)
    pr.add_argument("--tool", required=True)
    pr.add_argument("--args", default="{}")
    pr.add_argument("--events", default=None)
    pr.set_defaults(func=cmd_probe)

    a = sub.add_parser("ask", help="select a probe with the engine and execute it")
    a.add_argument("--bundle", required=True)
    a.add_argument("--prompt", required=True)
    a.add_argument("--engine", default=None)
    a.add_argument("--model", default=None)
    a.add_argument("--system", default=None)
    a.add_argument("--events", default=None)
    a.set_defaults(func=cmd_ask)

    s = sub.add_parser("status", help="verify a bundle and report coverage")
    s.add_argument("--bundle", required=True)
    s.add_argument("--events", default=None)
    s.set_defaults(func=cmd_status)

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
