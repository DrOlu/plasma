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
    if py_bridge.exists():
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
        platforms=platforms, make_zip=not args.no_zip,
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
        cmd = [sys.executable, str(py_bridge), "--coverage"] + (
            ["--events", args.events] if args.events else []
        )
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
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
