"""Build the single self-contained Windows x64 Plasma executable.

Stages the frozen instance, the Windows neuralOS engine + weights, and the
Sentinel payload under build/embedded/, writes a SHA256 manifest over that
payload, then asks PyInstaller to embed the whole directory into one .exe.

Run on a Windows machine/runner (PyInstaller does not cross-compile):

    python tools/build_embedded_windows.py \
        --engine-dir engines/windows-x86_64 \
        --sentinel-payload sensors/sentinel
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from plasma import __version__  # noqa: E402
from plasma.manifest import create_manifest  # noqa: E402

INSTANCE_FILES = [
    "models.py", "needle_menu.json", "graph_edges.json", "graph_bridge.py",
    "bridge.py", "bridge.ps1", "README.md", "golden.json", "verification.txt",
]
SENSOR_ROOT_FILES = ["sentinel.pin.json", "sealighter.pin.json", "sysmon-config.xml"]


def gzip_file(src: Path, dst: Path):
    """Deterministic gzip (mtime=0) so builds are reproducible."""
    with open(src, "rb") as fi, open(dst, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz:
            shutil.copyfileobj(fi, gz)


def copy_engine(engine_dir: Path, dest: Path, platform: str):
    exe_name = "needle.exe" if platform.startswith("windows") else "needle"
    src_exe = engine_dir / exe_name
    src_weights = engine_dir / "needle3.cact"
    if not src_exe.exists():
        raise FileNotFoundError(f"engine binary missing: {src_exe}")
    if not src_weights.exists():
        raise FileNotFoundError(f"engine weights missing: {src_weights}")

    # Executables are stored gzipped: PyInstaller rewrites Mach-O/PE files it
    # recognises, which would break the frozen manifest. Opaque .gz survives.
    gzip_file(src_exe, dest / "needle.gz")
    shutil.copy2(src_weights, dest / "needle3.cact")
    for optional in ("libneedle.a", "needle.h", "libneedle3.dll", "libneedle3.dylib"):
        src = engine_dir / optional
        if src.exists():
            shutil.copy2(src, dest / optional)


def assemble(engine_dir: Path, sentinel_payload: Path | None, out: Path, platform: str) -> dict:
    if out.exists():
        shutil.rmtree(out)
    (out / "instance").mkdir(parents=True)
    (out / "engines" / platform).mkdir(parents=True)
    (out / "sensors" / "sentinel").mkdir(parents=True)

    missing = []
    for name in INSTANCE_FILES:
        src = ROOT / "instance" / name
        if src.exists():
            shutil.copy2(src, out / "instance" / name)
        else:
            missing.append(f"instance/{name}")
    for name in SENSOR_ROOT_FILES:
        src = ROOT / "sensors" / name
        if src.exists():
            shutil.copy2(src, out / "sensors" / name)
        else:
            missing.append(f"sensors/{name}")
    copy_engine(engine_dir, out / "engines" / platform, platform)

    payload_files = 0
    if sentinel_payload and sentinel_payload.is_dir():
        for child in sorted(sentinel_payload.iterdir()):
            if child.is_file():
                if child.suffix.lower() == ".exe":
                    gzip_file(child, out / "sensors" / "sentinel" / (child.name + ".gz"))
                else:
                    shutil.copy2(child, out / "sensors" / "sentinel" / child.name)
                payload_files += 1

    probes = len(json.loads((out / "instance" / "needle_menu.json").read_text(encoding="utf-8")))
    manifest = create_manifest(
        out, __version__, instance_probes=probes, engine_platforms=[platform]
    )
    return {
        "missing": missing,
        "files": manifest["file_count"],
        "probes": probes,
        "sentinel_payload_files": payload_files,
        "platform": platform,
    }


def build(out: Path, dist: Path, name: str) -> Path:
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile", "--name", name,
        "--collect-all", "pydantic",
        "--collect-all", "pydantic_core",
        "--distpath", str(dist),
        "--workpath", str(ROOT / "build" / "pyinstaller"),
        "--specpath", str(ROOT / "build"),
        "--add-data", f"{out}{os.pathsep}embedded",
        str(ROOT / "plasma_entry.py"),
    ]
    subprocess.run(cmd, check=True, cwd=ROOT)
    exe = dist / (name + (".exe" if os.name == "nt" else ""))
    if not exe.exists():
        raise FileNotFoundError(f"executable not produced: {exe}")
    return exe


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine-dir", default="engines/windows-x86_64")
    ap.add_argument("--sentinel-payload", default="sensors/sentinel")
    ap.add_argument("--platform", default="windows-x86_64")
    ap.add_argument("--out", default="build/embedded")
    ap.add_argument("--dist", default="dist")
    ap.add_argument("--name", default="plasma")
    ap.add_argument("--assemble-only", action="store_true")
    a = ap.parse_args()

    out = (ROOT / a.out).resolve()
    dist = (ROOT / a.dist).resolve()
    engine_dir = (ROOT / a.engine_dir).resolve()
    payload = (ROOT / a.sentinel_payload).resolve()

    info = assemble(engine_dir, payload if payload.is_dir() else None, out, a.platform)
    if info["missing"]:
        print(json.dumps({"ok": False, "missing": info["missing"]}, indent=2))
        return 2
    if a.assemble_only:
        print(json.dumps({"ok": True, "assembled": str(out), **info}, indent=2))
        return 0

    exe = build(out, dist, a.name)
    print(json.dumps({
        "ok": True,
        "exe": str(exe),
        "size": exe.stat().st_size,
        "embedded_files": info["files"],
        "probes": info["probes"],
        "platform": info["platform"],
        "sentinel_payload_files": info["sentinel_payload_files"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
