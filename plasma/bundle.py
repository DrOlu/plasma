"""Assemble a deployable Plasma bundle.

The bundle is immutable: instance artifacts, installer, sensor declarations,
docs and (optionally) platform engine binaries. A manifest with SHA256 for
every file is written last and travels with the artifact.
"""
from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

from .manifest import create_manifest

REPO_ROOT = Path(__file__).resolve().parent.parent

INSTANCE_FILES = [
    "models.py",
    "needle_menu.json",
    "graph_edges.json",
    "graph_bridge.py",
    "bridge.py",
    "bridge.ps1",
    "README.md",
    "golden.json",
    "verification.txt",
]

PACKAGING_FILES = ["install.ps1", "verify.ps1", "config.example.json"]
SENSOR_FILES = ["sentinel.pin.json", "sysmon-config.xml", "sealighter.pin.json"]
DOC_FILES = ["ARCHITECTURE.md", "DEPLOYMENT.md", "SECURITY.md"]


def _copy(src: Path, dst: Path):
    if not src.exists():
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return True


def _menu_probe_count(path: Path) -> int | None:
    try:
        return len(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        return None


def build_bundle(
    out_dir: str | Path,
    version: str,
    *,
    repo_root: str | Path | None = None,
    engines_dir: str | Path | None = None,
    platforms: list[str] | None = None,
    sentinel_payload: str | Path | None = None,
    binaries: list[str | Path] | None = None,
    make_zip: bool = True,
    strict: bool = True,
) -> dict:
    repo = Path(repo_root) if repo_root else REPO_ROOT
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stage = out / f"plasma-{version}"
    if stage.exists():
        raise FileExistsError(f"staging directory already exists: {stage}")

    copied, missing = [], []

    def take(src: Path, rel: str):
        if _copy(src, stage / rel):
            copied.append(rel)
        else:
            missing.append(rel)

    for name in INSTANCE_FILES:
        take(repo / "instance" / name, f"instance/{name}")
    for name in PACKAGING_FILES:
        take(repo / "packaging" / name, f"packaging/{name}")
    for name in SENSOR_FILES:
        take(repo / "sensors" / name, f"sensors/{name}")
    for name in DOC_FILES:
        take(repo / "docs" / name, f"docs/{name}")
    take(repo / "README.md", "README.md")
    take(repo / "LICENSE", "LICENSE")

    # Sentinel payload (MIT): setup EXE + LICENSE + published checksums.
    payload_files = 0
    if sentinel_payload and Path(sentinel_payload).is_dir():
        for child in sorted(Path(sentinel_payload).iterdir()):
            if child.is_file():
                _copy(child, stage / "sensors" / "sentinel" / child.name)
                payload_files += 1

    # Plasma standalone executables (plasma / plasma.exe), per platform.
    binary_names = []
    for binary in binaries or []:
        p = Path(binary)
        if p.is_file():
            _copy(p, stage / "bin" / p.name)
            binary_names.append(p.name)
        elif strict:
            missing.append(f"bin/{p.name}")

    engine_platforms = []
    if engines_dir and Path(engines_dir).is_dir():
        wanted = platforms or [
            p.name for p in sorted(Path(engines_dir).iterdir()) if p.is_dir()
        ]
        for platform in wanted:
            src = Path(engines_dir) / platform
            if not src.is_dir():
                continue
            for child in sorted(src.iterdir()):
                if child.is_file():
                    _copy(child, stage / "engines" / platform / child.name)
            engine_platforms.append(platform)

    if strict and missing:
        shutil.rmtree(stage)
        raise FileNotFoundError(
            "bundle is incomplete; missing: " + ", ".join(sorted(missing))
        )

    probes = _menu_probe_count(stage / "instance" / "needle_menu.json")
    manifest = create_manifest(
        stage,
        version,
        instance_probes=probes,
        engine_platforms=engine_platforms,
    )

    zip_path = None
    if make_zip:
        zip_path = out / f"plasma-{version}.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(stage.rglob("*")):
                if path.is_file():
                    zf.write(path, path.relative_to(out).as_posix())

    return {
        "ok": True,
        "stage": str(stage),
        "zip": str(zip_path) if zip_path else None,
        "version": version,
        "files": len(manifest["files"]),
        "probes": probes,
        "engine_platforms": engine_platforms,
        "sentinel_payload_files": payload_files,
        "binaries": binary_names,
        "missing": missing,
    }
