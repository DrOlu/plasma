"""Bundle manifest: SHA256 integrity for every frozen artifact.

The manifest is the compatibility contract. A deployed bundle is trusted
only when every listed file hashes to its recorded value, the schema
version matches the normalizer, and the required sensor dependencies are
declared.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from . import PRODUCT, SCHEMA_VERSION

MANIFEST_NAME = "manifest.json"
EXCLUDE_DIRS = {"__pycache__", ".git", ".pytest_cache", "dist", "build"}
EXCLUDE_SUFFIXES = {".pyc", ".pyo", ".zip", ".msi", ".DS_Store"}
EXCLUDE_FILES = {MANIFEST_NAME}

SENSOR_REQUIREMENTS = {
    "whids": {"required": True, "min_version": "1.7.0", "install": "service"},
    "sysmon": {"required": True, "install": "official-package",
               "notes": "WHIDS depends on Sysmon for kernel telemetry"},
    "sealighter": {"required": False, "mode": "on-demand"},
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_bundle_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDE_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if name in EXCLUDE_FILES or path.suffix in EXCLUDE_SUFFIXES:
                continue
            yield rel, path


def create_manifest(
    root: str | Path,
    version: str,
    *,
    instance_probes: int | None = None,
    engine_platforms: list[str] | None = None,
    built_utc: str | None = None,
) -> dict:
    root = Path(root)
    if not root.is_dir():
        raise FileNotFoundError(f"bundle directory not found: {root}")
    files = {rel: sha256_file(path) for rel, path in iter_bundle_files(root)}
    manifest = {
        "product": PRODUCT,
        "version": version,
        "schema_version": SCHEMA_VERSION,
        "built_utc": built_utc or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": files,
        "file_count": len(files),
        "instance": {
            "runtime": "engine",
            "probes": instance_probes,
            "menu": "instance/needle_menu.json",
        },
        "engine": {
            "pinned": "neuralos>=3.10.2",
            "platforms": engine_platforms or [],
        },
        "sensor_requirements": SENSOR_REQUIREMENTS,
    }
    (root / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def verify_manifest(root: str | Path) -> dict:
    root = Path(root)
    mpath = root / MANIFEST_NAME
    if not mpath.exists():
        return {"ok": False, "error": f"missing {MANIFEST_NAME}", "checked": 0}
    try:
        manifest = json.loads(mpath.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"invalid manifest: {exc}", "checked": 0}

    recorded = manifest.get("files", {})
    missing, mismatched, present = [], [], set()
    for rel, expected in recorded.items():
        path = root / rel
        present.add(rel)
        if not path.exists():
            missing.append(rel)
            continue
        actual = sha256_file(path)
        if actual != expected:
            mismatched.append({"path": rel, "expected": expected[:16], "actual": actual[:16]})
    extra = sorted(
        rel for rel, _ in iter_bundle_files(root) if rel not in recorded
    )
    ok = not missing and not mismatched and not extra
    return {
        "ok": ok,
        "checked": len(recorded),
        "missing": missing,
        "mismatched": mismatched,
        "extra": extra,
        "version": manifest.get("version"),
        "schema_version": manifest.get("schema_version"),
        "sensor_requirements": manifest.get("sensor_requirements", {}),
    }
