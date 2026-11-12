#!/usr/bin/env python3
"""Fetch a neuralOS standalone engine bundle from a PINNED needle3 revision.

Upstream (Cactus-Compute/needle3) removed the per-platform engine bundles
from its repository head on 2026-11-05, which broke `needle.agent.fetch`
(nothing to download any more). Revision d6c7d6a2e965... is the last
revision that carries them, and its `needle3.cact` is BYTE-IDENTICAL to the
current head weights (verified: same blob id), so the pinned engine runs the
shipped weights exactly.

Usage (CI and local):
    python tools/fetch_engine.py --platform windows-x86_64 --dest engines/windows-x86_64
    python tools/fetch_engine.py --platform linux-x86_64  --dest engines/linux-x86_64

Weights are NOT part of the bundle: copy `needle3.cact` from the installed
`needle` package beside the engine (the published wheels bundle it), or pass
--with-weights to let this script download the head weights.
"""
from __future__ import annotations

import argparse
import os
import shutil
import stat
from pathlib import Path

REPO = "Cactus-Compute/needle3"
PINNED_REVISION = "d6c7d6a2e9655505e0f8e23339356dd1705900eb"

PLATFORMS = (
    "windows-x86_64", "windows-arm64",
    "linux-x86_64", "linux-arm64", "linux-armv7",
    "linux-riscv64", "linux-mipsel",
    "macos-arm64",
)
EXECUTABLES = {"needle", "needle.exe"}


def _hf():
    from huggingface_hub import hf_hub_download, list_repo_files  # lazy
    return hf_hub_download, list_repo_files


def platform_files(platform: str, revision: str = PINNED_REVISION) -> list[str]:
    """Remote file names for a platform at the pinned revision."""
    if platform not in PLATFORMS:
        raise SystemExit(f"unsupported platform {platform!r}; choose from {', '.join(PLATFORMS)}")
    _, list_repo_files = _hf()
    files = [f for f in list_repo_files(REPO, repo_type="model", revision=revision)
             if f.startswith(platform + "/")]
    if not files:
        raise SystemExit(f"no engine files for {platform} at revision {revision}")
    return sorted(files)


def fetch(platform: str, dest, revision: str = PINNED_REVISION,
          with_weights: bool = False) -> list[str]:
    hf_hub_download, _ = _hf()
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    out: list[str] = []
    for remote in platform_files(platform, revision):
        cached = hf_hub_download(repo_id=REPO, filename=remote,
                                 repo_type="model", revision=revision)
        target = dest / Path(remote).name
        shutil.copyfile(cached, target)
        if target.name in EXECUTABLES:
            target.chmod(target.stat().st_mode | stat.S_IXUSR
                         | stat.S_IXGRP | stat.S_IXOTH)
        out.append(str(target))
    if with_weights:
        weights = hf_hub_download(repo_id=REPO, filename="needle3.cact",
                                  repo_type="model")
        shutil.copyfile(weights, dest / "needle3.cact")
        out.append(str(dest / "needle3.cact"))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--platform", required=True, choices=PLATFORMS)
    ap.add_argument("--dest", required=True)
    ap.add_argument("--revision", default=os.environ.get("PLASMA_ENGINE_REVISION",
                                                          PINNED_REVISION))
    ap.add_argument("--with-weights", action="store_true",
                    help="also download needle3.cact (head revision)")
    args = ap.parse_args(argv)
    files = fetch(args.platform, args.dest, args.revision, args.with_weights)
    for f in files:
        print(f)
    print(f"engine bundle ready: {len(files)} files -> {args.dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
