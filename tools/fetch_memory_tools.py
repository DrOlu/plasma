#!/usr/bin/env python3
"""Fetch and hash-pin the memory scanner payload (HollowsHunter)."""
from __future__ import annotations

import argparse
import hashlib
import json
import urllib.request
from pathlib import Path

VERSION = "0.4.1.1"
BASE = ("https://github.com/hasherezade/hollows_hunter/releases/download/"
        f"v{VERSION}/")
EXPECTED = {
    "hollows_hunter64.exe": "56a58a8bbf2cec9a5c7c68129e8863af6181fb51dfc25226f1a756aba66b4707",
    "hollows_hunter32.exe": "c37b611cf14144bd15c98f696a948616aa9630b79671adcc9ac115d8ec9ab49f",
}
LICENSE_URL = "https://raw.githubusercontent.com/hasherezade/hollows_hunter/master/LICENSE"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "plasma-build"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", default="sensors/memory")
    args = ap.parse_args()
    dest = Path(args.dest)
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "VERSION").write_text(VERSION + "\n", encoding="utf-8")
    for name, expected in EXPECTED.items():
        path = dest / name
        data = fetch(BASE + name)
        path.write_bytes(data)
        actual = sha256(path)
        if actual != expected:
            path.unlink(missing_ok=True)
            raise SystemExit(
                f"{name}: hash mismatch (expected {expected}, got {actual})")
    (dest / "LICENSE").write_bytes(fetch(LICENSE_URL))
    print(json.dumps({"ok": True, "dest": str(dest), "version": VERSION,
                      "files": sorted(EXPECTED)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
