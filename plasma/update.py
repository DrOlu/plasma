"""Plasma update: self-update from GitHub releases.

`plasma update check` — compare current version against the latest release.
`plasma update apply` — download the new exe + SHA256SUMS, verify, run the
new exe's own installer, then rotate the canonical bin copy (rename-while-
running is legal on Windows; overwriting a running exe is not).

The repo is private by default: a token arrives via --token-env (never on
the command line, never on disk).
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.request


def _gh(url: str, token: str, timeout: int = 60, accept: str = "application/vnd.github+json") -> bytes:
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}", "Accept": accept,
        "User-Agent": "plasma-updater"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def latest_release(repo: str, token: str) -> dict:
    data = json.loads(_gh(f"https://api.github.com/repos/{repo}/releases/latest",
                          token).decode("utf-8"))
    assets = {a["name"]: a["url"] for a in data.get("assets", [])}
    return {"tag": data.get("tag_name", ""), "assets": assets}


def parse_version(tag: str) -> tuple:
    parts = []
    for piece in tag.lstrip("v").split("."):
        num = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(num or 0))
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def is_newer(current: str, latest: str) -> bool:
    return parse_version(latest) > parse_version(current)


def download_and_verify(repo: str, tag: str, token: str, dest) -> dict:
    """Download the release exe + SHA256SUMS, verify, keep the verified exe."""
    from pathlib import Path
    dest = Path(dest)
    rel = latest_release(repo, token)
    exe_url = next((u for n, u in rel["assets"].items() if n.endswith(".exe")), None)
    sums_url = next((u for n, u in rel["assets"].items() if n == "SHA256SUMS"), None)
    if not exe_url or not sums_url:
        return {"ok": False, "error": "release lacks exe/SHA256SUMS assets"}

    octet = "application/octet-stream"
    exe_bytes = _gh(exe_url, token, timeout=600, accept=octet)
    sums_bytes = _gh(sums_url, token, timeout=120, accept=octet).decode("utf-8")

    expected = ""
    for line in sums_bytes.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].endswith(".exe"):
            expected = parts[0].lower()
            break
    actual = hashlib.sha256(exe_bytes).hexdigest()
    if not expected or actual != expected:
        return {"ok": False, "error": "sha256 mismatch",
                "expected": expected, "actual": actual}

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(exe_bytes)
    return {"ok": True, "tag": tag or rel["tag"],
            "size": len(exe_bytes), "sha256": actual, "staged": str(dest)}


def rotate_bin(new_exe, bin_exe) -> dict:
    """Swap the canonical bin copy. Renaming a running exe is legal on
    Windows even though overwriting it is not."""
    from pathlib import Path
    bin_exe, new_exe = Path(bin_exe), Path(new_exe)
    if not new_exe.exists():
        return {"ok": False, "error": "staged exe missing"}
    if bin_exe.exists():
        old = bin_exe.with_suffix(bin_exe.suffix + ".old")
        os.replace(bin_exe, old)   # rename-while-running works
    bin_exe.parent.mkdir(parents=True, exist_ok=True)
    bin_exe.write_bytes(new_exe.read_bytes())
    return {"ok": True, "bin": str(bin_exe), "previous": str(bin_exe.with_suffix(bin_exe.suffix + ".old"))}
