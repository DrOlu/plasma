"""Plasma update: self-update from GitHub releases.

`plasma update check` — compare current version against the latest release.
`plasma update apply` — download the new exe + SHA256SUMS, verify, run the
new exe's own installer, then rotate the canonical bin copy (rename-while-
running is legal on Windows; overwriting a running exe is not).

The repo is public: updates work anonymously. A token (--token-env) is
still supported for private forks — never on the command line, never on
disk. Before executing a downloaded update, its Authenticode signer is
checked against thumbprints pinned inside the installed binary.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import urllib.request

# Signer pinning: an update is executed only if the downloaded exe carries an
# Authenticode signature from one of these certificates (SHA-1 thumbprints, as
# reported by Get-AuthenticodeSignature). This is a SECOND trust anchor:
# SHA256SUMS and the exe both come from the release, but the signer thumbprint
# is baked into the installed binary — a compromised release cannot forge it.
# Override with PLASMA_SIGNER_THUMBPRINTS (comma-separated) when rotating.
DEFAULT_SIGNER_THUMBPRINTS = {
    "BC67B990A783702D0C4761D557A58F9AD4534A68",  # Hyperspace Technologies Code Signing (self-signed, 2036)
}


def expected_signers() -> set:
    raw = os.environ.get("PLASMA_SIGNER_THUMBPRINTS", "").strip()
    if raw:
        return {t.strip().upper().replace(":", "").replace(" ", "")
                for t in raw.split(",") if t.strip()}
    return set(DEFAULT_SIGNER_THUMBPRINTS)


def verify_authenticode(exe_path, expected=None) -> dict:
    """Verify the Authenticode signer of a downloaded exe against pinned
    thumbprints. Trust-chain status is reported but not required (a lab box
    may not have the signer's root imported; the PIN is what matters)."""
    from pathlib import Path
    want = {t.upper().replace(":", "").replace(" ", "")
            for t in (expected if expected is not None else expected_signers())}
    if not want:
        return {"ok": False, "error": "no expected signer configured"}
    path = Path(exe_path)
    if not path.exists():
        return {"ok": False, "error": f"downloaded exe missing: {path}"}
    ps = shutil.which("powershell.exe") or shutil.which("pwsh")
    if not ps:
        return {"ok": False, "error": "cannot verify signature: no powershell on this host"}
    quoted = str(path).replace("'", "''")
    try:
        proc = subprocess.run(
            [ps, "-NoProfile", "-NonInteractive", "-Command",
             f"$s = Get-AuthenticodeSignature -LiteralPath '{quoted}'; "
             f"if ($s.SignerCertificate) {{ $s.SignerCertificate.Thumbprint + '|' + $s.Status }} "
             f"else {{ 'NOSIG|' + $s.Status }}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=90)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": f"signature check failed to run: {exc}"}
    out = (proc.stdout or "").strip().splitlines()
    line = out[-1].strip() if out else ""
    if "|" not in line:
        return {"ok": False, "error": "signature check emitted no verdict"}
    thumb_raw, status = line.split("|", 1)
    thumb = thumb_raw.strip().upper().replace(":", "").replace(" ", "")
    if thumb == "NOSIG" or not thumb:
        return {"ok": False, "error": "downloaded exe is unsigned", "status": status}
    if thumb not in want:
        return {"ok": False, "error": "signer thumbprint mismatch",
                "signer": thumb, "expected": sorted(want), "status": status}
    return {"ok": True, "signer": thumb, "status": status}


def _gh(url: str, token: str = "", timeout: int = 60,
        accept: str = "application/vnd.github+json") -> bytes:
    """GitHub API/file fetch. Anonymous when no token is supplied (the
    public repo needs none; a token remains supported for private forks)."""
    headers = {"Accept": accept, "User-Agent": "plasma-updater"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def latest_release(repo: str, token: str) -> dict:
    data = json.loads(_gh(f"https://api.github.com/repos/{repo}/releases/latest",
                          token).decode("utf-8"))
    assets = {a["name"]: a["url"] for a in data.get("assets", [])}
    return {"tag": data.get("tag_name", ""), "assets": assets}


def parse_version(tag: str) -> tuple:
    """'v1.2.3' -> (1, 2, 3). Pre-release suffixes (-rc1, -beta2) are ignored
    so a published v1.0.0 never reads as older than 'v1.0.0-rc2'."""
    parts = []
    for piece in tag.lstrip("v").split("."):
        digits = re.match(r"\d+", piece)
        parts.append(int(digits.group(0)) if digits else 0)
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
