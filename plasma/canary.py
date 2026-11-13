"""Plasma canary files: honest impact detection (T1486).

Ransomware crews enumerate and destroy user documents. A canary is a decoy
document in a known location whose only purpose is to be touched. Plasma
does not rely on heuristic "encryption bursts" (noisy, late); it records the
exact bytes of every canary at deploy time and verifies them on every
`watch` sweep or on demand.

    deploy  -> writes decoys + root/canaries.json (path, sha256, size)
    verify  -> missing or modified canary = finding, score 10
    status  -> manifest summary

The canary folder is excluded from normal operations: it is never read by
Plasma except by verify(), and deleting a canary is exactly the signal.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

MANIFEST_NAME = "canaries.json"
DEFAULT_SUBDIR = "Canaries"

# plausible document names — the point is to look worth encrypting
CANARY_NAMES = [
    "Finance_Q4_2026.xlsx",
    "Payroll_2026.csv",
    "Board_Minutes_Q4.docx",
    "Credentials_Backup.txt",
    "Invoices_Q4_2026.pdf",
    "Customer_Export_2026.xlsx",
]

CANARY_BODY = (
    "PLASMA CANARY FILE - DO NOT EDIT OR DELETE.\n"
    "This file is a decoy used to detect unauthorized access or encryption.\n"
    "Any modification is reported at maximum severity.\n"
)


def manifest_path(root) -> Path:
    return Path(root) / MANIFEST_NAME


def default_dir(root) -> Path:
    return Path(root) / DEFAULT_SUBDIR


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def deploy(root, extra_dirs=None, names=None) -> dict:
    """Create canary files and record their hashes. Existing canaries are
    left untouched (their current hash is recorded, not overwritten)."""
    root = Path(root)
    names = names or CANARY_NAMES
    dirs = [default_dir(root)] + [Path(d) for d in (extra_dirs or [])]
    entries = []
    created = 0
    for directory in dirs:
        directory.mkdir(parents=True, exist_ok=True)
        for name in names:
            path = directory / name
            if not path.exists():
                path.write_text(CANARY_BODY, encoding="utf-8")
                created += 1
            entries.append({
                "path": str(path),
                "sha256": _sha256(path),
                "size": path.stat().st_size,
            })
    manifest = {
        "deployed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "canaries": entries,
    }
    manifest_path(root).write_text(json.dumps(manifest, indent=1) + "\n",
                                   encoding="utf-8")
    return {"deployed": len(entries), "created": created,
            "manifest": str(manifest_path(root)),
            "dirs": [str(d) for d in dirs]}


def verify(root) -> dict:
    """Check every canary against its recorded hash.

    A missing or modified canary is a score-10 finding: ransomware or any
    destructive process touched a file that exists only to be touched."""
    mpath = manifest_path(root)
    if not mpath.exists():
        return {"error": "no canary manifest — run: plasma canary deploy",
                "checked": 0, "intact": 0, "tripped": [], "top_score": 0}
    try:
        manifest = json.loads(mpath.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"error": f"canary manifest unreadable: {exc}", "checked": 0,
                "intact": 0, "tripped": [], "top_score": 0}

    checked = intact = 0
    tripped = []
    for entry in manifest.get("canaries", []):
        path = Path(entry.get("path", ""))
        checked += 1
        if not path.exists():
            tripped.append({"path": str(path), "reason": "missing"})
            continue
        if _sha256(path) != entry.get("sha256"):
            tripped.append({"path": str(path), "reason": "modified"})
            continue
        intact += 1
    return {
        "checked": checked,
        "intact": intact,
        "tripped": tripped,
        "top_score": 10 if tripped else 0,
        "verdict": "canaries tripped" if tripped else "canaries intact",
    }


def status(root) -> dict:
    mpath = manifest_path(root)
    if not mpath.exists():
        return {"deployed": False,
                "hint": "plasma canary deploy --root <root>"}
    manifest = json.loads(mpath.read_text(encoding="utf-8-sig"))
    result = verify(root)
    return {"deployed": True,
            "manifest": str(mpath),
            "deployed_at": manifest.get("deployed_at"),
            "canaries": len(manifest.get("canaries", [])),
            "intact": result.get("intact", 0),
            "tripped": result.get("tripped", [])}
