"""Shared paths and canonicalisation for the agent trust layer."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any


def base(root=None) -> Path:
    if root:
        return Path(root)
    if os.name == "nt":
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Plasma"
    return Path.home() / ".plasma"


def ensure(root=None) -> Path:
    path = base(root)
    path.mkdir(parents=True, exist_ok=True)
    return path


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_obj(obj: Any) -> str:
    return hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def read_json(path: Path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def write_json(path: Path, obj) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(obj, indent=2, sort_keys=True) + "\n"
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass