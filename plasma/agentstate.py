"""Shared paths and canonicalisation for the agent trust layer."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from contextlib import contextmanager
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
        # utf-8-sig: PowerShell's Set-Content -Encoding UTF8 writes a BOM,
        # and a BOM made every such state file unreadable.
        return json.loads(Path(path).read_text(encoding="utf-8-sig"))
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

@contextmanager
def lock(path, timeout: float = 10.0, stale: float = 300.0):
    """Cross-process lock with a PID token and a stale-lock reclaim.

    The stale window must exceed the longest operation that holds the lock
    (actuate applies can run for 60 s); a 30 s window let a second process
    steal the journal lock mid-apply.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    token = f"{os.getpid()}:{time.time():.6f}"
    deadline = time.time() + timeout
    fd = None
    while fd is None:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, token.encode("ascii"))
        except FileExistsError:
            try:
                if time.time() - path.stat().st_mtime > stale:
                    path.unlink()
                    continue
            except OSError:
                pass
            if time.time() > deadline:
                raise TimeoutError(f"lock is held by another writer: {path}")
            time.sleep(0.05)
    try:
        yield
    finally:
        # Close before reading/unlinking: Windows keeps the file locked
        # while the handle is open, which left every lock behind.
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            if path.read_text(encoding="ascii", errors="replace") == token:
                path.unlink()
        except OSError:
            pass
