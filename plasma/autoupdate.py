"""Measured self-update.

The installer registers a daily ``PlasmaUpdate`` task. It checks the latest
signed release, respects the deployment ring and a maintenance window, then
runs the same download → SHA256 → Authenticode → install → rotate path as
``plasma update apply``. The previous binary is kept for rollback.

Defaults are deliberately conservative:

* signed releases only;
* a 24-hour canary hold before ``broad`` hosts update;
* a 02:00–05:00 local maintenance window;
* the kill switch pauses updates;
* one update at a time (a cross-process lock).
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, agentstate, killswitch, notify, rings, statemachine
from . import update as updater

DEFAULT_UPDATE: dict = {
    "auto": True,
    "repo": "DrOlu/plasma",
    "ring": "broad",
    "every_hours": 24,
    "window_start_hour": 2,
    "window_end_hour": 5,
    "canary_hold_hours": 24,
    "allow_unsigned": False,
    "restart_serve": True,
    "notify": True,
    # Set by the installer to the registered task name (or "disabled").
    "task": "PlasmaUpdate",
}

STATE_FILE = "update-state.json"
JOURNAL_FILE = "update-journal.jsonl"


def config(root=None) -> dict:
    cfg = dict(DEFAULT_UPDATE)
    data = agentstate.read_json(agentstate.base(root) / "config.json", {}) or {}
    block = data.get("update") if isinstance(data, dict) else {}
    if isinstance(block, dict):
        for key, value in block.items():
            if key in DEFAULT_UPDATE and value is not None:
                cfg[key] = value
    cfg["auto"] = bool(cfg["auto"])
    cfg["allow_unsigned"] = bool(cfg["allow_unsigned"])
    cfg["restart_serve"] = bool(cfg["restart_serve"])
    cfg["notify"] = bool(cfg["notify"])
    try:
        cfg["every_hours"] = max(1, int(cfg["every_hours"]))
    except (TypeError, ValueError):
        cfg["every_hours"] = 24
    try:
        cfg["window_start_hour"] = int(cfg["window_start_hour"]) % 24
        cfg["window_end_hour"] = int(cfg["window_end_hour"]) % 24
    except (TypeError, ValueError):
        cfg["window_start_hour"], cfg["window_end_hour"] = 2, 5
    try:
        cfg["canary_hold_hours"] = max(0, int(cfg["canary_hold_hours"]))
    except (TypeError, ValueError):
        cfg["canary_hold_hours"] = 24
    if cfg["ring"] not in ("canary", "broad", "rollback"):
        cfg["ring"] = "broad"
    return cfg


def state_path(root=None) -> Path:
    return agentstate.base(root) / STATE_FILE


def journal_path(root=None) -> Path:
    return agentstate.base(root) / JOURNAL_FILE


def load_state(root=None) -> dict:
    data = agentstate.read_json(state_path(root), {}) or {}
    return data if isinstance(data, dict) else {}


def _save_state(root, data: dict) -> dict:
    agentstate.write_json(state_path(root), data)
    return data


def _journal(root, entry: dict) -> dict:
    path = journal_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = dict(entry)
    entry.setdefault("ts", agentstate.now_iso())
    with agentstate.lock(path.parent / ".update-journal.lock", stale=300), \
            path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    return entry


def _parse_iso(value):
    if not value:
        return None
    try:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp


def in_window(cfg: dict, now: datetime | None = None) -> bool:
    now = now or datetime.now()
    start = cfg["window_start_hour"]
    end = cfg["window_end_hour"]
    if start == end:
        return True
    if start < end:
        return start <= now.hour < end
    return now.hour >= start or now.hour < end


def canary_hold_ok(release: dict, cfg: dict,
                   now: datetime | None = None) -> bool:
    if cfg.get("ring") != "broad":
        return True
    hold = int(cfg.get("canary_hold_hours", 0))
    if hold <= 0:
        return True
    published = _parse_iso(release.get("published_at"))
    if published is None:
        return True
    now = now or datetime.now(timezone.utc)
    return (now - published).total_seconds() >= hold * 3600


def ring_ok(root, host: str, ring: str | None = None) -> bool:
    ring = ring or config(root)["ring"]
    if ring == "rollback":
        return False
    state = rings.status(root)
    # No rings configured: broad is the default for every host.
    if ring == "broad" and not state["rings"].get("canary") \
            and not state["rings"].get("broad"):
        return True
    return rings.allows(root, host, ring)


def _state(root, target: str, detail=None) -> None:
    try:
        current = statemachine.load(root, statemachine.UPDATE_MACHINE)["state"]
        if current != "idle":
            statemachine.reset(root, statemachine.UPDATE_MACHINE, "auto update")
        if target != "idle":
            statemachine.transition(root, statemachine.UPDATE_MACHINE, target,
                                    detail)
    except Exception:  # noqa: BLE001, S110 - observability must not block the update
        pass


TASKS = ("PlasmaServe", "PlasmaWatch", "PlasmaWhidsWatchdog",
         "PlasmaIdentityPull")


def _task_running(task: str) -> bool:
    if os.name != "nt":
        return False
    query = subprocess.run(
        ["schtasks.exe", "/query", "/tn", task, "/fo", "LIST"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        check=False,
    )
    if query.returncode != 0:
        return False
    for line in query.stdout.splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() == "status":
            return value.strip().lower() == "running"
    return False


def _kill_lingering_serve() -> list[int]:
    """Kill serve processes that outlive their scheduled-task parent.

    A PyInstaller one-file executable re-execs itself as a child. Ending the
    task kills the bootloader but can leave that child holding the port and
    the old image, so a restart would bind-fail and the API would keep
    reporting the previous version.
    """
    if os.name != "nt":
        return []
    script = (
        f"$me = {os.getpid()}; "
        "Get-CimInstance Win32_Process -Filter \"Name LIKE 'plasma%'\" | "
        "Where-Object { $_.ProcessId -ne $me -and "
        "$_.CommandLine -match '(^|\\s)serve(\\s|$)' } | "
        "ForEach-Object { Stop-Process -Id $_.ProcessId -Force "
        "-ErrorAction SilentlyContinue; $_.ProcessId }"
    )
    run = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        check=False,
    )
    return [int(tok) for tok in run.stdout.split() if tok.strip().isdigit()]


def _stop_tasks(restart_serve: bool = True, skip_serve: bool = False) -> dict:
    """Stop the tasks that hold the binary open during rotation.

    ``skip_serve`` is set when this update was launched *by* ``plasma serve``:
    ending the serve task would kill the process tree that is doing the
    update. Renaming a running exe is still legal, so rotation can proceed.
    """
    if os.name != "nt":
        return {}
    stopped = {}
    for task in TASKS:
        if task == "PlasmaServe" and (not restart_serve or skip_serve):
            continue
        if not _task_running(task):
            continue
        end = subprocess.run(
            ["schtasks.exe", "/end", "/tn", task],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            check=False,
        )
        stopped[task] = end.returncode == 0
    if not skip_serve:
        killed = _kill_lingering_serve()
        if killed:
            stopped["_killed_serve"] = killed
    if stopped:
        time.sleep(3)
    return stopped


def _start_tasks(stopped: dict) -> dict:
    if os.name != "nt":
        return {}
    started = {}
    for task, was_stopped in stopped.items():
        if task.startswith("_") or not was_stopped:
            continue
        run = subprocess.run(
            ["schtasks.exe", "/run", "/tn", task],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            check=False,
        )
        started[task] = run.returncode == 0
    return started


def _rotate_with_retry(staged, target, attempts: int = 5) -> dict:
    result = {"ok": False, "error": "not attempted"}
    for attempt in range(attempts):
        result = updater.rotate_bin(staged, target)
        if result.get("ok"):
            return result
        time.sleep(1)
    return result


def rotate_running(staged, target, restart_serve: bool = True) -> dict:
    """Quiesce the tasks, rotate the running/canonical binaries, restart.

    Shared by ``update auto`` and the manual ``update apply`` path so both
    are equally robust against an in-use image.
    """
    target = Path(target)
    stopped = _stop_tasks(
        restart_serve,
        skip_serve=os.environ.get("PLASMA_SERVE_CHILD") == "1")
    rotation = {"ok": False, "error": "not attempted"}
    canonical_rotation = None
    try:
        rotation = _rotate_with_retry(staged, target)
        canonical = target.parent / "plasma.exe"
        if canonical != target:
            canonical_rotation = _rotate_with_retry(staged, canonical)
    finally:
        started = _start_tasks(stopped)
    return {"rotation": rotation, "canonical": canonical_rotation,
            "stopped": stopped, "started": started}


def _notify(root, cfg, title: str, body: str) -> dict | None:
    if not cfg.get("notify"):
        return None
    try:
        return notify.notify_all(root, title, body)
    except Exception as exc:  # noqa: BLE001 - delivery is best-effort
        return {"configured": 0, "sent": 0, "error": str(exc)[:200]}


def check(root=None, repo: str | None = None, tag: str | None = None,
          token: str | None = None) -> dict:
    cfg = config(root)
    repo = repo or cfg["repo"]
    rel = updater.latest_release(repo, token or os.environ.get(
        "PLASMA_GITHUB_TOKEN", ""), tag=tag)
    newer = updater.is_newer(__version__, rel["tag"])
    host = socket.gethostname() or "localhost"
    return {
        "ok": True,
        "current": __version__,
        "latest": rel["tag"],
        "update_available": newer,
        "published_at": rel.get("published_at"),
        "ring": rings.host_ring(root, host) or cfg["ring"],
        "auto": cfg["auto"],
    }


def auto(root=None, repo: str | None = None, ring: str | None = None,
         check_only: bool = False, force: bool = False,
         allow_unsigned: bool | None = None,
         notify_enabled: bool | None = None,
         token: str | None = None) -> dict:
    """Check and optionally apply the latest signed release."""
    root = agentstate.base(root)
    cfg = config(root)
    host = socket.gethostname() or "localhost"
    repo = repo or cfg["repo"]
    # An explicit host assignment is the local, human-set fact. Only fall
    # back to the configured default when the host is not in any ring.
    ring = ring or rings.host_ring(root, host) or cfg["ring"]
    allow_unsigned = (cfg["allow_unsigned"] if allow_unsigned is None
                      else bool(allow_unsigned))
    notify_enabled = (cfg["notify"] if notify_enabled is None
                      else bool(notify_enabled))
    now = datetime.now()
    base = {"host": host, "current": __version__, "ring": ring,
            "repo": repo, "check_only": check_only, "force": force}

    if not check_only and not force and not cfg["auto"]:
        return {**base, "ok": True, "status": "skipped",
                "reason": "automatic update disabled"}

    if not check_only and killswitch.blocked(root, host=host, risk="high"):
        return {**base, "ok": True, "status": "skipped",
                "reason": "kill switch is engaged for this host"}

    if not check_only and not force and not in_window(cfg, now):
        return {**base, "ok": True, "status": "skipped",
                "reason": (f"outside update window "
                           f"{cfg['window_start_hour']:02d}:00-"
                           f"{cfg['window_end_hour']:02d}:00")}

    if not ring_ok(root, host, ring):
        return {**base, "ok": True, "status": "skipped",
                "reason": f"host {host!r} is not in ring {ring!r}"}

    token = token if token is not None else os.environ.get(
        "PLASMA_GITHUB_TOKEN", "")
    rel = updater.latest_release(repo, token, tag=None)
    newer = updater.is_newer(__version__, rel["tag"])
    base.update({"latest": rel["tag"], "update_available": newer,
                 "published_at": rel.get("published_at")})

    if not newer and not force:
        _save_state(root, {
            "last_check": agentstate.now_iso(),
            "last_result": "up_to_date",
            "current": __version__,
            "latest": rel["tag"],
        })
        return {**base, "ok": True, "status": "up_to_date"}

    if ring == "broad" and not force and not canary_hold_ok(rel, cfg):
        return {**base, "ok": True, "status": "skipped",
                "reason": (f"canary hold: release is newer than "
                           f"{cfg['canary_hold_hours']}h")}

    if check_only:
        _save_state(root, {
            "last_check": agentstate.now_iso(),
            "last_result": "update_available",
            "current": __version__,
            "latest": rel["tag"],
        })
        return {**base, "ok": True, "status": "update_available"}

    lock = root / "update-auto.lock"
    try:
        with agentstate.lock(lock, timeout=5, stale=3600):
            result = _apply(root, cfg, host, repo, rel, token,
                            allow_unsigned, notify_enabled)
            _save_state(root, {
                "last_check": agentstate.now_iso(),
                "last_result": result.get("status"),
                "current": __version__,
                "latest": rel["tag"],
                "detail": result.get("reason") or result.get("error"),
            })
            return {**base, **result}
    except TimeoutError:
        return {**base, "ok": True, "status": "skipped",
                "reason": "another update is already running"}


def _apply(root, cfg, host, repo, rel, token, allow_unsigned,
           notify_enabled) -> dict:
    staged = root / "tools" / "plasma-update-staged.exe"
    download = updater.download_and_verify(repo, rel["tag"], token, staged)
    if not download.get("ok"):
        _journal(root, {"host": host, "status": "failed", "stage": "download",
                        "detail": download.get("error")})
        _state(root, "failed", "download failed")
        return {"ok": False, "status": "failed", "stage": "download",
                "error": download.get("error")}
    _state(root, "staged", rel["tag"])

    signature = updater.verify_authenticode(staged)
    if not signature.get("ok") and not allow_unsigned:
        _journal(root, {"host": host, "status": "refused",
                        "stage": "signature", "detail": signature.get("error")})
        _state(root, "failed", "signature verification failed")
        return {"ok": False, "status": "refused", "stage": "signature",
                "error": signature.get("error"),
                "hint": "dev builds may pass --allow-unsigned"}
    _state(root, "verified", signature.get("status") or "signature ok")

    _state(root, "installing")
    install = subprocess.run(
        [str(staged), "install", "--force", "--root", str(root)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=900, check=False,
    )
    if install.returncode != 0:
        detail = (install.stderr or install.stdout or "")[-500:]
        _journal(root, {"host": host, "status": "failed",
                        "stage": "install", "detail": detail})
        _state(root, "failed", f"install rc={install.returncode}")
        return {"ok": False, "status": "failed", "stage": "install",
                "error": f"install exited {install.returncode}",
                "detail": detail}
    _state(root, "installed", rel["tag"])

    # Windows will not let us replace a versioned binary that a scheduled
    # task has open. Stop the tasks that hold it, rotate, then restart them.
    # PlasmaUpdate itself is not stopped: it is the process running this code.
    current = root / "bin" / Path(sys.executable).name
    rotated = rotate_running(staged, current,
                             bool(cfg.get("restart_serve", True)))
    rotation = rotated["rotation"]
    canonical_rotation = rotated["canonical"]
    stopped = rotated["stopped"]
    started = rotated["started"]
    if not rotation.get("ok"):
        _journal(root, {"host": host, "status": "failed",
                        "stage": "rotate", "detail": rotation.get("error"),
                        "stopped": stopped, "started": started})
        _state(root, "failed", "bin rotation failed")
        return {"ok": False, "status": "failed", "stage": "rotate",
                "error": rotation.get("error"),
                "stopped": stopped, "started": started}
    _state(root, "rotated", rel["tag"])

    serve = {"stopped": stopped, "started": started}
    notification = _notify(
        root, cfg, "Plasma auto-update",
        f"{host}: {__version__} -> {rel['tag']}")

    entry = _journal(root, {
        "host": host,
        "status": "updated",
        "from": __version__,
        "to": rel["tag"],
        "sha256": download.get("sha256"),
        "signer": signature.get("signer"),
        "bin": rotation.get("bin"),
        "canonical": (canonical_rotation or {}).get("bin"),
        "serve_restart": serve,
        "notify": notification,
    })
    return {"ok": True, "status": "updated", "from": __version__,
            "to": rel["tag"], "sha256": download.get("sha256"),
            "signer": signature.get("signer"),
            "bin": rotation.get("bin"),
            "canonical": (canonical_rotation or {}).get("bin"),
            "serve_restart": serve, "journal": entry.get("ts")}
