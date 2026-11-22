"""Plugin host: run sensors and detectors as bounded child processes.

A plugin can crash, hang, flood stdout or emit garbage. None of that may take
down the caller: stdout is drained on a thread, every line is validated, the
run has a hard deadline, and events are appended only after normalisation and
dedupe. Stderr goes to a plugin log, never to the operator's JSON.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
from pathlib import Path

from . import plugin_api, plugins


def events_path(root) -> Path:
    try:
        from .watch import _events_path as watch_events
        return watch_events(root)
    except (ImportError, OSError):
        return Path(root) / "data" / "events.jsonl"


def append_events(events_path, events: list[dict],
                  max_existing: int = 5000) -> dict:
    """Append normalised events with a bounded dedupe window."""
    path = Path(events_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    seen = set()
    if path.exists():
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                lines = handle.readlines()[-max_existing:]
        except OSError:
            lines = []
        for line in lines:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                seen.add(plugin_api.dedupe_key(row))
    fresh = []
    for event in events:
        key = plugin_api.dedupe_key(event)
        if key in seen:
            continue
        seen.add(key)
        fresh.append(event)
    if fresh:
        with path.open("a", encoding="utf-8") as handle:
            for event in fresh:
                handle.write(json.dumps(event, separators=(",", ":"),
                                        default=str) + "\n")
    return {"written": len(fresh), "duplicates": len(events) - len(fresh),
            "out": str(path)}


def _reader(stream, sink: queue.Queue, max_line: int) -> None:
    try:
        while True:
            line = stream.readline(max_line + 1)
            if not line:
                break
            sink.put(line)
    except (ValueError, OSError):
        pass
    finally:
        sink.put(None)


def _log_path(root, name: str) -> Path:
    path = Path(root) / "logs" / f"plugin-{name}.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _manifest_limits(manifest: dict) -> dict:
    limits = manifest.get("limits") or {}
    return {
        "max_events": max(1, int(limits.get("max_events") or 1000)),
        "max_line_bytes": min(plugin_api.MAX_LINE,
                              int(limits.get("max_line_bytes") or plugin_api.MAX_LINE)),
        "timeout_seconds": max(1, int(limits.get("timeout_seconds") or 60)),
    }


def run_sensor(root, name: str, out_events=None, max_events: int | None = None,
               timeout_seconds: int | None = None, force: bool = False) -> dict:
    entry, manifest, base = plugins.load_installed(root, name)
    if manifest.get("kind") != "sensor":
        raise plugin_api.PluginError(f"plugin {name!r} is a {manifest.get('kind')}, not a sensor")
    if not entry.get("enabled") and not force:
        raise plugin_api.PluginError(
            f"plugin {name!r} is disabled (enable it or pass --force)")
    limits = _manifest_limits(manifest)
    limit = min(int(max_events or limits["max_events"]), limits["max_events"])
    timeout = min(int(timeout_seconds or limits["timeout_seconds"]),
                  limits["timeout_seconds"])
    argv = plugin_api.entry_command(manifest, base)
    env = {**os.environ,
           "PLASMA_PLUGIN_NAME": name,
           "PLASMA_PLUGIN_ROOT": str(root),
           "PLASMA_PLUGIN_MAX_EVENTS": str(limit),
           "PYTHONUNBUFFERED": "1"}
    started = time.time()
    proc = subprocess.Popen(
        argv, cwd=str(base), env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace", bufsize=1)
    sink: queue.Queue = queue.Queue()
    threading.Thread(target=_reader, args=(proc.stdout, sink,
                                           limits["max_line_bytes"]),
                     daemon=True).start()
    stderr_chunks: list[str] = []

    def _stderr_reader():
        try:
            for chunk in proc.stderr:
                stderr_chunks.append(chunk)
                if sum(len(part) for part in stderr_chunks) > 8192:
                    del stderr_chunks[:-10]
        except (ValueError, OSError):
            pass

    threading.Thread(target=_stderr_reader, daemon=True).start()

    accepted: list[dict] = []
    rejected = 0
    health = None
    deadline = started + timeout
    timed_out = False
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            timed_out = True
            break
        try:
            line = sink.get(timeout=min(0.2, remaining))
        except queue.Empty:
            if proc.poll() is not None and sink.empty():
                break
            continue
        if line is None:
            break
        if len(line.encode("utf-8", "replace")) > limits["max_line_bytes"]:
            rejected += 1
        else:
            try:
                payload = plugin_api.parse_line(line, name)
                if payload["type"] == "event":
                    accepted.append(plugin_api.normalize_event(
                        payload, name, manifest.get("version", "")))
                elif payload["type"] == "finding":
                    accepted.append(plugin_api.normalize_finding(
                        payload, name, manifest.get("version", "")))
                elif payload["type"] == "health":
                    health = payload.get("status")
                # logs are intentionally ignored: stderr is the log
            except plugin_api.PluginError:
                rejected += 1
        if len(accepted) >= limit or rejected >= 10:
            break
    capped = len(accepted) >= limit
    if proc.poll() is None and capped:
        try:
            proc.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            pass
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass

    log_path = _log_path(root, name)
    stderr_text = "".join(stderr_chunks)[-8000:]
    if stderr_text:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(stderr_text)

    appended = append_events(
        out_events or events_path(root), accepted[:limit]) if accepted else {
        "written": 0, "duplicates": 0, "out": str(out_events or events_path(root))}
    status = "timeout" if timed_out else (
        "quarantined" if rejected >= 10 else
        "ok" if capped or proc.returncode in (0, None)
        else f"exit:{proc.returncode}")
    plugins.update_run(root, name, status, {
        "accepted": len(accepted), "rejected": rejected,
        "written": appended["written"], "timed_out": timed_out,
    })
    return {
        "ok": status in ("ok", "timeout") and rejected < 10,
        "name": name, "status": status, "accepted": len(accepted),
        "rejected": rejected, "written": appended["written"],
        "duplicates": appended["duplicates"], "out": appended["out"],
        "timed_out": timed_out, "health": health,
        "duration_seconds": round(time.time() - started, 2),
        "log": str(log_path) if stderr_text else None,
    }


def run_detector(root, name: str, out_events=None, since=None,
                 max_rows: int = 5000, timeout_seconds: int = 15) -> dict:
    entry, manifest, base = plugins.load_installed(root, name)
    if manifest.get("kind") != "detector":
        raise plugin_api.PluginError(
            f"plugin {name!r} is a {manifest.get('kind')}, not a detector")
    if not entry.get("enabled"):
        raise plugin_api.PluginError(f"plugin {name!r} is disabled")
    source = Path(out_events or events_path(root))
    argv = plugin_api.entry_command(manifest, base) + [
        "--events", str(source), "--max-rows", str(int(max_rows))]
    if since:
        argv += ["--since", str(since)]
    limits = _manifest_limits(manifest)
    max_score = float((manifest.get("limits") or {}).get("max_score", 1.0))
    try:
        proc = subprocess.run(argv, cwd=str(base), capture_output=True,
                              text=True, timeout=min(timeout_seconds,
                                                     limits["timeout_seconds"]),
                              check=False)
    except subprocess.TimeoutExpired as exc:
        plugins.update_run(root, name, "timeout", {"error": "detector timeout"})
        return {"ok": False, "name": name, "status": "timeout",
                "error": str(exc)[:300], "written": 0}
    findings = []
    rejected = 0
    for line in (proc.stdout or "").splitlines():
        if not line.strip():
            continue
        try:
            payload = plugin_api.parse_line(line, name)
            if payload["type"] != "finding":
                continue
            findings.append(plugin_api.normalize_finding(
                payload, name, manifest.get("version", ""),
                max_score=max_score))
        except plugin_api.PluginError:
            rejected += 1
    appended = append_events(source, findings) if findings else {
        "written": 0, "duplicates": 0, "out": str(source)}
    status = "ok" if proc.returncode == 0 and rejected == 0 else (
        "quarantined" if rejected else f"exit:{proc.returncode}")
    plugins.update_run(root, name, status, {
        "findings": len(findings), "written": appended["written"],
        "rejected": rejected,
    })
    return {
        "ok": status == "ok", "name": name, "status": status,
        "findings": len(findings), "written": appended["written"],
        "duplicates": appended["duplicates"], "rejected": rejected,
        "exit_code": proc.returncode,
        "stderr": (proc.stderr or "")[:500],
        "out": appended["out"],
    }
