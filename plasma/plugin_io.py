"""Plugin I/O: ingest adapters and bounded exporters.

Inbound adapters turn an external source into PlasmaEvents; outbound
exporters push a bounded tail to another system. Both obey the same rules as
every other collector: fixed caps, no unbounded queue, failures are data.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from . import plugin_api, plugin_host
from .query import _load_rows, parse_time

DEFAULT_MAX_EVENTS = 500
MAX_BODY = 2 << 20
SPOOL_LINES = 5000


def _hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def ingest_jsonl(path, out_events, max_events: int = DEFAULT_MAX_EVENTS,
                 host: str | None = None, source: str = "jsonl") -> dict:
    """Read a bounded JSONL file and append normalised events."""
    source_path = Path(path)
    if not source_path.exists():
        return {"ok": False, "error": f"file not found: {source_path}",
                "written": 0}
    accepted, rejected = [], 0
    with source_path.open("r", encoding="utf-8", errors="replace") as handle:
        for index, line in enumerate(handle):
            if index >= max_events:
                break
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                rejected += 1
                continue
            try:
                if isinstance(raw, dict) and "type" in raw and "v" in raw:
                    payload = plugin_api.parse_line(line, "ingest")
                    if payload["type"] != "event":
                        rejected += 1
                        continue
                    event = plugin_api.normalize_event(
                        payload, f"ingest:{source}", host=host)
                elif isinstance(raw, dict):
                    event = plugin_api.normalize_event(
                        {"v": 1, "type": "event", "event": raw},
                        f"ingest:{source}", host=host)
                else:
                    raise plugin_api.PluginError("line is not an object")
            except plugin_api.PluginError:
                rejected += 1
                continue
            accepted.append(event)
    appended = plugin_host.append_events(out_events, accepted) if accepted else {
        "written": 0, "duplicates": 0, "out": str(out_events)}
    return {"ok": True, "read": len(accepted) + rejected,
            "accepted": len(accepted), "rejected": rejected,
            "written": appended["written"],
            "duplicates": appended["duplicates"],
            "source": source, "out": appended["out"]}


_SEVERITY = {
    "critical": "critical", "error": "high", "warning": "medium",
    "information": "info", "verbose": "info", "audit success": "info",
}


def _evtx_ts(value):
    """Accept ISO and PowerShell's legacy /Date(ms)/ serialisation."""
    text = str(value or "")
    if text.startswith("/Date(") and text.endswith(")/"):
        try:
            millis = int(text[6:-2].split("+")[0].split("-")[0])
            return datetime.fromtimestamp(
                millis / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        except (ValueError, OSError):
            return None
    return value


def parse_evtx_output(text: str, channel: str, host: str | None = None,
                      limit: int = DEFAULT_MAX_EVENTS) -> list[dict]:
    """Normalise the compact JSON emitted by the Event Log reader."""
    try:
        payload = json.loads(text or "null")
    except json.JSONDecodeError:
        return []
    rows = payload if isinstance(payload, list) else [payload]
    events = []
    for row in rows[:limit]:
        if not isinstance(row, dict):
            continue
        try:
            stamp = _evtx_ts(row.get("TimeCreated"))
            event = plugin_api.normalize_event({
                "v": 1, "type": "event", "event": {
                    "ts": stamp,
                    "host": host or row.get("MachineName") or _hostname(),
                    "kind": "alert",
                    "event_id": row.get("Id") or 0,
                    "severity": _SEVERITY.get(
                        str(row.get("LevelDisplayName") or "").lower(), "info"),
                    "score": 0.0,
                    "user": row.get("UserId"),
                    "description": str(row.get("Message") or "")[:2000],
                }
            }, f"ingest:evtx:{channel}", host=host)
        except plugin_api.PluginError:
            continue
        events.append(event)
    return events


def ingest_evtx(channel: str, out_events, since_minutes: int = 15,
                max_events: int = DEFAULT_MAX_EVENTS,
                host: str | None = None) -> dict:
    """Read a Windows Event Log channel read-only through Get-WinEvent."""
    if os.name != "nt":
        return {"ok": False, "error": "evtx ingest is Windows-only", "written": 0}
    since_minutes = max(1, min(int(since_minutes), 1440))
    max_events = max(1, min(int(max_events), 5000))
    script = (
        "$ErrorActionPreference='Stop';"
        f"$e=Get-WinEvent -FilterHashtable @{{LogName='{channel}';"
        f"StartTime=(Get-Date).AddMinutes(-{since_minutes})}} "
        f"-MaxEvents {max_events} -ErrorAction Stop | "
        "Select-Object TimeCreated,Id,ProviderName,LevelDisplayName,Message,UserId;"
        "if($e){$e|ConvertTo-Json -Depth 3 -Compress}")
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-EncodedCommand", encoded],
            capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "error": str(exc)[:300], "written": 0}
    if proc.returncode != 0:
        return {"ok": False, "error": (proc.stderr or "")[:300], "written": 0}
    events = parse_evtx_output(proc.stdout, channel, host=host, limit=max_events)
    appended = plugin_host.append_events(out_events, events) if events else {
        "written": 0, "duplicates": 0, "out": str(out_events)}
    return {"ok": True, "channel": channel, "read": len(events),
            "written": appended["written"],
            "duplicates": appended["duplicates"], "out": appended["out"]}


# ---------------------------------------------------------------------------
# webhook receiver
# ---------------------------------------------------------------------------

def _signature(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body,
                               hashlib.sha256).hexdigest()


def handle_webhook(body: bytes, secret: str | None, signature: str | None,
                   out_events, max_events: int = DEFAULT_MAX_EVENTS,
                   host: str | None = None) -> dict:
    if len(body) > MAX_BODY:
        return {"ok": False, "error": "body too large", "status": 413,
                "written": 0}
    if secret and (not signature or not hmac.compare_digest(
            signature, _signature(secret, body))):
        return {"ok": False, "error": "bad signature", "status": 401,
                "written": 0}
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"ok": False, "error": "invalid json", "status": 400,
                "written": 0}
    if isinstance(payload, dict) and "events" in payload:
        rows = payload["events"]
    elif isinstance(payload, list):
        rows = payload
    else:
        rows = [payload]
    if not isinstance(rows, list):
        return {"ok": False, "error": "events must be a list", "status": 400,
                "written": 0}
    events, rejected = [], 0
    for raw in rows[:max_events]:
        try:
            if isinstance(raw, dict) and "type" in raw and "v" in raw:
                envelope = plugin_api.parse_line(
                    json.dumps(raw), str(raw.get("plugin") or "ingest"))
                event = plugin_api.normalize_event(envelope, "ingest:webhook",
                                                   host=host)
            else:
                event = plugin_api.normalize_event(
                    {"v": 1, "type": "event", "event": raw},
                    "ingest:webhook", host=host)
        except plugin_api.PluginError:
            rejected += 1
            continue
        events.append(event)
    appended = plugin_host.append_events(out_events, events) if events else {
        "written": 0, "duplicates": 0, "out": str(out_events)}
    return {"ok": True, "accepted": len(events), "rejected": rejected,
            "written": appended["written"], "status": 200,
            "out": appended["out"]}


class _WebhookHandler(BaseHTTPRequestHandler):
    server_version = "PlasmaIngest/1.0"

    def log_message(self, format, *args):
        return

    def do_POST(self):
        if self.path.split("?", 1)[0] != self.server.webhook_path:  # type: ignore[attr-defined]
            self.send_response(404)
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            self.send_response(413 if length > MAX_BODY else 400)
            self.end_headers()
            return
        body = self.rfile.read(length)
        result = handle_webhook(
            body, self.server.secret,  # type: ignore[attr-defined]
            self.headers.get("X-Plasma-Signature"),
            self.server.out_events,  # type: ignore[attr-defined]
            max_events=self.server.max_events,  # type: ignore[attr-defined]
            host=self.server.host)  # type: ignore[attr-defined]
        status = result.get("status", 200 if result.get("ok") else 400)
        payload = json.dumps({key: result[key] for key in (
            "ok", "accepted", "rejected", "written", "error") if key in result}
        ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        if result.get("ok"):
            self.server.accepted += result.get("accepted", 0)  # type: ignore[attr-defined]
            self.server.requests += 1  # type: ignore[attr-defined]


def serve_webhook(bind: str, port: int, path: str, secret: str | None,
                  out_events, max_events: int = DEFAULT_MAX_EVENTS,
                  seconds: int = 30, once: bool = False,
                  host: str | None = None) -> dict:
    server = HTTPServer((bind, int(port)), _WebhookHandler)
    server.timeout = 0.5
    server.webhook_path = path or "/ingest"  # type: ignore[attr-defined]
    server.secret = secret  # type: ignore[attr-defined]
    server.out_events = out_events  # type: ignore[attr-defined]
    server.max_events = max_events  # type: ignore[attr-defined]
    server.host = host  # type: ignore[attr-defined]
    server.accepted = 0  # type: ignore[attr-defined]
    server.requests = 0  # type: ignore[attr-defined]
    deadline = time.time() + max(1, int(seconds))
    try:
        while time.time() < deadline:
            server.handle_request()
            if once and server.requests >= 1:  # type: ignore[attr-defined]
                break
            if server.accepted >= max_events:  # type: ignore[attr-defined]
                break
        bound_port = server.server_address[1]
    finally:
        server.server_close()
    return {"ok": True, "bind": bind, "port": bound_port,
            "requests": server.requests, "accepted": server.accepted,  # type: ignore[attr-defined]
            "path": server.webhook_path, "out": str(out_events)}


# ---------------------------------------------------------------------------
# exporters
# ---------------------------------------------------------------------------

def _spool(root, name: str, rows: list[dict]) -> dict:
    path = Path(root) / "export-spool" / f"{name}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = []
    if path.exists():
        existing = path.read_text(encoding="utf-8", errors="replace").splitlines()
    merged = (existing + [json.dumps(row, separators=(",", ":"), default=str)
                          for row in rows])[-SPOOL_LINES:]
    path.write_text("\n".join(merged) + "\n", encoding="utf-8")
    return {"path": str(path), "lines": len(merged)}


def export_webhook(url: str, out_events, root, secret: str | None = None,
                   since=None, max_events: int = DEFAULT_MAX_EVENTS,
                   batch_size: int = 100, retries: int = 3) -> dict:
    parsed = urllib.parse.urlparse(str(url))
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return {"ok": False, "error": "export url must be http(s)",
                "delivered": 0}
    rows = _load_rows(out_events, max_rows=max_events)
    since_dt = parse_time(since) if since else None
    if since_dt is not None:
        rows = [row for row in rows
                if _row_dt(row) is not None and _row_dt(row) >= since_dt]
    rows = rows[-max_events:]
    delivered, batches, failed = 0, 0, None
    batch_size = max(1, min(int(batch_size), 500))
    for start in range(0, len(rows), batch_size):
        batch = rows[start:start + batch_size]
        body = json.dumps({"events": batch}, separators=(",", ":")).encode()
        headers = {"Content-Type": "application/json"}
        if secret:
            headers["X-Plasma-Signature"] = _signature(secret, body)
        last_error = None
        for attempt in range(max(1, int(retries))):
            request = urllib.request.Request(
                url, data=body, headers=headers, method="POST")
            try:
                # Scheme checked above; only http(s) reaches urlopen.
                with urllib.request.urlopen(  # nosec B310
                        request, timeout=10) as response:
                    if 200 <= response.status < 300:
                        delivered += len(batch)
                        batches += 1
                        last_error = None
                        break
                    last_error = f"HTTP {response.status}"
            except (urllib.error.URLError, OSError) as exc:
                last_error = str(exc)[:200]
            time.sleep(min(2 ** attempt, 4) * 0.1)
        if last_error:
            failed = last_error
            spooled = _spool(root, "webhook", rows[start:])
            return {"ok": False, "delivered": delivered, "batches": batches,
                    "error": failed, "spooled": spooled, "remaining": len(rows) - start}
    return {"ok": True, "delivered": delivered, "batches": batches,
            "total": len(rows)}


def _row_dt(row):
    text = str(row.get("ts") or "")
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def export_syslog(host: str, port: int, protocol: str, out_events,
                  since=None, max_events: int = DEFAULT_MAX_EVENTS) -> dict:
    rows = _load_rows(out_events, max_rows=max_events)
    since_dt = parse_time(since) if since else None
    if since_dt is not None:
        rows = [row for row in rows
                if _row_dt(row) is not None and _row_dt(row) >= since_dt]
    rows = rows[-max_events:]
    protocol = "udp" if str(protocol).lower() == "udp" else "tcp"
    sock_type = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    sent = 0
    try:
        with socket.socket(socket.AF_INET, sock_type) as sock:
            sock.settimeout(5)
            if protocol == "tcp":
                sock.connect((host, int(port)))
            for row in rows:
                line = f"<134>1 {row.get('ts') or '-'} {_hostname()} plasma - - " \
                       + json.dumps(row, separators=(",", ":"), default=str)
                payload = line.encode("utf-8")[:8192]
                if protocol == "udp":
                    sock.sendto(payload, (host, int(port)))
                else:
                    sock.sendall(payload + b"\n")
                sent += 1
    except OSError as exc:
        return {"ok": False, "error": str(exc)[:300], "sent": sent,
                "protocol": protocol}
    return {"ok": True, "sent": sent, "protocol": protocol,
            "host": host, "port": int(port)}
