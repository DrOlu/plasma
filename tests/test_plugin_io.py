"""Ingest adapters, webhook receiver and bounded exporters."""
from __future__ import annotations

import hashlib
import hmac
import json
import socket
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from plasma import plugin_io


def _event(index=0):
    return {
        "ts": f"2026-11-22T10:0{index}:00Z", "host": "WS1", "kind": "process",
        "process": "cmd.exe", "parent": "explorer.exe", "pid": 100 + index,
        "score": 0.2, "description": "ingested",
    }


def _write(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(
        line if isinstance(line, str) else json.dumps(line) + "\n"
        for line in rows))
    return path


def _read(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def _sign(secret, body):
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


# ---------------------------------------------------------------------------
# jsonl and evtx
# ---------------------------------------------------------------------------

def test_ingest_jsonl_normalises_and_rejects_garbage(tmp_path):
    source = _write(tmp_path / "in.jsonl", [
        _event(0), "not json\n", _event(1)])
    out = tmp_path / "events.jsonl"
    result = plugin_io.ingest_jsonl(source, out, max_events=10)
    assert result["accepted"] == 2 and result["rejected"] == 1
    assert result["written"] == 2
    rows = _read(out)
    assert rows[0]["source"] == "plugin:ingest:jsonl"
    assert rows[0]["host"] == "WS1"


def test_ingest_jsonl_is_idempotent(tmp_path):
    source = _write(tmp_path / "in.jsonl", [_event(0)])
    out = tmp_path / "events.jsonl"
    assert plugin_io.ingest_jsonl(source, out)["written"] == 1
    second = plugin_io.ingest_jsonl(source, out)
    assert second["written"] == 0 and second["duplicates"] == 1


def test_parse_evtx_output_handles_iso_and_legacy_dates():
    iso = json.dumps([{
        "TimeCreated": "2026-11-22T10:00:00Z", "Id": 4624,
        "LevelDisplayName": "Information", "Message": "logon",
        "UserId": "CORP\\olu",
    }])
    legacy = json.dumps({"TimeCreated": "/Date(1730000000000)/", "Id": 1,
                         "Message": "legacy"})
    events = plugin_io.parse_evtx_output(iso, "Security")
    assert len(events) == 1
    assert events[0]["event_id"] == 4624
    assert events[0]["source"] == "plugin:ingest:evtx:Security"
    legacy_events = plugin_io.parse_evtx_output(legacy, "System")
    assert legacy_events and legacy_events[0]["ts"].startswith("2024-")


# ---------------------------------------------------------------------------
# webhook receiver
# ---------------------------------------------------------------------------

def test_handle_webhook_verifies_hmac_and_bounds_records(tmp_path):
    out = tmp_path / "events.jsonl"
    body = json.dumps({"events": [_event(0), _event(1)]}).encode()
    bad = plugin_io.handle_webhook(body, "secret", "sha256=bad", out)
    assert bad["ok"] is False and bad["status"] == 401
    good = plugin_io.handle_webhook(body, "secret", _sign("secret", body), out)
    assert good["ok"] is True and good["written"] == 2
    assert len(_read(out)) == 2


def test_webhook_server_accepts_one_signed_request(tmp_path):
    port = _free_port()
    out = tmp_path / "events.jsonl"
    captured = {}

    def run():
        captured.update(plugin_io.serve_webhook(
            "127.0.0.1", port, "/ingest", "secret", out,
            max_events=5, seconds=5, once=True))

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    body = json.dumps({"events": [_event(0)]}).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/ingest", data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "X-Plasma-Signature": _sign("secret", body)})
    for _ in range(30):
        try:
            with urllib.request.urlopen(request, timeout=1) as response:
                assert response.status == 200
                break
        except OSError:
            time.sleep(0.1)
    thread.join(timeout=6)
    assert captured["requests"] == 1
    assert captured["accepted"] == 1
    assert len(_read(out)) == 1


# ---------------------------------------------------------------------------
# exporters
# ---------------------------------------------------------------------------

class _Collector(BaseHTTPRequestHandler):
    received = []  # noqa: RUF012
    signatures = []  # noqa: RUF012

    def log_message(self, format, *args):
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        self.received.append(body)
        self.signatures.append(self.headers.get("X-Plasma-Signature"))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")


def _collector():
    server = HTTPServer(("127.0.0.1", 0), _Collector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


def test_export_webhook_delivers_batches_with_signature(tmp_path):
    server, port = _collector()
    try:
        _Collector.received, _Collector.signatures = [], []
        out = _write(tmp_path / "events.jsonl", [_event(0), _event(1)])
        result = plugin_io.export_webhook(
            f"http://127.0.0.1:{port}/ingest", out, tmp_path,
            secret="secret", max_events=10, batch_size=1)
        assert result["ok"] is True and result["delivered"] == 2
        assert len(_Collector.received) == 2
        assert _Collector.signatures[0].startswith("sha256=")
    finally:
        server.shutdown()
        server.server_close()


def test_export_webhook_spools_when_the_sink_is_down(tmp_path):
    out = _write(tmp_path / "events.jsonl", [_event(0)])
    port = _free_port()
    result = plugin_io.export_webhook(
        f"http://127.0.0.1:{port}/ingest", out, tmp_path,
        max_events=10, retries=1)
    assert result["ok"] is False
    spool = Path(result["spooled"]["path"])
    assert spool.exists() and len(spool.read_text().splitlines()) == 1
    assert result["spooled"]["lines"] == 1


def test_export_syslog_udp_sends_one_line_per_event(tmp_path):
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(3)
    port = receiver.getsockname()[1]
    out = _write(tmp_path / "events.jsonl", [_event(0), _event(1)])
    result = plugin_io.export_syslog("127.0.0.1", port, "udp", out,
                                    max_events=10)
    assert result["ok"] is True and result["sent"] == 2
    first, _ = receiver.recvfrom(65535)
    second, _ = receiver.recvfrom(65535)
    assert first.startswith(b"<134>1 ")
    assert b"cmd.exe" in first
    assert second
    receiver.close()


def test_export_webhook_rejects_non_http_schemes(tmp_path):
    out = _write(tmp_path / "events.jsonl", [_event(0)])
    result = plugin_io.export_webhook("file:///etc/passwd", out, tmp_path)
    assert result["ok"] is False
    assert "http" in result["error"]
