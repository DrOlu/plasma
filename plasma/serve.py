"""HTTP API for the full Plasma CLI.

`plasma serve` exposes the same command surface as the CLI over HTTP so a
jumphost, dashboard or automation can administer a host without WinRM or
SSH. It is deliberately narrow:

* one authenticated endpoint, ``POST /v1/exec``, that takes an argv list;
* the argv is parsed by the real CLI parser before anything runs;
* every command runs in a child process with a hard timeout;
* ``--read-only`` refuses every mutating command;
* every call is written to ``<root>/serve/audit.jsonl``.

The API key is a bearer secret. The default is ``plasmaplasma`` for lab
use; production deployments should pass ``--api-key-file`` or set
``PLASMA_SERVE_API_KEY``.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import io
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from contextlib import redirect_stderr, redirect_stdout
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

from . import __version__, agentstate
from . import help as helpmod
from .lifecycle import SERVE_REQUEST, require
from .openapi import SPEC
from .redact import redact_text

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9999
DEFAULT_API_KEY = "plasmaplasma"
DEFAULT_TIMEOUT = 300
DEFAULT_MAX_BODY = 1 << 20          # 1 MiB request body
DEFAULT_MAX_OUTPUT = 8 << 20        # 8 MiB stdout/stderr per call
MAX_ARGV = 64
MAX_ARG_LEN = 4096
SOCKET_TIMEOUT = 30

# argparse writes to the process-global stdout/stderr. Validation is
# serialized so two concurrent requests cannot capture each other's output.
_VALIDATE_LOCK = threading.Lock()
# Audit appends are serialized in-process before taking the cross-process
# file lock; a lost audit row is a security event, not a cosmetic one.
_AUDIT_LOCK = threading.Lock()
# Keep handler logging off the process-global sys.stderr so validation
# redirects cannot capture another request's log line.
_LOG_STREAM = sys.stderr

# Values after these flags are redacted in the audit log. The flag itself is
# kept so the audit still shows what was asked.
_SENSITIVE_FLAGS = ("--prompt", "--system", "--api-key")

# The routes described by the OpenAPI document. Kept here so a test can
# assert the spec and the server do not drift apart.
API_ROUTES = ("/healthz", "/v1/version", "/v1/commands", "/v1/exec")
DOC_ROUTES = ("/openapi.json", "/docs")

_DOCS_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Plasma HTTP API</title>
<style>
  :root { color-scheme: light; }
  body { margin: 0; font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         color: #141111; background: #fffaf0; }
  header { padding: 28px 32px 18px; border-bottom: 2px solid #141111; background: #ffd440; }
  h1 { margin: 0 0 4px; font-size: 26px; letter-spacing: -0.02em; }
  header p { margin: 0; color: #555552; }
  main { max-width: 980px; margin: 0 auto; padding: 24px 32px 60px; }
  h2 { margin: 28px 0 8px; font-size: 18px; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px;
         background: #f4f0e6; padding: 1px 4px; border-radius: 3px; }
  table { width: 100%; border-collapse: collapse; margin: 10px 0 18px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #d8d2c4; vertical-align: top; }
  th { background: #ffd440; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
  details { margin-top: 18px; }
  summary { cursor: pointer; font-weight: 600; }
  pre { overflow: auto; background: #141111; color: #f4f0e6; padding: 16px; border-radius: 6px;
        font-size: 12px; line-height: 1.45; }
  .note { border-left: 3px solid #0e7490; background: #f4f0e6; padding: 10px 14px; margin: 14px 0; }
</style>
</head>
<body>
<header>
  <h1>Plasma HTTP API</h1>
  <p id="meta">Loading the OpenAPI document…</p>
</header>
<main>
  <div class="note">
    Send <code>Authorization: Bearer &lt;key&gt;</code> or
    <code>X-API-Key: &lt;key&gt;</code>. The machine-readable spec is at
    <a href="/openapi.json"><code>/openapi.json</code></a>.
  </div>
  <div id="app"></div>
</main>
<script>
fetch('/openapi.json').then(function (r) { return r.json(); }).then(function (spec) {
  document.getElementById('meta').textContent =
    spec.info.title + ' · v' + spec.info.version + ' · OpenAPI ' + spec.openapi;
  var app = document.getElementById('app');
  var h2 = document.createElement('h2');
  h2.textContent = 'Endpoints';
  app.appendChild(h2);
  var table = document.createElement('table');
  table.innerHTML = '<thead><tr><th>Method</th><th>Path</th><th>Summary</th></tr></thead><tbody></tbody>';
  var tbody = table.querySelector('tbody');
  Object.keys(spec.paths).forEach(function (path) {
    Object.keys(spec.paths[path]).forEach(function (method) {
      var op = spec.paths[path][method];
      var tr = document.createElement('tr');
      tr.innerHTML = '<td><code>' + method.toUpperCase() + '</code></td>' +
                     '<td><code>' + path + '</code></td>' +
                     '<td>' + (op.summary || '') + '</td>';
      tbody.appendChild(tr);
    });
  });
  app.appendChild(table);
  var details = document.createElement('details');
  details.innerHTML = '<summary>Raw OpenAPI document</summary><pre></pre>';
  details.querySelector('pre').textContent = JSON.stringify(spec, null, 2);
  app.appendChild(details);
}).catch(function (err) {
  document.getElementById('meta').textContent = 'Could not load /openapi.json: ' + err;
});
</script>
</body>
</html>
"""

# Commands that never return (or are internal) and must not be run through
# the HTTP surface. A caller that needs them can use the CLI directly.
LONG_RUNNING = (
    "serve",
    "mcp serve",
    "watch loop",
    "canary serve",
    "_bridge",
)

# Commands that change host or Plasma state. Refused when --read-only is set.
# Prefix matching is on the command path (first non-flag tokens).
MUTATING = (
    "install",
    "bundle build",
    "manifest create",
    "actuate apply",
    "actuate undo",
    "playbook apply",
    "playbook undo",
    "prevent applocker",
    "prevent egress",
    "prevent asr",
    "prevent lsa",
    "prevent rollback",
    "enforce run",
    "enforce approve",
    "control policy set",
    "control approvals approve",
    "control approvals deny",
    "control killswitch on",
    "control killswitch off",
    "control tenants add",
    "control tenants remove",
    "update apply",
    "update auto",
    "protect arm",
    "protect disarm",
    "sigma convert",
    "deep persistence",
    "rollback",
    "ring assign",
    "ring promote",
    "whids pull",
    "whids push",
    "whids ensure",
    "whids prune",
    "canary deploy",
    "memory scan",
    "memory triage",
    "case open",
    "case add",
    "case note",
    "case report",
    "case seal",
    "canary token create",
    "canary token remove",
    "canary collect",
    "canary sysmon",
    "intercept rules add",
    "intercept rules remove",
    "intercept evaluate",
    "intercept apply",
    "intercept protect-canary",
    "intercept rollback",
    "fim baseline",
    "store rotate",
    "store compact",
    "store redact",
    "identity pull",
    "identity schedule",
    "identity unschedule",
    "notify test",
    "trace run",
    "trace provision",
    "tap run",
    "tap collect",
    "fleet pull",
    "fleet correlate",
    "fleet report",
    "fleet scan",
    "evidence export",
    "assurance sbom",
    "assurance safety-case",
    "assurance support-bundle",
    "eval run",
    "drift record",
    "watch once",
)


class ServeError(Exception):
    """A request-level error with an HTTP status and a stable code."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def resolve_api_key(api_key: str | None = None,
                    api_key_file: str | None = None) -> str:
    """Resolve the bearer key: explicit, env, file, then the lab default."""
    if api_key is not None:
        text = str(api_key).strip()
        if not text:
            raise ServeError(2, "api_key", "an explicitly supplied API key is empty")
        return text
    env = (os.environ.get("PLASMA_SERVE_API_KEY") or "").strip()
    if env:
        return env
    if api_key_file:
        path = Path(api_key_file)
        try:
            text = path.read_text(encoding="utf-8-sig")
        except OSError as exc:
            raise ServeError(2, "key_file", f"cannot read API key file: {exc}") from exc
        for line in text.splitlines():
            line = line.strip()
            if line:
                return line
        raise ServeError(2, "key_file", "API key file is empty")
    return DEFAULT_API_KEY


def key_id(key: str) -> str:
    """A short, non-reversible identifier for audit rows."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


def command_path(argv: list[str]) -> str:
    """Legacy best-effort path. Prefer ``_parsed_path`` after parsing."""
    parts: list[str] = []
    for token in argv:
        if token.startswith("-"):
            break
        parts.append(token)
        if len(parts) >= 3:
            break
    return " ".join(parts)


@lru_cache(maxsize=1)
def _func_paths() -> dict:
    """Map each command handler back to its canonical parser path."""
    from .cli import build_parser

    parser = build_parser()
    paths: dict = {}

    def walk(node, path=()):
        func = getattr(node, "_defaults", {}).get("func")
        if func is not None and path:
            paths.setdefault(func, " ".join(path))
        for action in node._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, child in action.choices.items():
                    walk(child, path + (name,))

    walk(parser)
    return paths


def _parsed_path(args) -> str:
    func = getattr(args, "func", None)
    return _func_paths().get(func, "") if func is not None else ""


def _argv_value(argv: list[str], name: str) -> str | None:
    for index, token in enumerate(argv):
        if token == name and index + 1 < len(argv):
            return argv[index + 1]
        if token.startswith(name + "="):
            return token.split("=", 1)[1]
    return None


def is_mutating(argv: list[str], path: str | None = None,
                parsed=None) -> bool:
    """True when the command changes host or Plasma state.

    The path must come from the parsed namespace (``_parsed_path``), not
    string scanning: options may precede the command name and a leading
    ``--`` is still a valid argv.
    """
    path = path if path is not None else command_path(argv)
    if "--apply" in argv or "--apply-prevention" in argv:
        return True
    # Read-only previews of commands that otherwise write.
    if path == "update auto" and "--check-only" in argv:
        return False
    if path == "sigma convert" and "--dry-run" in argv:
        return False
    if path == "deep persistence" and not _argv_value(argv, "--json-out"):
        return False
    if path == "intercept evaluate" and not _argv_value(argv, "--out"):
        return False
    if path == "query" and not _argv_value(argv, "--out"):
        return False
    if path == "manifest" and parsed is not None:
        return getattr(parsed, "action", "") == "create"
    for prefix in MUTATING:
        if path == prefix or path.startswith(prefix + " "):
            return True
    return False


def is_long_running(path: str) -> bool:
    for prefix in LONG_RUNNING:
        if path == prefix or path.startswith(prefix + " "):
            return True
    return False


def _validate_argv(argv: list[str]):
    """Parse the argv with the real CLI parser before running it.

    Returns the parsed namespace so the caller can derive the canonical
    command path. This catches unknown commands and missing arguments early,
    and keeps the HTTP surface honest: it accepts exactly what the CLI
    accepts.
    """
    if not isinstance(argv, list) or not argv:
        raise ServeError(400, "argv", "argv must be a non-empty list of strings")
    if len(argv) > MAX_ARGV:
        raise ServeError(400, "argv", f"argv has more than {MAX_ARGV} items")
    if argv[0] == "--":
        raise ServeError(400, "argv",
                         "a leading '--' is not accepted by the HTTP API")
    for item in argv:
        if not isinstance(item, str):
            raise ServeError(400, "argv", "every argv item must be a string")
        if len(item) > MAX_ARG_LEN:
            raise ServeError(400, "argv", f"an argv item exceeds {MAX_ARG_LEN} characters")

    from .cli import build_parser

    parser = build_parser()
    out, err = io.StringIO(), io.StringIO()
    try:
        with _VALIDATE_LOCK, redirect_stdout(out), redirect_stderr(err):
            return parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 2
        if code == 0:
            return None  # --help / --version
        message = err.getvalue().strip() or out.getvalue().strip() or "invalid arguments"
        raise ServeError(400, "argv", message) from exc


def _child_command(argv: list[str]) -> list[str]:
    """The command that runs one CLI invocation in a separate process."""
    if getattr(sys, "frozen", False):
        return [sys.executable, *argv]
    return [sys.executable, "-m", "plasma.cli", *argv]


def _maybe_json(text: str):
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _cap(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[:limit], True


def _is_sensitive_flag(token: str) -> bool:
    name = token.split("=", 1)[0]
    return any(name == flag or (len(name) >= 5 and flag.startswith(name))
               for flag in _SENSITIVE_FLAGS)


def _audit_argv(argv: list[str]) -> list[str]:
    """Redact secret-bearing values before they reach the audit log."""
    out: list[str] = []
    redact_next = False
    for item in argv:
        if redact_next:
            out.append("<redacted>")
            redact_next = False
            continue
        if _is_sensitive_flag(item):
            if "=" in item:
                out.append(item.split("=", 1)[0] + "=<redacted>")
            else:
                out.append(item)
                redact_next = True
            continue
        out.append(redact_text(item))
    return out


def _audit(root, entry: dict) -> bool:
    """Append one audit row. Returns False when the row could not be written."""
    try:
        directory = agentstate.ensure(root) / "serve"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "audit.jsonl"
        with (_AUDIT_LOCK,
              agentstate.lock(directory / ".lock", timeout=30, stale=60),
              path.open("a", encoding="utf-8") as fh):
            fh.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return True
    except Exception:  # noqa: BLE001 - audit must not break administration
        return False


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill a child and its descendants after a timeout."""
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            capture_output=True, check=False,
        )
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except OSError:
            pass


def _read_limited(stream, limit: int) -> tuple[str, bool]:
    """Read a pipe with a hard byte budget; discard anything beyond it."""
    chunks: list[str] = []
    used = 0
    truncated = False
    while True:
        chunk = stream.read(65536)
        if not chunk:
            break
        size = len(chunk.encode("utf-8", "replace"))
        if used + size <= limit:
            chunks.append(chunk)
            used += size
        else:
            keep = max(0, limit - used)
            if keep:
                chunks.append(chunk[:keep])
            used = limit
            truncated = True
    return "".join(chunks), truncated


def _run_child(cmd: list[str], env: dict, timeout: int,
               max_output: int) -> tuple[int, str, str, bool]:
    """Run one CLI invocation with a hard timeout, tree kill and byte cap.

    ``subprocess.run(timeout=...)`` kills only the direct child. Plasma
    commands spawn PowerShell, so a timeout must take the whole tree down.
    Output is read incrementally so a runaway command cannot exhaust the
    server's memory before the cap is applied.
    """
    kwargs: dict = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        **kwargs,
    )
    result: dict = {}

    def collect(name, pipe):
        result[name] = _read_limited(pipe, max_output)

    out_thread = threading.Thread(target=collect, args=("out", proc.stdout),
                                  daemon=True)
    err_thread = threading.Thread(target=collect, args=("err", proc.stderr),
                                  daemon=True)
    out_thread.start()
    err_thread.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except OSError:
                pass
        raise
    finally:
        out_thread.join(timeout=5)
        err_thread.join(timeout=5)
        for stream in (proc.stdout, proc.stderr):
            try:
                stream.close()
            except (AttributeError, OSError):
                pass
    out, out_cut = result.get("out", ("", False))
    err, err_cut = result.get("err", ("", False))
    return proc.returncode, out, err, out_cut or err_cut


def _command_tree(parser, path: list[str] | None = None,
                  help_text: str = "") -> list[dict]:
    """Flatten the argparse tree into command paths, options and positionals."""
    path = path or []
    options = []
    positionals = []
    for action in parser._actions:  # argparse has no public walk
        if isinstance(action, argparse._SubParsersAction):
            continue
        if action.option_strings:
            default = action.default
            if not isinstance(default, (str, int, float, bool, type(None))):
                default = None
            options.append({
                "flags": list(action.option_strings),
                "dest": action.dest,
                "required": bool(getattr(action, "required", False)),
                "type": getattr(action.type, "__name__", None) if action.type else None,
                "default": default,
                "choices": list(action.choices) if getattr(action, "choices", None) else None,
                "help": action.help or "",
            })
            continue
        if action.dest in ("help",):
            continue
        positionals.append({
            "name": action.dest,
            "required": bool(getattr(action, "required", False)),
            "type": getattr(action.type, "__name__", None) if action.type else None,
            "nargs": None if action.nargs is None else str(action.nargs),
            "choices": list(action.choices) if getattr(action, "choices", None) else None,
            "help": action.help or "",
        })
    spec = helpmod.COMMANDS.get(" ".join(path), {})
    rows = [{
        "path": path,
        "help": help_text,
        "summary": spec.get("summary", ""),
        "description": spec.get("description", ""),
        "examples": [
            {"title": title, "command": command}
            for title, command in spec.get("examples", [])
        ],
        "safety": spec.get("safety", ""),
        "output": spec.get("output", ""),
        "see_also": spec.get("see_also", []),
        "notes": spec.get("notes", []),
        "options": options,
        "positionals": positionals,
    }]
    for action in parser._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        helps = {a.dest: a.help for a in getattr(action, "_choices_actions", [])}
        for name, subparser in action.choices.items():
            if name.startswith("_"):
                continue
            rows.extend(_command_tree(subparser, path + [name], helps.get(name, "") or ""))
    return rows


class _BoundedServer(ThreadingHTTPServer):
    """Cap concurrent handlers so unauthenticated slow clients cannot grow
    the thread pool without bound. The queue is deliberately small."""

    daemon_threads = True
    request_queue_size = 64

    def __init__(self, *args, max_connections: int = 64, **kwargs):
        self._slots = threading.BoundedSemaphore(max(1, int(max_connections)))
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        self._slots.acquire()
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def shutdown_request(self, request):
        try:
            super().shutdown_request(request)
        finally:
            self._slots.release()


class _Handler(BaseHTTPRequestHandler):
    server_version = f"plasma-serve/{__version__}"
    protocol_version = "HTTP/1.1"
    timeout = SOCKET_TIMEOUT

    # Set by make_server().
    cfg: ClassVar[dict] = {}

    # -- plumbing ---------------------------------------------------------

    def setup(self):
        # TLS handshakes must run in the connection thread, not the accept
        # loop. A client that connects and sends nothing would otherwise
        # freeze every subsequent request.
        if isinstance(self.request, ssl.SSLSocket):
            self.request.settimeout(SOCKET_TIMEOUT)
            self.request.do_handshake()
        super().setup()

    def log_message(self, fmt, *args):
        if not self.cfg.get("quiet"):
            _LOG_STREAM.write(f"{self.address_string()} {fmt % args}\n")
            _LOG_STREAM.flush()

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        # One response per connection. This closes the request-smuggling
        # window when an error path cannot consume the request body.
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _error(self, status: int, code: str, message: str) -> None:
        self._send_json(status, {"ok": False, "code": code, "error": message})

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        supplied = ""
        if header.lower().startswith("bearer "):
            supplied = header[7:].strip()
        if not supplied:
            supplied = self.headers.get("X-API-Key", "").strip()
        if not supplied:
            return False
        # compare_digest on str rejects non-ASCII; compare bytes instead.
        return hmac.compare_digest(supplied.encode("utf-8"),
                                   self.cfg["api_key"].encode("utf-8"))

    def _require_auth(self) -> bool:
        if self._authorized():
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Bearer realm="plasma"')
        self.send_header("Content-Type", "application/json; charset=utf-8")
        body = json.dumps({"ok": False, "code": "unauthorized",
                           "error": "a valid API key is required"}).encode("utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        return False

    def _read_json(self) -> dict:
        lengths = self.headers.get_all("Content-Length") or []
        transfer = (self.headers.get("Transfer-Encoding") or "").strip().lower()
        if transfer:
            raise ServeError(400, "body",
                             "Transfer-Encoding is not supported; send Content-Length")
        if len(lengths) > 1:
            raise ServeError(400, "body",
                             "multiple Content-Length headers are not allowed")
        length = lengths[0] if lengths else None
        if length is None:
            raise ServeError(411, "length_required", "Content-Length is required")
        try:
            size = int(length)
        except ValueError as exc:
            raise ServeError(400, "body", "Content-Length is not an integer") from exc
        if size < 0:
            raise ServeError(400, "body", "Content-Length is negative")
        if size > self.cfg["max_body"]:
            raise ServeError(413, "body", "request body is too large")
        try:
            raw = self.rfile.read(size)
        except socket.timeout as exc:
            raise ServeError(408, "timeout", "request body read timed out") from exc
        except (ConnectionResetError, BrokenPipeError) as exc:
            raise ServeError(400, "body",
                             "client disconnected while sending the body") from exc
        if not raw:
            return {}
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ServeError(400, "body", "request body is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise ServeError(400, "body", "request body must be a JSON object")
        return payload

    # -- routes -----------------------------------------------------------

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self._send_json(200, {"ok": True, "product": "Plasma",
                                  "version": __version__})
            return
        if path == "/openapi.json":
            self._send_json(200, SPEC)
            return
        if path == "/docs":
            body = _DOCS_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        if not self._require_auth():
            return
        if path == "/":
            self._send_json(200, {
                "ok": True,
                "product": "Plasma",
                "version": __version__,
                "endpoints": {
                    "GET /healthz": "liveness (no auth)",
                    "GET /openapi.json": "OpenAPI 3.1 description (no auth)",
                    "GET /docs": "human-readable API docs (no auth)",
                    "GET /v1/version": "version and runtime",
                    "GET /v1/commands": "the full CLI command tree",
                    "POST /v1/exec": "run one CLI argv",
                },
                "read_only": self.cfg["read_only"],
            })
            return
        if path == "/v1/version":
            self._send_json(200, {
                "ok": True,
                "product": "Plasma",
                "version": __version__,
                "python": sys.version.split()[0],
                "platform": sys.platform,
                "frozen": bool(getattr(sys, "frozen", False)),
                "read_only": self.cfg["read_only"],
            })
            return
        if path == "/v1/commands":
            from .cli import build_parser
            rows = _command_tree(build_parser())
            root = rows[0]
            root["long_running"] = False
            root["mutating"] = False
            commands = rows[1:]
            for row in commands:
                row["long_running"] = is_long_running(" ".join(row["path"]))
                row["mutating"] = is_mutating(row["path"], " ".join(row["path"]))
            self._send_json(200, {"ok": True, "version": __version__,
                                  "root": root, "commands": commands})
            return
        self._error(404, "not_found", f"no route for GET {path}")

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path != "/v1/exec":
            self._error(404, "not_found", f"no route for POST {path}")
            return
        if not self._require_auth():
            return
        try:
            payload = self._read_json()
            argv = payload.get("argv")
            if argv is None and payload.get("command"):
                command = payload["command"]
                extra = payload.get("args") or []
                if isinstance(command, str):
                    command = [command]
                if not isinstance(command, list) or not isinstance(extra, list):
                    raise ServeError(400, "argv", "command and args must be lists")
                argv = command + extra
            if not isinstance(argv, list):
                raise ServeError(400, "argv", "argv must be a list of strings")
            result = self._exec(argv)
            self._send_json(200, result)
        except ServeError as exc:
            self._error(exc.status, exc.code, exc.message)
        except Exception as exc:  # noqa: BLE001 - errors are data
            self._error(500, "internal", f"{type(exc).__name__}: {exc}"[:300])

    def do_PUT(self):
        self._error(405, "method", "only GET and POST are supported")

    do_DELETE = do_PUT
    do_PATCH = do_PUT

    # -- execution --------------------------------------------------------

    def _exec(self, argv: list[str]) -> dict:
        state = "received"

        def move(target: str) -> None:
            nonlocal state
            require(SERVE_REQUEST, state, target)
            state = target

        try:
            parsed = _validate_argv(argv)
        except ServeError:
            move("rejected")
            raise
        move("validated")
        path = _parsed_path(parsed) if parsed is not None else command_path(argv)
        if is_long_running(path):
            move("rejected")
            raise ServeError(400, "long_running",
                             f"{path!r} does not return; run it from the CLI")
        mutating = is_mutating(argv, path, parsed)
        if self.cfg["read_only"] and mutating:
            move("rejected")
            raise ServeError(403, "read_only",
                             f"{path!r} changes state and this server is read-only")
        # A mutation that cannot be audited must not run.
        if mutating and self.cfg["audit"] and not self._audit(
                argv, path, None, 0.0, "started"):
            move("failed")
            raise ServeError(500, "audit",
                             "cannot write the audit row; refusing to mutate")

        env = os.environ.copy()
        env.pop("PLASMA_SERVE_API_KEY", None)
        env["PLASMA_SERVE_CHILD"] = "1"
        if self.cfg.get("root"):
            env["PLASMA_ROOT"] = str(self.cfg["root"])
        # The child's stdout is a pipe, not a console. Force UTF-8 so a
        # non-ASCII command output is not mangled by the Windows code page.
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        started = time.time()
        move("running")
        try:
            returncode, stdout, stderr, child_cut = _run_child(
                _child_command(argv), env, self.cfg["timeout"],
                self.cfg["max_output"])
        except subprocess.TimeoutExpired as exc:
            move("timed_out")
            elapsed = round((time.time() - started) * 1000, 1)
            self._audit(argv, path, None, elapsed, "timeout")
            raise ServeError(504, "timeout",
                             f"command exceeded {self.cfg['timeout']}s") from exc
        except OSError as exc:
            move("failed")
            elapsed = round((time.time() - started) * 1000, 1)
            self._audit(argv, path, None, elapsed, "spawn_error")
            raise ServeError(500, "spawn", f"cannot start command: {exc}") from exc

        move("completed")
        elapsed = round((time.time() - started) * 1000, 1)
        stdout, out_cut = _cap(stdout, self.cfg["max_output"])
        stderr, err_cut = _cap(stderr, self.cfg["max_output"])
        result = _maybe_json(stdout)
        self._audit(argv, path, returncode, elapsed,
                    "ok" if returncode == 0 else "exit")
        return {
            "ok": returncode == 0,
            "exit_code": returncode,
            "command": path,
            "argv": argv,
            "stdout": stdout,
            "stderr": stderr,
            "result": result,
            "truncated": child_cut or out_cut or err_cut,
            "duration_ms": elapsed,
        }

    def _audit(self, argv: list[str], path: str, exit_code: int | None,
               duration_ms: float, outcome: str) -> None:
        if not self.cfg["audit"]:
            return
        ok = _audit(self.cfg["root"], {
            "ts": agentstate.now_iso(),
            "remote": self.client_address[0] if self.client_address else None,
            "key_id": self.cfg["key_id"],
            "argv": _audit_argv(argv),
            "command": path,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "outcome": outcome,
            "read_only": self.cfg["read_only"],
        })
        if not ok and not self.cfg.get("quiet"):
            sys.stderr.write("plasma serve: audit write failed\n")
            sys.stderr.flush()


def make_server(root=None, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                api_key: str | None = None, api_key_file: str | None = None,
                read_only: bool = False, tls_cert: str | None = None,
                tls_key: str | None = None, timeout: int = DEFAULT_TIMEOUT,
                max_body: int = DEFAULT_MAX_BODY,
                max_output: int = DEFAULT_MAX_OUTPUT,
                audit: bool = True, quiet: bool = False,
                allow_insecure_default_key: bool = False):
    """Build (but do not start) the HTTP server. Returns (server, key)."""
    if (tls_cert is None) != (tls_key is None):
        raise ServeError(2, "tls", "TLS needs both --tls-cert and --tls-key")
    key = resolve_api_key(api_key, api_key_file)
    if key == DEFAULT_API_KEY and not allow_insecure_default_key \
            and host not in ("127.0.0.1", "localhost", "::1"):
        raise ServeError(
            2, "insecure_key",
            "refusing to expose the default API key on a non-loopback "
            "address; use --api-key-file, PLASMA_SERVE_API_KEY, or "
            "--allow-insecure-default-key for a controlled lab")
    cfg = {
        "root": root,
        "api_key": key,
        "key_id": key_id(key),
        "read_only": bool(read_only),
        "timeout": max(1, int(timeout)),
        "max_body": max(1, int(max_body)),
        "max_output": max(1, int(max_output)),
        "audit": bool(audit),
        "quiet": bool(quiet),
    }

    class Handler(_Handler):
        pass

    Handler.cfg = cfg
    server = _BoundedServer((host, int(port)), Handler)
    if tls_cert and tls_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=tls_cert, keyfile=tls_key)
        # do_handshake_on_connect=False: _Handler.setup() performs the
        # handshake in the per-connection thread under a timeout.
        server.socket = context.wrap_socket(
            server.socket, server_side=True, do_handshake_on_connect=False)
    return server, key


def serve(root=None, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
          api_key: str | None = None, api_key_file: str | None = None,
          read_only: bool = False, tls_cert: str | None = None,
          tls_key: str | None = None, timeout: int = DEFAULT_TIMEOUT,
          max_body: int = DEFAULT_MAX_BODY, max_output: int = DEFAULT_MAX_OUTPUT,
          audit: bool = True, quiet: bool = False,
          allow_insecure_default_key: bool = False) -> int:
    """Run the HTTP API until interrupted."""
    server, key = make_server(
        root=root, host=host, port=port, api_key=api_key,
        api_key_file=api_key_file, read_only=read_only, tls_cert=tls_cert,
        tls_key=tls_key, timeout=timeout, max_body=max_body,
        max_output=max_output, audit=audit, quiet=quiet,
        allow_insecure_default_key=allow_insecure_default_key,
    )
    bound_host, bound_port = server.server_address[:2]
    scheme = "https" if tls_cert else "http"
    print(json.dumps({
        "ok": True,
        "product": "Plasma",
        "version": __version__,
        "listening": f"{scheme}://{bound_host}:{bound_port}",
        "auth": "api-key",
        "read_only": bool(read_only),
        "audit": bool(audit),
    }, indent=2), flush=True)
    if key == DEFAULT_API_KEY and bound_host not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: plasma serve is using the default API key on a "
              "non-loopback address. Set --api-key-file or "
              "PLASMA_SERVE_API_KEY before exposing this port.",
              file=sys.stderr, flush=True)
    previous_term = None

    def _terminate(_signum, _frame):
        # shutdown() must run outside the serve_forever thread.
        threading.Thread(target=server.shutdown, daemon=True).start()

    try:
        previous_term = signal.signal(signal.SIGTERM, _terminate)
    except (ValueError, OSError):
        previous_term = None
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if previous_term is not None:
            try:
                signal.signal(signal.SIGTERM, previous_term)
            except (ValueError, OSError):
                pass
        server.server_close()
    return 0
