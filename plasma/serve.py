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
import ssl
import subprocess
import sys
import time
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

from . import __version__, agentstate
from .openapi import SPEC

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 9999
DEFAULT_API_KEY = "plasmaplasma"
DEFAULT_TIMEOUT = 300
DEFAULT_MAX_BODY = 1 << 20          # 1 MiB request body
DEFAULT_MAX_OUTPUT = 8 << 20        # 8 MiB stdout/stderr per call
MAX_ARGV = 64
MAX_ARG_LEN = 4096

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
    "rollback",
    "ring assign",
    "ring promote",
    "whids pull",
    "whids push",
    "whids ensure",
    "whids prune",
    "canary deploy",
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
    if api_key:
        return api_key
    env = os.environ.get("PLASMA_SERVE_API_KEY")
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
    """The leading non-flag tokens, e.g. ['control','policy','set']."""
    parts: list[str] = []
    for token in argv:
        if token.startswith("-"):
            break
        parts.append(token)
        if len(parts) >= 3:
            break
    return " ".join(parts)


def is_mutating(argv: list[str], path: str | None = None) -> bool:
    """True when the command changes host or Plasma state."""
    path = path if path is not None else command_path(argv)
    if "--apply" in argv:
        return True
    for prefix in MUTATING:
        if path == prefix or path.startswith(prefix + " "):
            return True
    return False


def is_long_running(path: str) -> bool:
    for prefix in LONG_RUNNING:
        if path == prefix or path.startswith(prefix + " "):
            return True
    return False


def _validate_argv(argv: list[str]) -> None:
    """Parse the argv with the real CLI parser before running it.

    This catches unknown commands and missing arguments early, and keeps the
    HTTP surface honest: it accepts exactly what the CLI accepts.
    """
    if not isinstance(argv, list) or not argv:
        raise ServeError(400, "argv", "argv must be a non-empty list of strings")
    if len(argv) > MAX_ARGV:
        raise ServeError(400, "argv", f"argv has more than {MAX_ARGV} items")
    for item in argv:
        if not isinstance(item, str):
            raise ServeError(400, "argv", "every argv item must be a string")
        if len(item) > MAX_ARG_LEN:
            raise ServeError(400, "argv", f"an argv item exceeds {MAX_ARG_LEN} characters")

    from .cli import build_parser

    parser = build_parser()
    out, err = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 2
        if code == 0:
            return  # --help / --version
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


def _audit(root, entry: dict) -> None:
    """Append one audit row. Best-effort: never fail the request."""
    try:
        directory = agentstate.ensure(root) / "serve"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "audit.jsonl"
        with (agentstate.lock(directory / ".lock", timeout=5, stale=60),
              path.open("a", encoding="utf-8") as fh):
            fh.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:  # noqa: BLE001, S110 - audit must not break administration
        pass


def _command_tree(parser, path: list[str] | None = None,
                  help_text: str = "") -> list[dict]:
    """Flatten the argparse tree into a list of command paths + options."""
    path = path or []
    options = []
    for action in parser._actions:  # argparse has no public walk
        if not action.option_strings:
            continue
        default = action.default
        if not isinstance(default, (str, int, float, bool, type(None))):
            default = None
        options.append({
            "flags": list(action.option_strings),
            "dest": action.dest,
            "required": bool(getattr(action, "required", False)),
            "default": default,
            "choices": list(action.choices) if getattr(action, "choices", None) else None,
            "help": action.help or "",
        })
    rows = [{"path": path, "help": help_text, "options": options}]
    for action in parser._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        helps = {a.dest: a.help for a in getattr(action, "_choices_actions", [])}
        for name, subparser in action.choices.items():
            if name.startswith("_"):
                continue
            rows.extend(_command_tree(subparser, path + [name], helps.get(name, "") or ""))
    return rows


class _Handler(BaseHTTPRequestHandler):
    server_version = f"plasma-serve/{__version__}"
    protocol_version = "HTTP/1.1"

    # Set by make_server().
    cfg: ClassVar[dict] = {}

    # -- plumbing ---------------------------------------------------------

    def log_message(self, fmt, *args):
        if not self.cfg.get("quiet"):
            sys.stderr.write(f"{self.address_string()} {fmt % args}\n")
            sys.stderr.flush()

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, code: str, message: str) -> None:
        self._send_json(status, {"ok": False, "code": code, "error": message})

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        supplied = ""
        if header.lower().startswith("bearer "):
            supplied = header[7:].strip()
        if not supplied:
            supplied = self.headers.get("X-API-Key", "").strip()
        return bool(supplied) and hmac.compare_digest(supplied, self.cfg["api_key"])

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
        self.wfile.write(body)
        return False

    def _read_json(self) -> dict:
        length = self.headers.get("Content-Length")
        if length is None:
            return {}
        try:
            size = int(length)
        except ValueError as exc:
            raise ServeError(400, "body", "Content-Length is not an integer") from exc
        if size < 0:
            raise ServeError(400, "body", "Content-Length is negative")
        if size > self.cfg["max_body"]:
            raise ServeError(413, "body", "request body is too large")
        raw = self.rfile.read(size)
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
            self.wfile.write(body)
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
            for row in rows:
                row["long_running"] = is_long_running(" ".join(row["path"]))
                row["mutating"] = is_mutating(row["path"], " ".join(row["path"]))
            self._send_json(200, {"ok": True, "version": __version__,
                                  "commands": rows})
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
        _validate_argv(argv)
        path = command_path(argv)
        if is_long_running(path):
            raise ServeError(400, "long_running",
                             f"{path!r} does not return; run it from the CLI")
        if self.cfg["read_only"] and is_mutating(argv, path):
            raise ServeError(403, "read_only",
                             f"{path!r} changes state and this server is read-only")

        env = os.environ.copy()
        env.pop("PLASMA_SERVE_API_KEY", None)
        env["PLASMA_SERVE_CHILD"] = "1"
        started = time.time()
        try:
            proc = subprocess.run(
                _child_command(argv),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.cfg["timeout"],
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            elapsed = round((time.time() - started) * 1000, 1)
            self._audit(argv, path, None, elapsed, "timeout")
            raise ServeError(504, "timeout",
                             f"command exceeded {self.cfg['timeout']}s") from exc
        except OSError as exc:
            elapsed = round((time.time() - started) * 1000, 1)
            self._audit(argv, path, None, elapsed, "spawn_error")
            raise ServeError(500, "spawn", f"cannot start command: {exc}") from exc

        elapsed = round((time.time() - started) * 1000, 1)
        stdout, out_cut = _cap(proc.stdout or "", self.cfg["max_output"])
        stderr, err_cut = _cap(proc.stderr or "", self.cfg["max_output"])
        result = _maybe_json(stdout)
        self._audit(argv, path, proc.returncode, elapsed,
                    "ok" if proc.returncode == 0 else "exit")
        return {
            "ok": proc.returncode == 0,
            "exit_code": proc.returncode,
            "command": path,
            "argv": argv,
            "stdout": stdout,
            "stderr": stderr,
            "result": result,
            "truncated": out_cut or err_cut,
            "duration_ms": elapsed,
        }

    def _audit(self, argv: list[str], path: str, exit_code: int | None,
               duration_ms: float, outcome: str) -> None:
        if not self.cfg["audit"]:
            return
        _audit(self.cfg["root"], {
            "ts": agentstate.now_iso(),
            "remote": self.client_address[0] if self.client_address else None,
            "key_id": self.cfg["key_id"],
            "argv": argv,
            "command": path,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "outcome": outcome,
            "read_only": self.cfg["read_only"],
        })


def make_server(root=None, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                api_key: str | None = None, api_key_file: str | None = None,
                read_only: bool = False, tls_cert: str | None = None,
                tls_key: str | None = None, timeout: int = DEFAULT_TIMEOUT,
                max_body: int = DEFAULT_MAX_BODY,
                max_output: int = DEFAULT_MAX_OUTPUT,
                audit: bool = True, quiet: bool = False):
    """Build (but do not start) the HTTP server. Returns (server, key)."""
    if (tls_cert is None) != (tls_key is None):
        raise ServeError(2, "tls", "TLS needs both --tls-cert and --tls-key")
    key = resolve_api_key(api_key, api_key_file)
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
    server = ThreadingHTTPServer((host, int(port)), Handler)
    server.daemon_threads = True
    if tls_cert and tls_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=tls_cert, keyfile=tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server, key


def serve(root=None, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
          api_key: str | None = None, api_key_file: str | None = None,
          read_only: bool = False, tls_cert: str | None = None,
          tls_key: str | None = None, timeout: int = DEFAULT_TIMEOUT,
          max_body: int = DEFAULT_MAX_BODY, max_output: int = DEFAULT_MAX_OUTPUT,
          audit: bool = True, quiet: bool = False) -> int:
    """Run the HTTP API until interrupted."""
    server, key = make_server(
        root=root, host=host, port=port, api_key=api_key,
        api_key_file=api_key_file, read_only=read_only, tls_cert=tls_cert,
        tls_key=tls_key, timeout=timeout, max_body=max_body,
        max_output=max_output, audit=audit, quiet=quiet,
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
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
