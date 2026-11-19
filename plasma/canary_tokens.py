"""Native Plasma canary tokens: DNS tripwires, local HTTP callbacks, files.

A canary token is a unique artifact whose only purpose is to be used.  This
module keeps the whole loop local:

* ``dns``  — a unique hostname.  A query is observed in Sysmon EID 22 (or
  any normalized event that carries ``dns_query``) and becomes a score-8
  canary event.  No callback server and no cloud dependency.
* ``http`` — a unique URL served by ``plasma canary serve`` on a management
  host.  The artifact is a Windows ``.url`` shortcut; the server records the
  hit and writes JSONL.  No Docker, no external service.
* ``file`` — the existing hash-verified decoys in :mod:`plasma.canary`.

The registry is a local JSON manifest.  Hits are appended to the normal
Plasma event store as ``source="canary"`` alert rows, so ``watch``, ``fleet``
and the response policy see them without a second data path.
"""

from __future__ import annotations

import hashlib
import http.server
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import agentstate, redact

TOKENS_FILE = "canary-tokens.json"
HITS_FILE = "canary-hits.jsonl"
DNS_STATE = "canary-dns-state.json"
HTTP_STATE = "canary-http-state.json"
SERVER_STATE = "canary-http-server.json"

EVENT_ID = 9001
EVENT_SCORE = 0.8
MAX_SEEN = 2000
TOKEN_RE = re.compile(r"^[a-f0-9]{24}$")
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

URL_NAMES = [
    "Intranet_Portal.url",
    "Benefits_2026.url",
    "Shared_Assets.url",
    "Travel_Booking.url",
    "Supplier_Portal.url",
    "HR_Services.url",
]

_GIF = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!"
    b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00"
    b"\x00\x02\x02D\x01\x00;"
)

_PS_SYSMON = r"""
$ErrorActionPreference = 'Stop'
$since = (Get-Date).AddMinutes(-{since_minutes})
try {{
  $ev = Get-WinEvent -FilterHashtable @{{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=22; StartTime=$since }} -MaxEvents {max_events} -ErrorAction Stop
}} catch {{
  [pscustomobject]@{{ events = @(); error = $_.Exception.Message }} |
    ConvertTo-Json -Depth 5 -Compress
  exit 0
}}
$rows = @()
foreach ($e in $ev) {{
  $x = [xml]$e.ToXml(); $d = @{{}}
  foreach ($p in $x.Event.EventData.Data) {{ if ($p.Name) {{ $d[$p.Name] = $p.'#text' }} }}
  $rows += [pscustomobject]@{{
    ts = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    dns_query = $d['QueryName']
    query_status = $d['QueryStatus']
    query_results = $d['QueryResults']
    process = $d['Image']
    pid = $d['ProcessId']
    user = $d['User']
  }}
}}
[pscustomobject]@{{ events = @($rows); error = $null }} |
  ConvertTo-Json -Depth 5 -Compress
"""


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _tokens_path(root) -> Path:
    return Path(root) / TOKENS_FILE


def _hits_path(root) -> Path:
    return Path(root) / HITS_FILE


def _load(root) -> dict:
    path = _tokens_path(root)
    if not path.exists():
        return {"tokens": []}
    try:
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"canary token registry unreadable: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("tokens"), list):
        raise ValueError("canary token registry has no 'tokens' array")
    return doc


def _save(root, doc: dict) -> None:
    doc["updated_at"] = _now()
    agentstate.write_json(_tokens_path(root), doc)


def _new_id(doc: dict) -> str:
    existing = {str(t.get("id") or "") for t in doc.get("tokens", [])}
    for _ in range(32):
        token_id = secrets.token_hex(12)
        if token_id not in existing:
            return token_id
    raise ValueError("could not allocate a unique token id")


def validate_domain(domain) -> str:
    """Return a normalized DNS suffix, or raise ValueError.

    Tokens are a subdomain of this suffix (``<id>.assets.internal``), so the
    suffix must be a real hostname shape.  No scheme, no path, no wildcard.
    """
    text = str(domain or "").strip().rstrip(".").lower()
    if not text or len(text) > 253:
        raise ValueError("DNS domain must be 1..253 characters")
    labels = text.split(".")
    if len(labels) < 2:
        raise ValueError("DNS domain must contain at least two labels")
    for label in labels:
        if not label or len(label) > 63 or not DOMAIN_LABEL_RE.match(label):
            raise ValueError(f"invalid DNS label: {label!r}")
    return text


def validate_base_url(url) -> str:
    """Validate an HTTP(S) token base URL and return it without a trailing /."""
    text = str(url or "").strip()
    if not text:
        raise ValueError("HTTP token needs --base-url or canary.http_base_url")
    parts = urlsplit(text)
    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError("token base URL must use http:// or https://")
    if not parts.netloc or parts.username or parts.password:
        raise ValueError("token base URL must have a host and no credentials")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("token base URL has an invalid port") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("token base URL port must be 1..65535")
    if parts.query or parts.fragment:
        raise ValueError("token base URL must not contain a query or fragment")
    if parts.path not in ("", "/"):
        raise ValueError("token base URL must not include a path; "
                         "the token path is /t/<id>")
    return text.rstrip("/")


def _artifact_path(root, out, name, default_suffix=".url") -> Path:
    root = Path(root)
    filename = name or secrets.choice(URL_NAMES)
    if out:
        candidate = Path(out)
        if candidate.exists() and candidate.is_dir():
            return candidate / _safe_filename(filename, default_suffix)
        # A missing path without a filename suffix is treated as a directory
        # so `--out C:\Shares\Tokens` does the obvious thing.
        if not candidate.suffix:
            return candidate / _safe_filename(filename, default_suffix)
        return candidate
    return root / "canary-artifacts" / _safe_filename(filename, default_suffix)


def _safe_filename(name: str, suffix: str) -> str:
    text = str(name or "").strip()
    if not text or Path(text).name != text or "/" in text or "\\" in text:
        raise ValueError(f"artifact name must be a plain filename: {name!r}")
    if suffix and not text.lower().endswith(suffix):
        text += suffix
    return text


def _write_url_artifact(path: Path, url: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Windows InternetShortcut files are INI-like and tolerate CRLF best.
    path.write_text(
        "[InternetShortcut]\r\n"
        f"URL={url}\r\n",
        encoding="utf-8",
        newline="",
    )


def create(root, kind: str, domain=None, base_url=None, out=None,
           name=None, label=None) -> dict:
    """Create one DNS or HTTP canary token and persist its registry entry."""
    root = Path(root)
    kind = str(kind or "").lower()
    if kind not in ("dns", "http"):
        raise ValueError("token kind must be 'dns' or 'http'")
    doc = _load(root)
    token_id = _new_id(doc)
    token = {
        "id": token_id,
        "kind": kind,
        "created_at": _now(),
        "label": str(label)[:120] if label else None,
        "hits": 0,
    }
    if kind == "dns":
        suffix = validate_domain(domain)
        fqdn = f"{token_id}.{suffix}"
        token.update({"domain": suffix, "fqdn": fqdn})
        if out:
            path = Path(out)
            if (path.exists() and path.is_dir()) or not path.suffix:
                path = path / _safe_filename(name or f"{token_id}.txt", ".txt")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(fqdn + "\n", encoding="utf-8")
            token["artifact"] = str(path.resolve())
    else:
        base = validate_base_url(base_url)
        url = f"{base}/t/{token_id}"
        token.update({"base_url": base, "url": url})
        path = _artifact_path(root, out, name)
        _write_url_artifact(path, url)
        token["artifact"] = str(path.resolve())
    doc.setdefault("tokens", []).append(token)
    _save(root, doc)
    return token


def list_tokens(root) -> dict:
    doc = _load(root)
    tokens = sorted(doc.get("tokens", []), key=lambda t: str(t.get("created_at") or ""))
    return {"count": len(tokens), "tokens": tokens}


def remove(root, token_id: str, delete_artifact: bool = False) -> dict:
    root = Path(root)
    doc = _load(root)
    token = next((t for t in doc.get("tokens", []) if t.get("id") == token_id), None)
    if token is None:
        return {"error": f"no token {token_id}"}
    doc["tokens"] = [t for t in doc.get("tokens", []) if t.get("id") != token_id]
    _save(root, doc)
    artifact = token.get("artifact")
    removed = False
    if delete_artifact and artifact:
        path = Path(artifact)
        try:
            path.resolve().relative_to(root.resolve())
            if path.exists() and path.is_file():
                path.unlink()
                removed = True
        except (OSError, ValueError):
            pass
    return {"removed": token_id, "artifact_removed": removed,
            "artifact": artifact}


def dns_tokens(root) -> list[dict]:
    return [t for t in _load(root).get("tokens", []) if t.get("kind") == "dns"]


def http_tokens(root) -> list[dict]:
    return [t for t in _load(root).get("tokens", []) if t.get("kind") == "http"]


def dns_domains(root) -> list[str]:
    return sorted({str(t.get("domain")) for t in dns_tokens(root)
                   if t.get("domain")})


def status(root) -> dict:
    doc = _load(root)
    tokens = doc.get("tokens", [])
    by_kind: dict[str, int] = {}
    missing = []
    for token in tokens:
        by_kind[token.get("kind", "?")] = by_kind.get(token.get("kind", "?"), 0) + 1
        artifact = token.get("artifact")
        if artifact and not Path(artifact).exists():
            missing.append({"id": token.get("id"), "artifact": artifact})
    return {
        "registry": str(_tokens_path(root)),
        "tokens": len(tokens),
        "by_kind": by_kind,
        "missing_artifacts": missing,
        "dns_domains": dns_domains(root),
        "last_hit": last_hit(root),
    }


def last_hit(root):
    path = _hits_path(root)
    if not path.exists():
        return None
    last = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip().startswith("{"):
            try:
                last = json.loads(line)
            except json.JSONDecodeError:
                continue
    return last


# ---------------------------------------------------------------------------
# event normalization
# ---------------------------------------------------------------------------

def _base_name(value):
    if not value:
        return None
    return str(value).replace("\\", "/").rsplit("/", 1)[-1][:260]


def _safe_pid(value):
    if value in (None, "", "-"):
        return None
    try:
        pid = int(str(value), 0)
    except (TypeError, ValueError):
        return None
    return pid if 0 <= pid <= 2_147_483_647 else None


def _safe_ip(value):
    if not value:
        return None
    text = str(value).strip()
    try:
        ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None
    # PlasmaEvent.dest_ip starts with an alphanumeric character; "::1" does
    # not, so leave it out rather than write a row the bridge will reject.
    return text if text[0].isalnum() else None


def _canary_event(alert_id: str, description: str, *, host: str,
                  ts: str | None = None, **fields) -> dict:
    event = {
        "ts": ts or _now(),
        "host": host or socket.gethostname() or "localhost",
        "source": "canary",
        "kind": "alert",
        "event_id": EVENT_ID,
        "severity": "high",
        "score": EVENT_SCORE,
        "action": "logged",
        "alert_id": alert_id[:64],
        "description": description[:2048],
    }
    for key in ("user", "process", "pid", "dest_ip", "dns_query", "file_path"):
        value = fields.get(key)
        if value not in (None, ""):
            event[key] = value
    return event


def _append_event(root, events_path, event: dict) -> None:
    events_path = Path(events_path)
    events_path.parent.mkdir(parents=True, exist_ok=True)
    with agentstate.lock(Path(root) / ".canary-events.lock",
                         timeout=10, stale=60):
        agentstate.ensure_trailing_newline(events_path)
        with events_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n")


def _hit_key(*parts) -> str:
    return hashlib.sha256(
        "|".join(str(p or "") for p in parts).encode("utf-8")
    ).hexdigest()[:32]


def _tail_rows(path: Path, max_rows: int = 5000, max_bytes: int = 4 << 20):
    path = Path(path)
    if not path.exists():
        return []
    try:
        size = path.stat().st_size
        start = max(0, size - max_bytes)
        with path.open("rb") as fh:
            fh.seek(start)
            blob = fh.read()
        if start:
            # Drop the partial first line.
            cut = blob.find(b"\n")
            blob = blob[cut + 1:] if cut >= 0 else b""
        rows = []
        for line in blob.splitlines()[-max_rows:]:
            if not line.strip():
                continue
            try:
                row = json.loads(line.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
        return rows
    except OSError:
        return []


def _dns_event(token: dict, row: dict, host: str) -> dict:
    return _canary_event(
        f"canary:dns:{token['id']}",
        f"canary DNS token queried: {token.get('fqdn')}",
        host=str(row.get("host") or host or socket.gethostname() or "localhost"),
        ts=row.get("ts"),
        user=row.get("user"),
        process=_base_name(row.get("process")),
        pid=_safe_pid(row.get("pid")),
        dest_ip=_safe_ip(row.get("dest_ip")),
        dns_query=row.get("dns_query"),
    )


def _http_event(token: dict, hit: dict) -> dict:
    source_ip = _safe_ip(hit.get("source_ip"))
    return _canary_event(
        f"canary:http:{token['id']}",
        f"canary HTTP token requested: {token['id']}"
        + (f" from {source_ip}" if source_ip else ""),
        host=socket.gethostname() or "localhost",
        ts=hit.get("ts"),
        dest_ip=source_ip,
    )


# ---------------------------------------------------------------------------
# DNS collection
# ---------------------------------------------------------------------------

def _pull_sysmon_dns(since_minutes: int = 15, max_events: int = 500) -> dict:
    if os.name != "nt":
        return {"events": [], "error": "Sysmon DNS collection requires Windows"}
    exe = shutil.which("powershell.exe") or shutil.which("pwsh")
    if not exe:
        return {"events": [], "error": "powershell not available on this host"}
    since_minutes = max(1, min(1440, int(since_minutes)))
    max_events = max(1, min(5000, int(max_events)))
    payload = _PS_SYSMON.format(since_minutes=since_minutes,
                                max_events=max_events)
    try:
        proc = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-Command", payload],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"events": [], "error": str(exc)[:300]}
    text = (proc.stdout or "").strip()
    if not text:
        return {"events": [], "error": (proc.stderr or "Sysmon query returned no output").strip()[:300]}
    try:
        blob = json.loads(text.splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return {"events": [], "error": "Sysmon query did not emit JSON"}
    if isinstance(blob, dict) and blob.get("error"):
        return {"events": [], "error": str(blob["error"])[:300]}
    rows = blob.get("events") if isinstance(blob, dict) else blob
    return {"events": rows or [], "error": None, "rc": proc.returncode}


def collect_dns_hits(root, events_path, since_minutes: int = 15,
                     max_events: int = 500, host: str | None = None) -> dict:
    """Find new DNS token queries and append canary alert events.

    Two sources are checked: the existing Plasma event store (tap/WHIDS/
    normalized Sysmon rows already collected) and, on Windows, a bounded
    Sysmon EID 22 pull.  The latter is what makes a fresh install work even
    when no other collector has ingested the query yet.
    """
    root = Path(root)
    tokens = dns_tokens(root)
    if not tokens:
        return {"checked": 0, "hits": [], "appended": 0, "error": None}
    by_name = {str(t.get("fqdn") or "").lower().rstrip("."): t for t in tokens}
    state_path = root / DNS_STATE
    state = agentstate.read_json(state_path, {}) or {}
    seen = set(state.get("seen") or []) if isinstance(state, dict) else set()
    host = host or socket.gethostname() or "localhost"
    candidates = []

    for row in _tail_rows(Path(events_path)):
        if str(row.get("source") or "") == "canary":
            continue
        query = str(row.get("dns_query") or "").lower().rstrip(".")
        token = by_name.get(query)
        if token:
            candidates.append((token, row))

    sysmon_error = None
    if os.name == "nt":
        pulled = _pull_sysmon_dns(since_minutes, max_events)
        sysmon_error = pulled.get("error")
        for row in pulled.get("events") or []:
            query = str(row.get("dns_query") or "").lower().rstrip(".")
            token = by_name.get(query)
            if token:
                candidates.append((token, row))

    appended = 0
    hits = []
    new_seen = set(seen)
    for token, row in candidates:
        key = _hit_key("dns", token["id"], str(row.get("host") or host),
                       str(row.get("ts") or "")[:16],
                       str(row.get("dns_query") or "").lower().rstrip("."),
                       row.get("pid"), _base_name(row.get("process")))
        if key in new_seen:
            continue
        event = _dns_event(token, row, host)
        try:
            _append_event(root, events_path, event)
        except OSError as exc:
            return {"checked": len(candidates), "hits": hits,
                    "appended": appended, "error": f"event append failed: {exc}",
                    "sysmon_error": sysmon_error}
        new_seen.add(key)
        appended += 1
        hits.append({"token_id": token["id"], "kind": "dns",
                     "fqdn": token.get("fqdn"), "event": event})

    agentstate.write_json(state_path, {"seen": list(new_seen)[-MAX_SEEN:]})
    return {"checked": len(candidates), "hits": hits, "appended": appended,
            "error": None, "sysmon_error": sysmon_error}


# ---------------------------------------------------------------------------
# HTTP collection
# ---------------------------------------------------------------------------

def record_http_hit(root, token_id: str, source_ip: str | None,
                    user_agent: str | None = None, path: str | None = None):
    """Record one valid HTTP token request.  Returns the hit row or None."""
    tokens = {str(t.get("id")): t for t in http_tokens(root)}
    token = tokens.get(str(token_id))
    if token is None:
        return None
    ua = redact.redact_text(str(user_agent or ""))[:256]
    ua = "".join(ch for ch in ua if ch == "\t" or ord(ch) >= 32)
    row = {
        "ts": _now(),
        "token_id": token["id"],
        "kind": "http",
        "source_ip": _safe_ip(source_ip) or None,
        "user_agent": ua or None,
        "path": str(path or "")[:512],
    }
    path_obj = _hits_path(root)
    path_obj.parent.mkdir(parents=True, exist_ok=True)
    with agentstate.lock(Path(root) / ".canary-hits.lock",
                         timeout=10, stale=60):
        agentstate.ensure_trailing_newline(path_obj)
        with path_obj.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
    return row


def _file_head(path: Path, limit: int = 512) -> str:
    limit = max(0, min(int(limit), 512))
    if not limit:
        return ""
    try:
        with path.open("rb") as fh:
            return hashlib.sha1(fh.read(limit)).hexdigest()
    except OSError:
        return ""


def _read_new_hit_rows(root, max_bytes: int = 4 << 20):
    path = _hits_path(root)
    state_path = Path(root) / HTTP_STATE
    state = agentstate.read_json(state_path, {}) or {}
    if not isinstance(state, dict):
        state = {}
    if not path.exists():
        return [], state, state_path
    try:
        size = path.stat().st_size
    except OSError:
        return [], state, state_path
    offset = int(state.get("offset", 0) or 0)
    # Hash exactly the bytes already consumed.  Hashing a fixed 512-byte
    # window changes when a short file is appended to, which made every
    # second hit look like a replaced file and re-ingested the history.
    head = _file_head(path, min(offset, 512))
    if size < offset or (head and state.get("head") and state.get("head") != head):
        offset = 0
        head = ""
    try:
        with path.open("rb") as fh:
            fh.seek(offset)
            blob = fh.read(max_bytes)
    except OSError:
        return [], state, state_path
    cut = blob.rfind(b"\n")
    if cut < 0:
        return [], {"offset": offset, "size": size, "head": head}, state_path
    consumed = offset + cut + 1
    rows = []
    for line in blob[:cut + 1].splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows, {"offset": consumed, "size": size,
                  "head": _file_head(path, min(consumed, 512))}, state_path


def collect_http_hits(root, events_path) -> dict:
    tokens = {str(t.get("id")): t for t in http_tokens(root)}
    if not tokens:
        return {"checked": 0, "hits": [], "appended": 0, "error": None}
    rows, state, state_path = _read_new_hit_rows(root)
    if not isinstance(state, dict):
        state = {}
    seen = set(state.get("seen") or [])
    appended = 0
    hits = []
    new_seen = set(seen)
    for row in rows:
        token = tokens.get(str(row.get("token_id") or ""))
        if token is None:
            continue
        key = _hit_key("http", token["id"], row.get("ts"),
                       row.get("source_ip"), row.get("user_agent"))
        if key in new_seen:
            continue
        event = _http_event(token, row)
        try:
            _append_event(root, events_path, event)
        except OSError as exc:
            return {"checked": len(rows), "hits": hits,
                    "appended": appended,
                    "error": f"event append failed: {exc}"}
        new_seen.add(key)
        appended += 1
        hits.append({"token_id": token["id"], "kind": "http",
                     "event": event})
    state["seen"] = list(new_seen)[-MAX_SEEN:]
    agentstate.write_json(state_path, state)
    return {"checked": len(rows), "hits": hits, "appended": appended,
            "error": None}


def collect_all(root, events_path, since_minutes: int = 15,
                max_events: int = 500) -> dict:
    dns = collect_dns_hits(root, events_path, since_minutes, max_events)
    http = collect_http_hits(root, events_path)
    return {
        "dns": dns,
        "http": http,
        "appended": int(dns.get("appended", 0)) + int(http.get("appended", 0)),
    }


def hits(root, events_path, last: int = 50) -> dict:
    """Return recent canary alert rows from the event store."""
    rows = []
    for row in _tail_rows(Path(events_path), max_rows=max(1, last)):
        if row.get("source") == "canary":
            rows.append(row)
    return {"count": len(rows), "hits": rows[-max(1, last):]}


# ---------------------------------------------------------------------------
# local HTTP token service
# ---------------------------------------------------------------------------

def _loopback(host: str) -> bool:
    text = str(host or "").strip().lower()
    if text in ("localhost", "::1"):
        return True
    try:
        return ipaddress.ip_address(text.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


class _TokenServer(http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = False
    timeout = 10


def make_server(root, host: str = "127.0.0.1", port: int = 8088,
                allow_non_loopback: bool = False, max_requests: int = 0):
    """Create the HTTP token server without starting it.

    The caller can use ``server.serve_forever()``, or bind ``port=0`` and
    read ``server.server_address[1]`` in tests.  A non-loopback bind is
    refused unless explicitly allowed, mirroring ``plasma serve``.
    """
    if not _loopback(host) and not allow_non_loopback:
        return None, {"error": "refusing a non-loopback token listener; "
                               "pass --allow-non-loopback for a VLAN/collector "
                               "interface"}
    tokens = {str(t.get("id")): t for t in http_tokens(root)}
    root = Path(root)

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "PlasmaCanary/1"
        sys_version = ""
        protocol_version = "HTTP/1.0"

        def log_message(self, fmt, *args):  # noqa: A003 - stdlib API
            return

        def _handle(self, send_body: bool):
            parts = urlsplit(self.path)
            token_id = parts.path[3:].strip("/") if parts.path.startswith("/t/") else ""
            token = tokens.get(token_id) if TOKEN_RE.match(token_id) else None
            if token is None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            try:
                record_http_hit(root, token_id, self.client_address[0],
                                self.headers.get("User-Agent"), parts.path)
            except OSError:
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.server.request_count += 1
            self.send_response(200)
            self.send_header("Content-Type", "image/gif")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(_GIF)))
            self.end_headers()
            if send_body:
                try:
                    self.wfile.write(_GIF)
                except OSError:
                    pass
            if self.server.max_requests and \
                    self.server.request_count >= self.server.max_requests:
                threading.Thread(target=self.server.shutdown,
                                 daemon=True).start()

        def do_GET(self):  # noqa: N802 - stdlib API
            self._handle(True)

        def do_HEAD(self):  # noqa: N802 - stdlib API
            self._handle(False)

        def do_POST(self):  # noqa: N802 - stdlib API
            self.send_response(405)
            self.send_header("Allow", "GET, HEAD")
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_PUT = do_POST
        do_DELETE = do_POST
        do_PATCH = do_POST

    try:
        server = _TokenServer((host, int(port)), Handler)
    except OSError as exc:
        return None, {"error": f"cannot bind {host}:{port}: {exc}"}
    server.token_map = tokens
    server.request_count = 0
    server.max_requests = max(0, int(max_requests))
    server.plasma_root = root
    info = {
        "host": host,
        "port": server.server_address[1],
        "tokens": len(tokens),
        "max_requests": server.max_requests,
        "hits_file": str(_hits_path(root)),
    }
    return server, info


def serve(root, host: str = "127.0.0.1", port: int = 8088,
          allow_non_loopback: bool = False, max_requests: int = 0) -> dict:
    """Run the local HTTP token service until interrupted or max_requests."""
    server, info = make_server(root, host, port, allow_non_loopback,
                               max_requests)
    if server is None:
        return info
    state_path = Path(root) / SERVER_STATE
    agentstate.write_json(state_path, {
        "pid": os.getpid(), "host": info["host"], "port": info["port"],
        "started_at": _now(), "tokens": info["tokens"],
    })
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        agentstate.write_json(state_path, {
            "pid": os.getpid(), "host": info["host"], "port": info["port"],
            "started_at": _now(), "stopped_at": _now(),
            "requests": server.request_count, "tokens": info["tokens"],
        })
    return {"ok": True, **info, "requests": server.request_count,
            "stopped_at": _now()}
