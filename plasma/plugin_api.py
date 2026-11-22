"""Plugin API: manifest, envelope, normalisation and signatures.

Plasma plugins are processes, not imports. A plugin declares what it is in
`plugin.json`, emits newline-delimited JSON on stdout (or a pipe), and the
core validates every record before it can reach the event store. Nothing a
plugin emits is trusted: fields are typed, capped, redacted and stamped with
the core-owned source.

This module is deliberately dependency-light. Ed25519 signing uses
`cryptography` when it is installed; unsigned plugins are refused by the
installer unless an operator explicitly allows them.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

API_VERSION = "1.0"
SUPPORTED_API = {"1.0"}
ENVELOPE_VERSION = 1
KINDS = {"sensor", "detector", "responder", "exporter"}
RUNTIMES = {"native", "python", "powershell"}
PROTOCOLS = {"ndjson-stdio"}
EVENT_KINDS = {"process", "alert", "network", "file", "registry", "auth"}
SEVERITIES = {"info", "low", "medium", "high", "critical"}
TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
VERSION = re.compile(r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?$")
MAX_DESCRIPTION = 2048
MAX_LINE = 65536
MAX_ATTRIBUTES = 20
MAX_ATTRIBUTE_CHARS = 512
MAX_EVIDENCE = 10

EVENT_FIELDS = {
    "ts", "host", "source", "kind", "event_id", "severity", "score",
    "action", "user", "process", "pid", "ppid", "parent", "image",
    "cmdline", "dest_ip", "dest_port", "dns_query", "file_path",
    "file_hash", "registry_path", "technique", "alert_id", "description",
}
_NUMERIC = {"pid", "ppid", "event_id", "dest_port"}
_TEXT_LIMITS = {
    "user": 128, "process": 260, "parent": 260, "image": 512,
    "cmdline": 2048, "dest_ip": 45, "dns_query": 512, "file_path": 1024,
    "file_hash": 128, "registry_path": 1024, "technique": 16,
    "alert_id": 128, "action": 32, "severity": 16, "kind": 16,
    "host": 128, "source": 128, "ts": 64,
}


class PluginError(ValueError):
    """A plugin manifest, envelope or record is invalid."""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _clip(value, limit: int) -> str:
    return str(value if value is not None else "")[:limit]


def _redact(value) -> str:
    try:
        from .redact import redact_text
        return redact_text(str(value))
    except Exception:  # noqa: BLE001 — redaction must never break ingestion
        return str(value)


# ---------------------------------------------------------------------------
# manifest
# ---------------------------------------------------------------------------

def load_manifest(plugin_dir) -> dict:
    path = Path(plugin_dir) / "plugin.json"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise PluginError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PluginError(f"invalid plugin.json: {exc}") from exc
    if not isinstance(manifest, dict):
        raise PluginError("plugin.json must be an object")
    errors = validate_manifest(manifest, Path(plugin_dir))
    if errors:
        raise PluginError("; ".join(errors))
    return manifest


def validate_manifest(manifest: dict, base: Path | None = None) -> list[str]:
    errors: list[str] = []
    name = str(manifest.get("name") or "")
    if not NAME.match(name):
        errors.append("name must match [a-z0-9][a-z0-9._-]{0,63}")
    if not VERSION.match(str(manifest.get("version") or "")):
        errors.append("version must be semver-like (x.y.z)")
    if str(manifest.get("api_version") or "") not in SUPPORTED_API:
        errors.append(f"api_version must be one of {sorted(SUPPORTED_API)}")
    kind = str(manifest.get("kind") or "")
    if kind not in KINDS:
        errors.append(f"kind must be one of {sorted(KINDS)}")
    runtime = str(manifest.get("runtime") or "native")
    if runtime not in RUNTIMES:
        errors.append(f"runtime must be one of {sorted(RUNTIMES)}")
    protocol = str(manifest.get("protocol") or "ndjson-stdio")
    if protocol not in PROTOCOLS:
        errors.append(f"protocol must be one of {sorted(PROTOCOLS)}")
    entry = str(manifest.get("entrypoint") or "")
    if not entry:
        errors.append("entrypoint is required")
    elif base is not None:
        target = (base / entry).resolve()
        try:
            target.relative_to(base.resolve())
        except ValueError:
            errors.append("entrypoint must stay inside the plugin directory")
        else:
            if not target.is_file():
                errors.append(f"entrypoint not found: {entry}")
    limits = manifest.get("limits") or {}
    if not isinstance(limits, dict):
        errors.append("limits must be an object")
    else:
        for key in ("max_events", "max_line_bytes", "timeout_seconds"):
            value = limits.get(key)
            if value is not None and (not isinstance(value, int) or value <= 0):
                errors.append(f"limits.{key} must be a positive integer")
        if int(limits.get("max_line_bytes") or MAX_LINE) > MAX_LINE:
            errors.append(f"limits.max_line_bytes cannot exceed {MAX_LINE}")
    permissions = manifest.get("permissions") or {}
    if not isinstance(permissions, dict):
        errors.append("permissions must be an object")
    else:
        for key, values in permissions.items():
            if not isinstance(values, list) or not all(
                    isinstance(item, str) for item in values):
                errors.append(f"permissions.{key} must be a list of strings")
    health = manifest.get("health")
    if health is not None and not isinstance(health, dict):
        errors.append("health must be an object")
    return errors


def entry_command(manifest: dict, base: Path) -> list[str]:
    """Build the argv for a plugin entrypoint without a shell."""
    entry = (base / str(manifest["entrypoint"])).resolve()
    runtime = str(manifest.get("runtime") or "native")
    if runtime == "python":
        interpreter = os.environ.get("PLASMA_PLUGIN_PYTHON") or (
            sys.executable if not getattr(sys, "frozen", False) else "python")
        return [interpreter, str(entry)]
    if runtime == "powershell":
        return ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(entry)]
    return [str(entry)]


# ---------------------------------------------------------------------------
# envelope and records
# ---------------------------------------------------------------------------

def parse_line(line: str, plugin: str) -> dict:
    if not isinstance(line, str):
        raise PluginError("record is not text")
    if len(line.encode("utf-8", "replace")) > MAX_LINE:
        raise PluginError(f"record exceeds {MAX_LINE} bytes")
    try:
        payload = json.loads(line)
    except json.JSONDecodeError as exc:
        raise PluginError(f"invalid JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise PluginError("record must be a JSON object")
    if int(payload.get("v") or 0) != ENVELOPE_VERSION:
        raise PluginError(f"unsupported envelope version {payload.get('v')!r}")
    kind = str(payload.get("type") or "")
    if kind not in ("event", "finding", "health", "log"):
        raise PluginError(f"unknown record type {kind!r}")
    if payload.get("plugin") not in (None, plugin):
        raise PluginError("record plugin id does not match the installed plugin")
    return payload


def _ts(value) -> str:
    text = str(value or "").strip()
    if not text:
        return now_iso()
    try:
        stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PluginError(f"invalid timestamp {text!r}") from exc
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_event(payload: dict, plugin: str, version: str = "",
                    host: str | None = None) -> dict:
    raw = payload.get("event") if isinstance(payload.get("event"), dict) else payload
    if not isinstance(raw, dict):
        raise PluginError("event must be an object")

    event: dict = {}
    attributes: dict = {}
    for key, value in raw.items():
        key = str(key)
        if key in EVENT_FIELDS:
            event[key] = value
        elif len(attributes) < MAX_ATTRIBUTES:
            attributes[key[:64]] = _clip(_redact(value), MAX_ATTRIBUTE_CHARS)

    event["ts"] = _ts(event.get("ts"))
    event["host"] = _clip(event.get("host") or host or _hostname(), 128)
    event["source"] = f"plugin:{plugin}"
    event["kind"] = str(event.get("kind") or "process").lower()
    if event["kind"] not in EVENT_KINDS:
        raise PluginError(f"event kind must be one of {sorted(EVENT_KINDS)}")

    for key, limit in _TEXT_LIMITS.items():
        if key in event and event[key] is not None:
            event[key] = _clip(_redact(event[key]) if key in (
                "cmdline", "description", "file_path", "registry_path"
            ) else event[key], limit)
    for key in _NUMERIC:
        if key in event and event[key] not in (None, ""):
            try:
                event[key] = int(event[key])
            except (TypeError, ValueError) as exc:
                raise PluginError(f"{key} must be an integer") from exc

    event_id = event.get("event_id", 0)
    if not isinstance(event_id, int) or not 0 <= event_id <= 65535:
        raise PluginError("event_id must be an integer 0..65535")

    score = event.get("score", 0.0)
    try:
        score = float(score)
    except (TypeError, ValueError) as exc:
        raise PluginError("score must be a number 0..1") from exc
    if not 0.0 <= score <= 1.0:
        raise PluginError("score must be between 0 and 1")
    event["score"] = round(score, 3)

    severity = str(event.get("severity") or "").lower()
    if severity and severity not in SEVERITIES:
        raise PluginError(f"severity must be one of {sorted(SEVERITIES)}")
    event["severity"] = severity or _severity(score)

    technique = event.get("technique")
    if technique is not None and not TECHNIQUE.match(str(technique)):
        raise PluginError("technique must look like T1234 or T1234.567")

    if not any(event.get(field) not in (None, "", 0) for field in (
            "process", "pid", "user", "file_path", "registry_path",
            "dest_ip", "dns_query", "cmdline", "description")):
        raise PluginError("event carries no usable signal")

    event["action"] = str(event.get("action") or "logged")
    event["description"] = _clip(
        event.get("description") or
        f"plugin {plugin} {event['kind']}", MAX_DESCRIPTION)
    event.setdefault("plugin", f"{plugin}@{version}" if version else plugin)
    if attributes:
        event["attributes"] = attributes
    return {key: value for key, value in event.items() if value is not None}


def normalize_finding(payload: dict, plugin: str, version: str = "",
                      host: str | None = None, max_score: float = 1.0) -> dict:
    raw = payload.get("finding") if isinstance(payload.get("finding"), dict) else payload
    if not isinstance(raw, dict):
        raise PluginError("finding must be an object")
    description = _clip(_redact(raw.get("description") or ""), MAX_DESCRIPTION)
    if not description:
        raise PluginError("finding needs a description")
    try:
        score = float(raw.get("score"))
    except (TypeError, ValueError) as exc:
        raise PluginError("finding score must be a number") from exc
    if not 0.0 <= score <= max_score:
        raise PluginError(f"finding score must be between 0 and {max_score}")
    technique = raw.get("technique")
    if technique is not None and not TECHNIQUE.match(str(technique)):
        raise PluginError("finding technique must look like T1234 or T1234.567")
    evidence = raw.get("evidence") or []
    if not isinstance(evidence, list):
        raise PluginError("evidence must be a list")
    evidence = [_clip(_redact(item), 200) for item in evidence[:MAX_EVIDENCE]]
    event = {
        "ts": _ts(raw.get("ts")),
        "host": _clip(raw.get("host") or host or _hostname(), 128),
        "source": f"plugin:{plugin}",
        "kind": "alert",
        "event_id": 0,
        "severity": _severity(score),
        "score": round(score, 3),
        "action": "logged",
        "technique": str(technique) if technique else None,
        "alert_id": f"plugin:{plugin}"[:128],
        "description": description,
        "plugin": f"{plugin}@{version}" if version else plugin,
    }
    if evidence:
        event["evidence"] = evidence
    return {key: value for key, value in event.items() if value is not None}


def _severity(score: float) -> str:
    if score >= 0.9:
        return "critical"
    if score >= 0.7:
        return "high"
    if score >= 0.4:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def dedupe_key(event: dict) -> str:
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"),
                           default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# signatures
# ---------------------------------------------------------------------------

_PAYLOAD_SKIP_DIRS = {"__pycache__", ".git", ".pytest_cache"}
_PAYLOAD_SKIP_SUFFIXES = {".pyc", ".pyo"}
SIGNATURE_NAME = "SIGNATURE"


def payload_files(plugin_dir) -> list[Path]:
    base = Path(plugin_dir)
    files = []
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(base)
        if any(part in _PAYLOAD_SKIP_DIRS for part in rel.parts):
            continue
        if path.suffix in _PAYLOAD_SKIP_SUFFIXES or path.name == SIGNATURE_NAME:
            continue
        files.append(path)
    return files


def payload_digest(plugin_dir) -> str:
    base = Path(plugin_dir)
    digest = hashlib.sha256()
    for path in payload_files(base):
        rel = path.relative_to(base).as_posix().encode("utf-8")
        digest.update(rel + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def keygen(out_dir) -> dict:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.generate()
    private_path = target / "plugin-private.pem"
    public_path = target / "plugin-public.pem"
    private_path.write_bytes(private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()))
    public_path.write_bytes(private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass
    return {"ok": True, "private_key": str(private_path),
            "public_key": str(public_path),
            "fingerprint": _fingerprint(_raw_public(private.public_key()))}


def sign(plugin_dir, key_path) -> dict:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    base = Path(plugin_dir)
    private = serialization.load_pem_private_key(
        Path(key_path).read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise PluginError("signing key must be Ed25519")
    digest = payload_digest(base)
    signature = private.sign(digest.encode("ascii"))
    public_raw = _raw_public(private.public_key())
    record = {
        "algo": "ed25519",
        "digest": digest,
        "public_key": base64.b64encode(public_raw).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
        "fingerprint": _fingerprint(public_raw),
        "signed_at": now_iso(),
    }
    (base / SIGNATURE_NAME).write_text(
        json.dumps(record, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return {"ok": True, "signature": str(base / SIGNATURE_NAME), **record}


def verify_signature(plugin_dir, trust_key=None) -> dict:
    """Verify SIGNATURE and recompute the payload digest."""
    base = Path(plugin_dir)
    path = base / SIGNATURE_NAME
    if not path.exists():
        return {"ok": False, "signed": False, "reason": "unsigned plugin"}
    try:
        record = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "signed": True,
                "reason": f"unreadable signature: {exc}"}
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        public_raw = base64.b64decode(record["public_key"])
        signature = base64.b64decode(record["signature"])
        digest = payload_digest(base)
        if record.get("digest") != digest:
            return {"ok": False, "signed": True,
                    "reason": "payload digest mismatch"}
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            signature, digest.encode("ascii"))
    except Exception as exc:  # noqa: BLE001 — any failure is a refusal
        return {"ok": False, "signed": True,
                "reason": f"signature verification failed: {exc}"}
    fingerprint = _fingerprint(public_raw)
    if trust_key is not None:
        try:
            expected = _trust_fingerprint(trust_key)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "signed": True,
                    "reason": f"unreadable trust key: {exc}"}
        if expected != fingerprint:
            return {"ok": False, "signed": True, "fingerprint": fingerprint,
                    "reason": "signing key is not trusted"}
    return {"ok": True, "signed": True, "digest": digest,
            "fingerprint": fingerprint, "signed_at": record.get("signed_at")}


def _raw_public(public_key) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)


def _fingerprint(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _trust_fingerprint(trust_key) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    text = str(trust_key)
    path = Path(text)
    if path.exists():
        public = serialization.load_pem_public_key(path.read_bytes())
        if not isinstance(public, Ed25519PublicKey):
            raise PluginError("trust key must be Ed25519")
        return _fingerprint(_raw_public(public))
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError as exc:
        raise PluginError("trust key is neither a PEM file nor base64") from exc
    return _fingerprint(raw)


def seconds_since(stamp: str | None) -> float | None:
    if not stamp:
        return None
    try:
        parsed = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return max(0.0, time.time() - parsed.timestamp())
