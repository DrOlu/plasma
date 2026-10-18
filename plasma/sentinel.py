"""Two-way Sentinel integration.

PULL   Sentinel detections  ->  normalized Plasma events
       %ProgramData%\\Sentinel\\events.jsonl contains JSONL records of the form
       {"type":"detection","timestamp":...,"data":DetectionEvent}. DetectionEvent
       uses PascalCase fields (RuleName, RuleId, Confidence, Tier, ProcessName,
       ProcessId, Metadata, AuthorizedResponse, KillAuthorized).

PUSH   Plasma intelligence -> Sentinel local IOC snapshot
       %ProgramData%\\Sentinel\\threatfox-bundle.json.gz is an unsigned gzipped
       JSON array of {Indicator, IocType, MalwareFamily, Confidence, Source}.
       Sentinel loads it at service start: SHA-256 hashes -> IoCScanner,
       domains/URLs -> DnsQueryMonitor. Rule packs are vendor-RSA-signed and are
       deliberately NOT touched by this module.

Safety: push is dry-run by default; private/reserved addresses and benign
domains are excluded; the existing bundle is backed up and merged by highest
confidence; every apply is journaled.
"""
from __future__ import annotations

import gzip
import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .manifest import sha256_file

# DetectionTier: Tier1Behavioral=0, Tier2Indicator=1
# ResponseAction order (Sentinel.Core.Models)
RESPONSE_ACTIONS = [
    "LogOnly", "NetworkIsolate", "RemoveCert", "VpnShieldUp", "KillProcess",
    "KillProcessTree", "Quarantine", "QuarantineAndKill", "RemoveCertAndKillAdder",
    "RemoveRegistryEntry",
]

BENIGN_DOMAIN_SUFFIXES = (
    "microsoft.com", "windows.com", "windowsupdate.com", "office365.com",
    "office.com", "live.com", "bing.com", "google.com", "googleapis.com",
    "gstatic.com", "cloudflare.com", "akamai.net", "amazonaws.com",
    "local", "internal", "corp.local", "localhost",
)

HASH_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

DEFAULT_MIN_CONFIDENCE = 85
DEFAULT_MAX_IOCS = 5000


def default_root() -> Path:
    env = os.environ.get("PLASMA_SENTINEL_ROOT")
    if env:
        return Path(env)
    base = os.environ.get("ProgramData", r"C:\ProgramData")
    return Path(base) / "Sentinel"


def default_events_path() -> Path:
    env = os.environ.get("PLASMA_EVENTS")
    if env:
        return Path(env)
    base = os.environ.get("ProgramData", r"C:\ProgramData")
    return Path(base) / "Plasma" / "data" / "events.jsonl"


def _get(record: dict, *names, default=None):
    lowered = {str(k).lower(): v for k, v in record.items()}
    for name in names:
        if name.lower() in lowered and lowered[name.lower()] is not None:
            return lowered[name.lower()]
    return default


def _enum(value, values, default=""):
    if isinstance(value, int) and 0 <= value < len(values):
        return values[value]
    if isinstance(value, str):
        for candidate in values:
            if candidate.lower() == value.lower():
                return candidate
        if value.isdigit() and int(value) < len(values):
            return values[int(value)]
    return default


def _severity(tier: str, confidence: float) -> str:
    if tier == "Tier1Behavioral":
        if confidence >= 0.90:
            return "critical"
        if confidence >= 0.70:
            return "high"
        return "medium"
    if confidence >= 0.90:
        return "high"
    if confidence >= 0.60:
        return "medium"
    return "low"


def _action(authorized: str, kill_authorized: bool) -> str:
    if authorized in ("KillProcess", "KillProcessTree", "QuarantineAndKill",
                      "RemoveCertAndKillAdder"):
        return "killed"
    if authorized == "Quarantine":
        return "quarantined"
    if authorized == "NetworkIsolate":
        return "blocked"
    if kill_authorized:
        return "killed"
    return "logged"


def _slug(text: str, limit: int = 64) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", text or "sentinel").strip("-")
    return slug[:limit] or "sentinel"


def _technique(metadata: dict, record: dict):
    for key in ("AttackTechnique", "AttackTechniques", "Technique", "MITRE",
                "MitreTechnique", "ATT&CK", "AttackTechniquesList"):
        value = _get(metadata, key)
        if isinstance(value, list):
            value = value[0] if value else None
        if isinstance(value, str):
            value = value.strip().strip("[]\"'")
            if TECHNIQUE_RE.match(value):
                return value
    direct = _get(record, "Technique", "AttackTechnique")
    if isinstance(direct, str) and TECHNIQUE_RE.match(direct.strip()):
        return direct.strip()
    return None


def normalize_detection(line: dict, host: str | None = None):
    """Convert one Sentinel events.jsonl record to a Plasma event dict.

    Returns None for non-detection records (response/audit/integrity).
    """
    if str(_get(line, "type", default="")).lower() != "detection":
        return None
    data = _get(line, "data", default={}) or {}
    if not isinstance(data, dict):
        return None

    rule_name = str(_get(data, "RuleName", default="Sentinel detection") or "Sentinel detection")
    rule_id = _get(data, "RuleId")
    confidence = float(_get(data, "Confidence", default=0.0) or 0.0)
    tier = _enum(_get(data, "Tier"), ["Tier1Behavioral", "Tier2Indicator"])
    authorized = _enum(_get(data, "AuthorizedResponse"), RESPONSE_ACTIONS)
    kill_authorized = bool(_get(data, "KillAuthorized", default=False))
    metadata = _get(data, "Metadata", default={}) or {}
    if not isinstance(metadata, dict):
        metadata = {}

    ts = _get(data, "Timestamp") or _get(line, "timestamp")
    process = _get(data, "ProcessName")
    if isinstance(process, str) and "\\" in process:
        process = process.rsplit("\\", 1)[-1]
    pid = _get(data, "ProcessId")
    evidence = str(_get(data, "Evidence", default="") or "")
    reasoning = str(_get(data, "Reasoning", default="") or "")
    description = (f"{rule_name}: {evidence}" if evidence else rule_name)[:2048]

    event = {
        "ts": ts,
        "host": str(_get(metadata, "Host", "Computer", "Hostname", default=host or socket.gethostname())),
        "source": "sentinel",
        "kind": "alert",
        "event_id": 9100,
        "severity": _severity(tier, confidence),
        "user": _get(metadata, "User", "UserName"),
        "process": process,
        "pid": int(pid) if isinstance(pid, (int, float)) and int(pid) >= 0 else None,
        "ppid": None,
        "parent": None,
        "image": None,
        "cmdline": _get(metadata, "CommandLine", "CmdLine"),
        "dest_ip": _get(metadata, "RemoteIp", "DestinationIp", "DestIp", "RemoteAddress"),
        "dest_port": _get(metadata, "RemotePort", "DestinationPort"),
        "dns_query": _get(metadata, "Domain", "QueryName", "DnsQuery"),
        "file_path": _get(metadata, "FilePath", "TargetFile"),
        "registry_path": _get(metadata, "RegistryPath", "TargetObject"),
        "file_hash": _get(metadata, "Sha256", "SHA256", "FileHash", "Hash"),
        "technique": _technique(metadata, data),
        "alert_id": str(rule_id) if rule_id else _slug(rule_name),
        "score": max(0.0, min(confidence, 1.0)),
        "action": _action(authorized, kill_authorized),
        "description": description,
    }
    if reasoning and len(description) < 1024:
        event["description"] = f"{description} | {reasoning}"[:2048]

    # Keep the strict PlasmaEvent contract happy: nulls are allowed, wrong
    # types are not. Drop optional fields that fail a quick shape check.
    if event["dest_ip"] is not None and not re.match(r"^[0-9A-Fa-f:.]{2,45}$", str(event["dest_ip"])):
        event["dest_ip"] = None
    if event["file_hash"] is not None and not HASH_RE.match(str(event["file_hash"])):
        event["file_hash"] = None
    if event["dest_port"] is not None:
        try:
            port = int(event["dest_port"])
            event["dest_port"] = port if 0 <= port <= 65535 else None
        except (TypeError, ValueError):
            event["dest_port"] = None
    return event


# ---------------------------------------------------------------------------
# PULL
# ---------------------------------------------------------------------------

def _event_key(event: dict) -> tuple:
    return (event.get("alert_id"), str(event.get("ts")), event.get("pid"), event.get("process"))


def pull(sentinel_root: str | Path | None = None, out: str | Path | None = None,
         host: str | None = None) -> dict:
    root = Path(sentinel_root) if sentinel_root else default_root()
    source = root / "events.jsonl"
    target = Path(out) if out else default_events_path()
    if not source.exists():
        return {"error": f"Sentinel event log not found: {source}", "written": 0}

    events, skipped = [], 0
    with open(source, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue
            event = normalize_detection(record, host=host)
            if event is None:
                skipped += 1
                continue
            events.append(event)

    existing_keys = set()
    existing = 0
    if target.exists():
        with open(target, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    prior = json.loads(line)
                except json.JSONDecodeError:
                    continue
                existing_keys.add(_event_key(prior))
                existing += 1

    fresh = [e for e in events if _event_key(e) not in existing_keys]
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "a", encoding="utf-8") as fh:
        for event in fresh:
            fh.write(json.dumps(event, separators=(",", ":"), default=str) + "\n")

    return {
        "source": str(source),
        "out": str(target),
        "detections": len(events),
        "skipped_records": skipped,
        "already_present": existing,
        "written": len(fresh),
    }


# ---------------------------------------------------------------------------
# PUSH
# ---------------------------------------------------------------------------

def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
        or ip.is_reserved or ip.is_unspecified
    )


def _is_benign_domain(value: str) -> bool:
    domain = str(value).strip().lower().rstrip(".")
    return any(domain == suffix or domain.endswith("." + suffix)
               for suffix in BENIGN_DOMAIN_SUFFIXES)


def _row_score(row: dict) -> int:
    if row.get("score") is not None:
        try:
            return max(0, min(100, int(round(float(row["score"]) * 100))))
        except (TypeError, ValueError):
            pass
    return {"critical": 95, "high": 85, "medium": 60}.get(row.get("severity"), 50)


def extract_indicators(rows, min_confidence: int = DEFAULT_MIN_CONFIDENCE) -> list[dict]:
    """Select high-confidence indicators from normalized Plasma events."""
    found: dict[str, dict] = {}

    def add(indicator, ioc_type, confidence, family, row):
        if indicator is None:
            return
        indicator = str(indicator).strip()
        if not indicator or indicator.lower() in ("none", "null"):
            return
        if ioc_type == "ip" and not _is_public_ip(indicator):
            return
        if ioc_type == "domain" and _is_benign_domain(indicator):
            return
        if ioc_type == "sha256" and not HASH_RE.match(indicator):
            return
        if confidence < min_confidence:
            return
        key = indicator.lower()
        candidate = {
            "Indicator": indicator,
            "IocType": ioc_type,
            "MalwareFamily": family or None,
            "Confidence": int(confidence),
            "Source": "Plasma",
        }
        prior = found.get(key)
        if prior is None or candidate["Confidence"] > prior["Confidence"]:
            found[key] = candidate

    for row in rows:
        confidence = _row_score(row)
        if confidence < min_confidence:
            continue
        family = row.get("alert_id") or row.get("technique")
        add(row.get("dest_ip"), "ip", confidence, family, row)
        add(row.get("dns_query"), "domain", confidence, family, row)
        add(row.get("file_hash"), "sha256", confidence, family, row)
    return sorted(found.values(), key=lambda i: (-i["Confidence"], i["Indicator"].lower()))


def read_bundle(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError, EOFError):
        return []


def merge_bundle(existing: list[dict], new: list[dict], max_iocs: int = DEFAULT_MAX_IOCS) -> list[dict]:
    merged: dict[str, dict] = {}
    for item in existing + new:
        if not isinstance(item, dict):
            continue
        indicator = _get(item, "Indicator")
        if not indicator or str(indicator).strip().lower() in ("none", "null"):
            continue
        key = str(indicator).lower()
        record = {
            "Indicator": str(indicator),
            "IocType": str(_get(item, "IocType", default="unknown") or "unknown"),
            "MalwareFamily": _get(item, "MalwareFamily"),
            "Confidence": int(_get(item, "Confidence", default=50) or 50),
            "Source": str(_get(item, "Source", default="Unknown") or "Unknown"),
        }
        prior = merged.get(key)
        if prior is None or record["Confidence"] > prior["Confidence"]:
            merged[key] = record
    ordered = sorted(merged.values(), key=lambda i: (-i["Confidence"], i["Indicator"].lower()))
    return ordered[:max_iocs]


def write_bundle(path: Path, iocs: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    payload = json.dumps(iocs, separators=(",", ":"), sort_keys=True).encode("utf-8")
    with open(tmp, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz:
            gz.write(payload)
    os.replace(tmp, path)


def _journal_path(events_path: Path) -> Path:
    return events_path.parent / "sentinel-intel-journal.jsonl"


def _sentinel_service_name() -> str | None:
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             "Get-Service | Where-Object { $_.Name -like 'Sentinel*' -or "
             "$_.DisplayName -like '*Sentinel*' } | Select-Object -First 1 "
             "-ExpandProperty Name"],
            capture_output=True, text=True, timeout=20,
        )
        return proc.stdout.strip() or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def push(events_path: str | Path | None = None, sentinel_root: str | Path | None = None,
         min_confidence: int = DEFAULT_MIN_CONFIDENCE, max_iocs: int = DEFAULT_MAX_IOCS,
         apply: bool = False, restart_service: bool = False, reason: str = "") -> dict:
    events_file = Path(events_path) if events_path else default_events_path()
    root = Path(sentinel_root) if sentinel_root else default_root()
    bundle_path = root / "threatfox-bundle.json.gz"

    if not events_file.exists():
        return {"error": f"Plasma event store not found: {events_file}"}

    rows = []
    with open(events_file, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)

    new_iocs = extract_indicators(rows, min_confidence=min_confidence)
    existing = read_bundle(bundle_path)
    merged = merge_bundle(existing, new_iocs, max_iocs=max_iocs)

    def summary(items):
        counts = {"ip": 0, "domain": 0, "sha256": 0}
        for item in items:
            key = str(_get(item, "IocType", default="")).lower()
            counts[key] = counts.get(key, 0) + 1
        return counts

    plan = {
        "events_file": str(events_file),
        "bundle": str(bundle_path),
        "min_confidence": min_confidence,
        "max_iocs": max_iocs,
        "existing_iocs": len(existing),
        "new_iocs": len(new_iocs),
        "merged_iocs": len(merged),
        "by_type_new": summary(new_iocs),
        "by_type_merged": summary(merged),
        "sample": new_iocs[:10],
        "sentinel_actions": {
            "sha256": "IoCScanner hash watchlist",
            "domain": "DnsQueryMonitor domain IOC",
            "ip": "stored in the bundle; Sentinel 3.3.1 exposes no active IP query",
        },
        "apply": bool(apply),
    }

    if not apply:
        return {"ok": True, "dry_run": True, **plan}

    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    backup = None
    if bundle_path.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = bundle_path.with_name(f"threatfox-bundle.{stamp}.bak.gz")
        backup.write_bytes(bundle_path.read_bytes())

    write_bundle(bundle_path, merged)
    bundle_hash = sha256_file(bundle_path)

    service_restarted = False
    service_error = None
    service = _sentinel_service_name()
    if restart_service:
        if service:
            try:
                proc = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-Command",
                     f"Restart-Service -Name '{service}' -Force"],
                    capture_output=True, text=True, timeout=120,
                )
                service_restarted = proc.returncode == 0
                if not service_restarted:
                    service_error = (proc.stderr or proc.stdout).strip()[:300]
            except (OSError, subprocess.TimeoutExpired) as exc:
                service_error = str(exc)[:300]
        else:
            service_error = "Sentinel service not found"

    entry = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "action": "sentinel.push",
        "bundle": str(bundle_path),
        "bundle_sha256": bundle_hash,
        "backup": str(backup) if backup else None,
        "existing_iocs": len(existing),
        "new_iocs": len(new_iocs),
        "merged_iocs": len(merged),
        "min_confidence": min_confidence,
        "reason": reason,
        "service": service,
        "service_restarted": service_restarted,
        "service_error": service_error,
    }
    journal = _journal_path(events_file)
    journal.parent.mkdir(parents=True, exist_ok=True)
    with open(journal, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, separators=(",", ":")) + "\n")

    return {
        "ok": True,
        "dry_run": False,
        **plan,
        "bundle_sha256": bundle_hash,
        "backup": str(backup) if backup else None,
        "journal": str(journal),
        "service": service,
        "service_restarted": service_restarted,
        "service_error": service_error,
    }


def status(sentinel_root: str | Path | None = None,
           events_path: str | Path | None = None) -> dict:
    root = Path(sentinel_root) if sentinel_root else default_root()
    events_file = Path(events_path) if events_path else default_events_path()
    bundle = root / "threatfox-bundle.json.gz"

    detections = 0
    source = root / "events.jsonl"
    if source.exists():
        with open(source, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if str(_get(record, "type", default="")).lower() == "detection":
                    detections += 1

    iocs = read_bundle(bundle)
    by_type: dict[str, int] = {}
    for item in iocs:
        key = str(_get(item, "IocType", default="unknown")).lower()
        by_type[key] = by_type.get(key, 0) + 1

    journal = _journal_path(events_file)
    last = None
    if journal.exists():
        lines = [ln for ln in journal.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
        if lines:
            try:
                last = json.loads(lines[-1])
            except json.JSONDecodeError:
                last = None

    return {
        "sentinel_root": str(root),
        "sentinel_service": _sentinel_service_name(),
        "sentinel_events_log": str(source),
        "sentinel_detections": detections,
        "plasma_events": str(events_file),
        "plasma_events_present": events_file.exists(),
        "bundle": str(bundle),
        "bundle_present": bundle.exists(),
        "bundle_iocs": len(iocs),
        "bundle_by_type": by_type,
        "last_push": last,
    }
