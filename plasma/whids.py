"""Two-way WHIDS integration (replaces the Sentinel adapter).

PULL   WHIDS alerts -> normalized Plasma events
       WHIDS (standalone, local forwarder) writes alert JSONL under
       <root>\\Logs\\Alerts\\**. Each line is an EdrEvent:
         {"Event": {"EventData": {...}, "System": {"EventID":..., "Computer":...}},
          "EdrData": {...},
          "Detection": {"Signature": [...], "Criticality": 0-10,
                        "ATTACK": [{"ID": "T1059.001", ...}], "Actions": [...]}}

PUSH   Plasma intelligence -> WHIDS detection rules
       A gene schema-2.0.0 rule file dropped into <root>\\Database\\Rules\\
       (plasma-iocs.gen). WHIDS compiles gene rules at start; matching
       events raise alerts with our rule signature.

Safety: push is dry-run by default; private/reserved addresses and benign
domains are excluded; the existing rule file is backed up and merged; every
apply is journaled. WHIDS owns response actions (kill/dump/quarantine via
its actionable rules) — Plasma never drives them.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .manifest import sha256_file
from .redact import redact_text

SERVICE_NAME = "Whids"
DEFAULT_MIN_CONFIDENCE = 8
DEFAULT_MAX_INDICATORS = 500

HASH_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
PID_RE = re.compile(r"^(?:0x[0-9A-Fa-f]+|\d+)$")

BENIGN_DOMAIN_SUFFIXES = (
    "microsoft.com", "windows.com", "windowsupdate.com", "office365.com",
    "office.com", "live.com", "bing.com", "google.com", "googleapis.com",
    "gstatic.com", "cloudflare.com", "akamai.net", "amazonaws.com",
    "local", "internal", "corp.local", "localhost",
)


def default_root() -> Path:
    env = os.environ.get("PLASMA_WHIDS_ROOT")
    if env:
        return Path(env)
    base = os.environ.get("ProgramFiles", r"C:\Program Files")
    return Path(base) / "Whids"


def default_events_path() -> Path:
    env = os.environ.get("PLASMA_EVENTS")
    if env:
        return Path(env)
    base = os.environ.get("ProgramData", r"C:\ProgramData")
    return Path(base) / "Plasma" / "data" / "events.jsonl"


def _dig(obj, *names, default=None):
    """Case-insensitive recursive search for the first matching key."""
    if not isinstance(obj, dict):
        return default
    lowered = {str(k).lower(): v for k, v in obj.items()}
    for name in names:
        if name.lower() in lowered and lowered[name.lower()] not in (None, ""):
            return lowered[name.lower()]
    for value in lowered.values():
        if isinstance(value, dict):
            found = _dig(value, *names)
            if found not in (None, ""):
                return found
    return default


def _slug(text: str, limit: int = 64) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", text or "whids").strip("-")
    return slug[:limit] or "whids"


def _parse_pid(value) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text)
    except ValueError:
        return None


def _parse_hashes(value) -> dict[str, str]:
    out = {}
    for part in re.split(r"[,;]", str(value or "")):
        if "=" in part:
            algo, _, digest = part.partition("=")
            digest = digest.strip()
            if HASH_RE.match(digest):
                out[algo.strip().upper()] = digest.lower()
    return out


def _severity(criticality: float) -> str:
    if criticality >= 9:
        return "critical"
    if criticality >= 7:
        return "high"
    if criticality >= 5:
        return "medium"
    return "low"


def _action(actions) -> str:
    actions = actions or []
    lowered = {str(a).lower() for a in actions}
    if "kill" in lowered:
        return "killed"
    if "blacklist" in lowered:
        return "blocked"
    return "logged"


# WHIDS 1.7 alerts carry only Criticality + Signature in GeneInfo — the
# rule's Tags (and therefore its ATT&CK ID) are not propagated. Without this
# map every gene alert landed in the store with technique=None, so coverage,
# chains and fleet could not see the technique (WS2 field finding).
RULE_TECHNIQUES = {
    "Plasma LOLBin Certutil": "T1140",
    "Plasma Office Spawning Shell": "T1566.001",
    "Plasma SAM Hive Dump": "T1003.002",
    "Plasma Bitsadmin Transfer": "T1197",
    "Plasma Mshta Network": "T1218.005",
    "Plasma Rundll32 JS": "T1218.011",
    "Plasma Net Account Add": "T1136.001",
    "Plasma Encoded Cmd": "T1027",
    "Plasma Scheduled Task Create": "T1053.005",
    "Plasma Wmic Process Call": "T1047",
    "Plasma File Delete by LOLBin": "T1070.004",
    "Plasma Run Key Persistence": "T1547.001",
    "Plasma Service Registry Persistence": "T1543.003",
    "Plasma Privileged Group Add": "T1098",
    "Plasma Execution From User Paths": "T1204.002",
}


def _benign_context(rule_name: str, event_data: dict) -> str | None:
    """Positive evidence that a rule fired on expected admin/installer work.

    Suppression is conservative: it requires a Microsoft signature or a
    known Windows installer/service writer. Absence of evidence never
    suppresses. A suppressed alert stays in the store at info/0.2 so the
    history is not lost, but it cannot raise the watch verdict or become an
    IOC.
    """
    rule = str(rule_name or "").lower()
    image_path = str(_get_flat(event_data, "Image", "ProcessName") or "").lower()
    image = _base_name(image_path) or ""
    # Windows service binaries live in System32, but also in ADFS,
    # Microsoft.NET, WinSxS and servicing. Temp/Tasks/Debug are writable
    # staging areas and must never inherit that trust.
    system_binary = image_path.startswith("c:\\windows\\") and not image_path.startswith((
        "c:\\windows\\temp\\", "c:\\windows\\tasks\\",
        "c:\\windows\\debug\\"))
    parent = _base_name(_get_flat(event_data, "ParentImage")) or ""
    parent = parent.lower()
    signed = str(_get_flat(event_data, "Signed") or "").strip().lower()
    company = str(_get_flat(event_data, "Company") or "").strip().lower()
    signature = str(_get_flat(event_data, "Signature") or "").strip().lower()
    user = str(_get_flat(event_data, "User") or "").strip().lower()
    microsoft = ("microsoft" in company or "microsoft" in signature
                 or signed in ("microsoft windows", "microsoft corporation"))

    if "execution from user paths" in rule and microsoft:
        return "Microsoft-signed binary in a user-writable path"
    if "run key persistence" in rule:
        # Only actual installer writers. A Microsoft-signed LOLBin (reg.exe,
        # powershell.exe, sc.exe) writing a Run key is the technique.
        writers = {"msiexec.exe", "trustedinstaller.exe", "services.exe",
                   "setup.exe", "update.exe", "wuauclt.exe",
                   "officeclicktorun.exe", "infdefaultinstall.exe"}
        if image in writers:
            return f"expected installer writer ({image})"
    if "service registry persistence" in rule:
        # Windows' own service binaries (dns.exe, lsass.exe, DFSRs.exe, AD
        # WebServices, ...) update their service keys during normal servicing
        # and produced a storm of criticality-8 false positives on a live
        # server. Suppress only Microsoft-signed non-LOLBins; reg.exe /
        # sc.exe / powershell.exe keep the full score.
        lolbins = {"reg.exe", "sc.exe", "powershell.exe", "pwsh.exe",
                   "cmd.exe", "wmic.exe", "rundll32.exe", "mshta.exe",
                   "certutil.exe", "bitsadmin.exe"}
        if image and image not in lolbins and (microsoft or system_binary):
            return f"Windows service binary updating its service key ({image})"
        writers = {"msiexec.exe", "trustedinstaller.exe", "services.exe",
                   "svchost.exe", "setup.exe", "update.exe", "wuauclt.exe",
                   "officeclicktorun.exe", "infdefaultinstall.exe"}
        if image in writers and image not in lolbins:
            return f"expected installer/service writer ({image})"
    if "scheduled task create" in rule:
        if parent in {"msiexec.exe", "trustedinstaller.exe", "svchost.exe",
                      "setup.exe", "update.exe"}:
            return f"task created by expected installer parent ({parent})"
    if "file delete by lolbin" in rule:
        target = str(_get_flat(event_data, "TargetFilename") or "")
        name = _base_name(target).lower()
        if image == "powershell.exe" and name.startswith("__psscriptpolicytest_"):
            return "PowerShell policy-test scratch file"
    if "encoded cmd" in rule:
        if parent in {"svchost.exe", "taskeng.exe", "taskhostw.exe"} and (
                user in ("system", "nt authority\\system")
                or user.endswith("\\system")):
            return f"SYSTEM-encoded command from {parent}"
    return None


def normalize_alert(alert: dict, host: str | None = None):
    """Convert one WHIDS EdrEvent alert to a Plasma event dict.

    Returns None for non-alert events (no Detection object).
    """
    if not isinstance(alert, dict):
        return None
    # WHIDS v1.7.0 nests match info under Event.GeneInfo; the later rewrite
    # uses Event.Detection. Accept both — same Criticality/Signature keys.
    detection = _dig(alert, "Detection")
    if not isinstance(detection, dict):
        detection = _dig(alert, "GeneInfo")
    if not isinstance(detection, dict):
        return None
    signature = detection.get("Signature") or []
    if isinstance(signature, str):
        signature = [signature]
    rule_name = str(signature[0]) if signature else "WHIDS detection"

    criticality = float(_dig(detection, "Criticality", default=0) or 0)
    actions = _dig(detection, "Actions", default=[]) or []
    attack = _dig(detection, "ATTACK", default=[]) or []
    technique = None
    if isinstance(attack, list):
        for entry in attack:
            if isinstance(entry, dict):
                candidate = str(entry.get("ID") or entry.get("TechniqueId") or "")
            else:
                candidate = str(entry)
            if TECHNIQUE_RE.match(candidate.strip()):
                technique = candidate.strip()
                break
    if technique is None:
        technique = RULE_TECHNIQUES.get(rule_name)

    event_data = _dig(alert, "EventData") or {}
    if not isinstance(event_data, dict):
        event_data = {}
    hashes = {}
    for key in ("Hashes", "ImageHashes", "SourceHashes", "FileHashes"):
        hashes.update(_parse_hashes(_get_flat(event_data, key)))
    file_hash = hashes.get("SHA256")

    ts = _dig(alert, "SystemTime", "TimeCreated", "Timestamp") or ""
    if isinstance(ts, dict):
        ts = ts.get("SystemTime") or ""

    image = _get_flat(event_data, "Image", "ProcessName")
    pid = _parse_pid(_get_flat(event_data, "ProcessId"))
    user = _get_flat(event_data, "User") or _get_flat(event_data, "SubjectUserName")

    event = {
        "ts": ts,
        "host": str(_dig(alert, "Computer", "Hostname", default=host or socket_hostname())),
        "source": "whids",
        "kind": "alert",
        "event_id": int(_dig(alert, "EventID", default=0) or 0),
        "severity": _severity(criticality),
        "user": user,
        "process": _base_name(image),
        "pid": pid,
        "ppid": _parse_pid(_get_flat(event_data, "ParentProcessId")),
        "parent": _base_name(_get_flat(event_data, "ParentImage")),
        "image": image,
        "cmdline": redact_text(_get_flat(event_data, "CommandLine")),
        "dest_ip": _get_flat(event_data, "DestinationIp", "DestinationHostname2"),
        "dest_port": _parse_pid(_get_flat(event_data, "DestinationPort")),
        "dns_query": _get_flat(event_data, "QueryName", "QueryResults"),
        "file_path": _get_flat(event_data, "TargetFilename", "ImageLoaded"),
        "file_hash": file_hash,
        "registry_path": _get_flat(event_data, "TargetObject"),
        "technique": technique,
        "alert_id": _slug(rule_name),
        "score": max(0.0, min(criticality, 10.0)) / 10.0,
        "action": _action(actions),
        "description": ("WHIDS " + " | ".join(str(s) for s in signature))[:2048],
    }
    # Shape-guard optional fields against the strict PlasmaEvent contract.
    if event["dest_ip"] is not None and not re.match(r"^[0-9A-Fa-f:.]{2,45}$", str(event["dest_ip"])):
        event["dest_ip"] = None
    if event["file_hash"] is not None and not HASH_RE.match(str(event["file_hash"])):
        event["file_hash"] = None
    if event["dest_port"] is not None:
        port = event["dest_port"]
        event["dest_port"] = port if 0 <= port <= 65535 else None
    if event["technique"] is not None and not TECHNIQUE_RE.match(event["technique"]):
        event["technique"] = None
    reason = _benign_context(rule_name, event_data)
    if reason:
        event["suppressed"] = reason
        event["score"] = min(float(event.get("score") or 0.2), 0.2)
        event["severity"] = "info"
        event["description"] = (str(event.get("description") or "")
                                + f" [suppressed: {reason}]")[:2048]
    return event


def _base_name(path):
    if path is None:
        return None
    # Windows paths use backslashes; do not rely on the host OS Path rules.
    return str(path).replace("\\", "/").rsplit("/", 1)[-1]


def socket_hostname() -> str:
    try:
        import socket
        return socket.gethostname()
    except Exception:  # noqa: BLE001
        return "unknown"


def _get_flat(obj: dict, *names):
    """Case-insensitive lookup within one dict level only."""
    lowered = {str(k).lower(): v for k, v in obj.items()}
    for name in names:
        if name.lower() in lowered and lowered[name.lower()] not in (None, ""):
            return lowered[name.lower()]
    return None


# ---------------------------------------------------------------------------
# PULL
# ---------------------------------------------------------------------------

def _alert_key(event: dict) -> tuple:
    return (event.get("alert_id"), str(event.get("ts")), event.get("pid"), event.get("process"))


def alert_files(root: str | Path | None = None) -> list[Path]:
    root = Path(root) if root else default_root()
    alerts = root / "Logs" / "Alerts"
    if not alerts.is_dir():
        return []
    # .gz archives are compressed and .old-* trees are archived copies; a
    # text read of them produces garbage lines and inflated counts.
    return sorted(p for p in alerts.rglob("*")
                  if p.is_file() and p.suffix != ".gz"
                  and ".old-" not in str(p))


STORM_THRESHOLD = 25
STORM_SAMPLES = 5


def _storm_key(event: dict) -> tuple:
    return (event.get("alert_id"), event.get("process"), event.get("user"),
            event.get("registry_path") or event.get("file_path")
            or event.get("dns_query") or event.get("dest_ip") or "",
            event.get("image") or "")


def coalesce_storms(events: list[dict], threshold: int = STORM_THRESHOLD,
                    samples: int = STORM_SAMPLES) -> tuple[list[dict], int]:
    """Collapse high-volume identical alerts into a few samples + a summary.

    An agent process repeated the same Tcpip service-key write 17k times in
    two hours. Storing every copy makes the diary unreadable and hides the
    one useful fact: something is doing this in a loop. The summary keeps
    the count, first/last time and incremented score; samples keep evidence.
    """
    groups: dict[tuple, list[dict]] = {}
    order: list[tuple] = []
    for event in events:
        key = _storm_key(event)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(event)
    out: list[dict] = []
    coalesced = 0
    for key in order:
        # Files are scanned by path, not by time; a storm can span rotated
        # logs. Sort before choosing first/last so the window is coherent.
        group = sorted(groups[key], key=lambda e: str(e.get("ts") or ""))
        if len(group) <= threshold:
            out.extend(group)
            continue
        coalesced += 1
        chosen = group[:max(1, samples)]
        if group[-1] not in chosen:
            chosen.append(group[-1])
        out.extend(chosen)
        last = dict(group[-1])
        first = group[0]
        last["ts"] = group[-1].get("ts")
        last["pid"] = None
        last["storm"] = True
        last["storm_count"] = len(group)
        last["storm_first_ts"] = first.get("ts")
        last["score"] = max(float(e.get("score") or 0) for e in group)
        last["severity"] = max(
            (str(e.get("severity") or "info") for e in group),
            key=lambda s: {"info": 0, "low": 1, "medium": 2,
                           "high": 3, "critical": 4}.get(s, 0))
        last["description"] = (
            f"STORM {last.get('alert_id')}: {len(group)} occurrences between "
            f"{first.get('ts')} and {group[-1].get('ts')}; "
            f"{len(chosen)} samples retained")[:2048]
        out.append(last)
    return out, coalesced


def pull(root: str | Path | None = None, out: str | Path | None = None,
         host: str | None = None) -> dict:
    target = Path(out) if out else default_events_path()
    files = alert_files(root)
    if not files:
        return {"error": f"no WHIDS alert logs under: {(Path(root) if root else default_root()) / 'Logs' / 'Alerts'}",
                "written": 0}

    events, skipped = [], 0
    for path in files:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    skipped += 1
                    continue
                event = normalize_alert(record, host=host)
                if event is None:
                    skipped += 1
                    continue
                events.append(event)

    existing_keys = set()
    existing_storms = []
    if target.exists():
        with open(target, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    prior = json.loads(line)
                except json.JSONDecodeError:
                    continue
                existing_keys.add(_alert_key(prior))
                if prior.get("storm_count"):
                    existing_storms.append(prior)

    def _covered(event):
        # A raw event inside an already-summarised storm window is already
        # represented by the summary; do not mint another summary on the
        # next pull just because only samples were stored.
        key = _storm_key(event)
        ts = str(event.get("ts") or "")
        for storm in existing_storms:
            if _storm_key(storm) != key:
                continue
            first = str(storm.get("storm_first_ts") or "")
            last = str(storm.get("ts") or "")
            # Older summaries (1.8.3) could be written inverted because
            # rotated files are scanned by path. Normalise before testing.
            if first > last:
                first, last = last, first
            if first <= ts <= last:
                return True
        return False

    fresh = [e for e in events
             if _alert_key(e) not in existing_keys and not _covered(e)]
    fresh, storm_groups = coalesce_storms(fresh)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "a", encoding="utf-8") as fh:
        for event in fresh:
            fh.write(json.dumps(event, separators=(",", ":"), default=str) + "\n")

    # A pull consumes the on-disk alert backlog; tell watch so the next
    # sweep does not report thousands of "unpulled" rows that are already
    # in the store (the 1.8.x field confusion).
    if target.name == "events.jsonl" and target.parent.name == "data":
        try:
            count = 0
            for f in alert_files(root):
                if f.is_file():
                    count += sum(1 for ln in f.read_text(
                        encoding="utf-8", errors="replace").splitlines()
                        if ln.strip().startswith("{"))
            state_path = target.parent.parent / "watch-alerts-state.json"
            state_path.write_text(json.dumps({"seen_alert_rows": count}) + "\n",
                                  encoding="utf-8")
        except OSError:
            pass
    return {
        "alert_files": len(files),
        "out": str(target),
        "alerts": len(events),
        "skipped_records": skipped,
        "already_present": len(events) - len(fresh),
        "storm_groups": storm_groups,
        "written": len(fresh),
    }


# ---------------------------------------------------------------------------
# PUSH — generate a gene schema-2.0.0 IOC rule for WHIDS
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
    """Plasma score (0-1) or severity -> WHIDS criticality (0-10)."""
    if row.get("score") is not None:
        try:
            return max(0, min(10, int(round(float(row["score"]) * 10))))
        except (TypeError, ValueError):
            pass
    return {"critical": 9, "high": 8, "medium": 6}.get(row.get("severity"), 4)


def extract_indicators(rows, min_confidence: int = DEFAULT_MIN_CONFIDENCE) -> list[dict]:
    """Select high-confidence indicators from normalized Plasma events.

    min_confidence is on the WHIDS 0-10 criticality scale.
    """
    found: dict[str, dict] = {}

    def add(indicator, ioc_type, criticality, family):
        if indicator is None:
            return
        indicator = str(indicator).strip()
        if not indicator or indicator.lower() in ("none", "null"):
            return
        if ioc_type == "ip" and not _is_public_ip(indicator):
            return
        if ioc_type == "domain":
            indicator = indicator.lower().rstrip(".")
            if not re.fullmatch(r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?", indicator) \
                    or ".." in indicator:
                return
            if _is_benign_domain(indicator):
                return
        if ioc_type == "sha256" and not HASH_RE.match(indicator):
            return
        if criticality < min_confidence:
            return
        key = indicator.lower()
        candidate = {
            "indicator": indicator,
            "ioc_type": ioc_type,
            "criticality": int(criticality),
            "family": family,
        }
        prior = found.get(key)
        if prior is None or candidate["criticality"] > prior["criticality"]:
            found[key] = candidate

    for row in rows:
        criticality = _row_score(row)
        if criticality < min_confidence:
            continue
        family = row.get("technique") or row.get("alert_id")
        add(row.get("file_hash"), "sha256", criticality, family)
        add(row.get("dns_query"), "domain", criticality, family)
        add(row.get("dest_ip"), "ip", criticality, family)

    out = []
    for item in found.values():
        item["family"] = str(item["family"] or "unknown")
        out.append(item)
    return sorted(out, key=lambda i: (-i["criticality"], i["indicator"].lower()))


def build_gene_rule(indicators: list[dict]) -> dict:
    """Build a gene schema-1.0.0 rule from Plasma indicators.

    Schema 1.0.0 is what WHIDS v1.7.0's engine (gene v1.6.10) compiles:
    Meta.EventIDs (list, not the 2.0 Events{channel: ids} map), equality
    via a single '=', regex via '~=' with /.../ delimiters and single-quoted
    regex bodies. Field names are bare Sysmon fields (gene prepends
    EventData). Rules carry no action semantics: v1.7.0 has no action
    system, and later schemas must never auto-arm one from a pushed IOC.
    """
    matches, conditions = [], []
    index = 0

    def add(expr):
        nonlocal index
        label = f"$plasma{index}"
        matches.append(f"{label}: {expr}")
        conditions.append(label)
        index += 1

    for ioc in indicators:
        value = ioc["indicator"]
        if ioc["ioc_type"] == "sha256":
            add(f"Hashes ~= '(?i)sha256={value}'")
            add(f"ImageHashes ~= '(?i)sha256={value}'")
        elif ioc["ioc_type"] == "domain":
            escaped = re.escape(value)
            add(f"QueryName ~= '(?i)^{escaped}$'")
        else:
            add(f"DestinationIp = '{value}'")

    tags = ["Plasma", "IOC"]
    techniques = sorted({i["family"] for i in indicators
                         if i["family"] and TECHNIQUE_RE.match(str(i["family"]))})
    tags.extend(techniques[:5])

    return {
        "Name": "Plasma IOC Feed",
        "Tags": tags,
        "Meta": {
            "EventIDs": [1, 3, 6, 7, 15, 22],
            "Channels": ["Microsoft-Windows-Sysmon/Operational"],
            "Computers": [],
            "Criticality": 9,
            "Author": "Plasma",
            "Comment": "Indicators pushed by 'plasma whids push'. Regenerated on every apply.",
            "Schema": "1.0.0",
        },
        "Matches": matches,
        "Condition": " or ".join(conditions),
    }


def read_rules(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def merge_rules(existing: dict | None, rule: dict) -> dict:
    if not existing or existing.get("Name") != rule.get("Name"):
        return rule
    merged_exprs = []
    seen = set()
    for expr in (existing.get("Matches") or []) + (rule.get("Matches") or []):
        if expr not in seen:
            seen.add(expr)
            merged_exprs.append(expr)
    rule = json.loads(json.dumps(rule))  # deep copy
    rule["Matches"] = merged_exprs
    rule["Condition"] = " or ".join(f"$plasma{i}" for i in range(len(merged_exprs)))
    # Rebuild labels to match the condition ordering.
    rule["Matches"] = [
        re.sub(r"^\$plasma\d+:", f"$plasma{i}:", expr)
        for i, expr in enumerate(merged_exprs)
    ]
    return rule


def write_rules(path: Path, rule: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(rule, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _journal_path(events_path: Path) -> Path:
    return events_path.parent / "whids-intel-journal.jsonl"


def _whids_service_name() -> str | None:
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             "Get-Service | Where-Object { $_.Name -like 'Whids*' } | "
             "Select-Object -First 1 -ExpandProperty Name"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20,
        )
        return proc.stdout.strip() or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _service_state(name: str | None = None) -> str:
    """Current SCM state as a plain string ('' when the service is absent)."""
    name = name or _whids_service_name() or SERVICE_NAME
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
             f"(Get-Service -Name '{name}' -ErrorAction SilentlyContinue).Status"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
        return (proc.stdout or "").strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _ps(script: str, timeout: int = 60) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout)
        return proc.returncode, (proc.stdout or "").strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)[:200]


def _watchdog_log(root, result: dict) -> None:
    try:
        base = (Path(root) if root else
                Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Plasma")
        log = base / "logs" / "whids-watchdog.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(result, sort_keys=True) + "\n")
    except OSError:
        pass


def prune_dumps(install_dir=None, max_mb: int = 512, keep_days: int = 7,
                dry_run: bool = False, max_files: int = 20000,
                archive_dir=None) -> dict:
    """Bound the WHIDS dump tree.

    WHIDS 1.7.0's ``max-dumps`` is per-GUID, not global. A noisy host grew
    145k files / 2.3 GB, after which startup exceeded the SCM 30s limit and
    the service stopped responding. Detect-only Plasma has no use for dumps,
    so the shipped config disables hooks; this is the cleanup/backstop for
    nodes that already have a tree (and for any future hook use).
    """
    import os
    import time

    base = Path(install_dir) if install_dir else Path(
        os.environ.get("ProgramFiles", r"C:\Program Files")) / "Whids"
    dumps = base / "Dumps"
    archive_root = Path(archive_dir) if archive_dir else Path(
        os.environ.get("ProgramData", r"C:\ProgramData")) / "Plasma" / "whids-archive"
    moved = []

    def _move_out(directory: Path, label: str) -> None:
        """Rename a legacy tree OUT of the install directory.

        WHIDS resets ACLs on its whole install tree at startup; a tree with
        tens of thousands of files makes that exceed the SCM 30-45s start
        timeout. Moving a directory on the same volume is instant.
        """
        if not directory.is_dir():
            return
        try:
            archive_root.mkdir(parents=True, exist_ok=True)
            dest = archive_root / f"{label}-{int(time.time())}"
            __import__("shutil").move(str(directory), str(dest))
            moved.append({"from": str(directory), "to": str(dest)})
        except Exception:
            return

    # Legacy trees from older configs always live inside the install dir.
    for legacy in base.glob("Dumps.pruned-*"):
        _move_out(legacy, "Dumps-legacy")
    for legacy in base.glob("Dumps.old-*"):
        _move_out(legacy, "Dumps-legacy")

    if not dumps.is_dir():
        return {"dumps_dir": str(dumps), "removed_files": 0,
                "removed_bytes": 0, "remaining_files": 0,
                "remaining_bytes": 0, "skipped": 0, "moved_dirs": moved}

    limit = max(0, int(max_mb)) * 1024 * 1024
    cutoff = time.time() - max(0, int(keep_days)) * 86400
    entries = []
    skipped = 0
    try:
        for path in dumps.rglob("*"):
            if len(entries) >= 250000:      # hard scan bound
                break
            if not path.is_file():
                continue
            try:
                stat = path.stat()
            except OSError:
                skipped += 1
                continue
            entries.append((stat.st_mtime, stat.st_size, path))
    except OSError as exc:
        return {"error": f"cannot scan dumps: {exc}", "dumps_dir": str(dumps)}
    entries.sort(key=lambda e: e[0])        # oldest first
    total = sum(e[1] for e in entries)
    if not dry_run and (len(entries) > max_files or total > max_mb * 1024 * 1024 * 4):
        # Too large to prune file-by-file before the next service start:
        # move the whole tree out of the ACL-reset path in one operation.
        _move_out(dumps, "Dumps")
        if any(m.get("from") == str(dumps) for m in moved):
            dumps.mkdir(parents=True, exist_ok=True)
            return {"dumps_dir": str(dumps), "removed_files": 0,
                    "removed_bytes": 0, "remaining_files": 0,
                    "remaining_bytes": 0, "skipped": skipped,
                    "moved_dirs": moved, "max_mb": int(max_mb),
                    "keep_days": int(keep_days), "dry_run": False}
        # The move failed (e.g. an open handle): fall through to bounded
        # per-file removal instead of claiming the tree is gone.
    removed_files = removed_bytes = 0
    for mtime, size, path in entries:
        if total <= limit and mtime >= cutoff:
            break
        if dry_run:
            removed_files += 1
            removed_bytes += size
            total -= size
            continue
        try:
            path.unlink()
        except OSError:
            skipped += 1
            continue
        removed_files += 1
        removed_bytes += size
        total -= size
    return {
        "dumps_dir": str(dumps),
        "removed_files": removed_files,
        "removed_bytes": removed_bytes,
        "remaining_files": max(0, len(entries) - removed_files),
        "remaining_bytes": max(0, total),
        "skipped": skipped,
        "moved_dirs": moved,
        "dry_run": bool(dry_run),
        "max_mb": int(max_mb),
        "keep_days": int(keep_days),
    }


def ensure(root=None, wait_seconds: int = 30) -> dict:
    """Make the WHIDS service Running, healing the 1.7.0 init hang.

    WHIDS 1.7.0 can sit in StartPending forever (or stop after a manual
    restart). A hung StartPending never responds to Start-Service, so the
    only reliable recovery is force-stop then start. This is the body of
    the `PlasmaWhidsWatchdog` scheduled task the installer registers.
    """
    import time
    name = _whids_service_name() or SERVICE_NAME
    actions: list[dict] = []
    state = _service_state(name)
    if state == "Running":
        return {"ok": True, "service": name, "state": state, "actions": actions}

    pending = ("StartPending", "Stopping", "Unknown", "")
    if state in pending:
        deadline = time.time() + wait_seconds
        while state in pending and time.time() < deadline:
            time.sleep(3)
            state = _service_state(name)

    if state != "Running":
        # A pathological dump tree can be the reason startup exceeds the
        # SCM timeout; bound it before attempting the restart.
        pruned = prune_dumps()
        if pruned.get("removed_files") or pruned.get("moved_dirs"):
            actions.append({"action": "prune_dumps",
                            "removed_files": pruned.get("removed_files", 0),
                            "removed_mb": round(pruned.get("removed_bytes", 0) / (1024 * 1024), 1),
                            "moved_dirs": len(pruned.get("moved_dirs") or [])})
        rc, _ = _ps(f"Stop-Service -Name '{name}' -Force -ErrorAction SilentlyContinue")
        actions.append({"action": "stop", "rc": rc})
        time.sleep(2)
        rc, _ = _ps(f"Start-Service -Name '{name}' -ErrorAction SilentlyContinue")
        actions.append({"action": "start", "rc": rc})
        deadline = time.time() + wait_seconds
        state = _service_state(name)
        while state in pending and time.time() < deadline:
            time.sleep(3)
            state = _service_state(name)
        if state != "Running" and state in pending:
            # Stop-Service can return 0 while the process remains wedged
            # (StartPending is NOT_STOPPABLE). The SCM cannot kill it, so
            # terminate the orphan directly and try one clean start.
            rc_kill, _ = _ps(
                "$p = Get-Process -Name 'whids' -ErrorAction SilentlyContinue; "
                "if ($p) { $p | Stop-Process -Force; 'killed' } else { 'no process' }")
            actions.append({"action": "force_kill_orphan", "rc": rc_kill})
            time.sleep(2)
            rc, _ = _ps(f"Start-Service -Name '{name}' -ErrorAction SilentlyContinue")
            actions.append({"action": "start_retry", "rc": rc})
            deadline = time.time() + wait_seconds
            state = _service_state(name)
            while state in pending and time.time() < deadline:
                time.sleep(3)
                state = _service_state(name)

    result = {"ok": state == "Running", "service": name, "state": state,
              "actions": actions,
              "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if actions:
        _watchdog_log(root, result)
    return result


RULE_FILES = ("plasma-iocs.gen", "plasma-baseline.gen")


def deploy_rules(src_dir, rules_db) -> list[str]:
    """Copy every shipped gene-rule file into WHIDS's rules database.

    The baseline rules are the detection content; shipping only the IOC file
    left live nodes running 1-2 rules instead of the full set (field-found).
    """
    src_dir, rules_db = Path(src_dir), Path(rules_db)
    rules_db.mkdir(parents=True, exist_ok=True)
    # Gene loads every *.gen in the directory, including the timestamped
    # backups left by older `push` runs. On WS1 that meant an obsolete rule
    # set was loaded alongside the current one; drop the backups.
    for stale in rules_db.glob("*.bak.gen"):
        try:
            stale.unlink()
        except OSError:
            pass
    copied = []
    for name in RULE_FILES:
        # The builder stages shared rule files at sensors/ and the WHIDS
        # payload at sensors/whids/, so look one level up as well (v1.5.1
        # only ever found the IOC file and baseline never shipped).
        src = next((p for p in (src_dir / name, src_dir.parent / name)
                    if p.exists()), None)
        if src is not None:
            shutil.copy2(src, rules_db / name)
            copied.append(name)
    return copied


def diagnose(root: str | Path | None = None) -> dict:
    """Explain why WHIDS is not Running — the field init-hang triage.

    Read-only. Gathers service state/start mode/path, channel readability,
    recent Service Control Manager errors and the last lines of whids.log,
    then states the most likely cause. Data, never a guess at a fix."""
    whids_root = Path(root) if root else default_root()
    service = _whids_service_name()
    info: dict = {
        "whids_root": str(whids_root),
        "service": service,
        "service_state": None,
        "start_mode": None,
        "binary_path": None,
        "install_dir": str(whids_root),
        "binary_present": False,
        "config_present": (whids_root / "config.toml").exists(),
        "channels": [],
        "service_errors": [],
        "log_tail": [],
        "findings": [],
    }

    if service:
        script = (
            "$ErrorActionPreference='SilentlyContinue';"
            f"$s = Get-CimInstance Win32_Service -Filter \"Name='{service}'\";"
            "$out = @{};"
            "$out.state = $s.State; $out.startMode = $s.StartMode;"
            "$out.pathName = $s.PathName;"
            "$out.hang = ($s.State -eq 'StartPending');"
            "$out.channels = @(Get-WinEvent -ListLog "
            "'Microsoft-Windows-Sysmon/Operational',"
            "'Microsoft-Windows-PowerShell/Operational','Security','System' | "
            "ForEach-Object { @{ log=$_.LogName; enabled=$_.IsEnabled; "
            "records=$_.RecordCount } });"
            "$out.serviceErrors = @(Get-WinEvent -FilterHashtable "
            "@{LogName='System'; Id=7000,7009,7011,7031,7034; "
            "StartTime=(Get-Date).AddHours(-24)} | Select-Object -First 5 | "
            "ForEach-Object { $_.TimeCreated.ToString('o') + ' id=' + $_.Id + ': ' + "
            "($_.Message -replace '\\s+',' ') });"
            "$out | ConvertTo-Json -Depth 4 -Compress"
        )
        try:
            proc = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=60)
            text = (proc.stdout or "").strip()
            parsed = json.loads(text[text.find("{"):]) if "{" in text else {}
            info["service_state"] = parsed.get("state")
            info["start_mode"] = parsed.get("startMode")
            info["binary_path"] = parsed.get("pathName")
            info["channels"] = parsed.get("channels") or []
            info["service_errors"] = parsed.get("serviceErrors") or []
            if parsed.get("hang"):
                info["findings"].append(
                    "service is StartPending — hung at init, not starting slowly")
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            info["findings"].append(f"service probe failed: {str(exc)[:160]}")

    install_dir = whids_root
    if info["binary_path"]:
        raw = info["binary_path"].strip()
        exe = raw.split('"')[1] if raw.startswith('"') else raw.split()[0]
        exe_path = Path(exe)
        info["binary_present"] = exe_path.exists()
        if exe_path.parent:
            install_dir = exe_path.parent
            info["install_dir"] = str(install_dir)

    # On an installed node the config and logs live next to the service
    # binary (C:\Program Files\Whids); on a dev checkout they may sit under
    # the given root. Report whichever actually exists.
    info["config_present"] = ((install_dir / "config.toml").exists()
                              or (whids_root / "config.toml").exists())
    log = install_dir / "Logs" / "whids.log"
    if not log.exists():
        log = whids_root / "Logs" / "whids.log"
    if log.exists():
        lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
        info["log_tail"] = lines[-30:]

    if not info["config_present"]:
        info["findings"].append(
            "config.toml missing — v1.7.0 loads config.toml next to the binary")
    if info["binary_path"] and not info["binary_present"]:
        info["findings"].append("service binary path does not exist")
    unreadable = [c.get("log") for c in info["channels"]
                  if isinstance(c, dict) and not c.get("enabled")]
    if unreadable:
        info["findings"].append(
            "disabled/unreadable channels: " + ", ".join(str(c) for c in unreadable))
    if info.get("service_state") == "StartPending":
        info["findings"].append(
            "known field issue: WHIDS 1.7.0 can hang subscribing to channels; "
            "use the explicit channel list shipped in whids.toml and reinstall")
    # Watchdog task: the permanent answer to the init hang.
    rc, task_out = _ps("schtasks /query /tn PlasmaWhidsWatchdog /fo LIST", timeout=30)
    info["watchdog"] = {"task": "PlasmaWhidsWatchdog", "present": rc == 0,
                        "detail": task_out[:200] if rc == 0 else None}
    if rc != 0:
        info["findings"].append(
            "watchdog task missing — reinstall to register PlasmaWhidsWatchdog")
    if not info["findings"]:
        info["findings"].append("no obvious cause found — attach the log tail to an issue")
    return info


def push(events_path: str | Path | None = None, root: str | Path | None = None,
         min_confidence: int = DEFAULT_MIN_CONFIDENCE, max_indicators: int = DEFAULT_MAX_INDICATORS,
         apply: bool = False, restart_service: bool = False, reason: str = "") -> dict:
    events_file = Path(events_path) if events_path else default_events_path()
    whids_root = Path(root) if root else default_root()
    rules_path = whids_root / "Database" / "Rules" / "plasma-iocs.gen"

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

    indicators = extract_indicators(rows, min_confidence=min_confidence)[:max_indicators]
    # Plasma owns plasma-iocs.gen: the rule is regenerated from the full
    # events store on every push, so it REPLACES the file (with backup).
    # Merging a seed of a different gene schema produced duplicate-rule
    # load failures on endpoints (WS1, 2026-10).
    rule = build_gene_rule(indicators)

    plan = {
        "events_file": str(events_file),
        "rules_file": str(rules_path),
        "min_confidence": min_confidence,
        "max_indicators": max_indicators,
        "indicators": len(indicators),
        "expressions": len(rule.get("Matches") or []),
        "sample": indicators[:10],
        "apply": bool(apply),
    }

    if not apply:
        return {"ok": True, "dry_run": True, **plan}

    rules_path.parent.mkdir(parents=True, exist_ok=True)
    backup = None
    if rules_path.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = rules_path.with_name(f"plasma-iocs.{stamp}.bak.gen")
        backup.write_text(rules_path.read_text(encoding="utf-8"), encoding="utf-8")

    write_rules(rules_path, rule)
    rules_hash = hashlib.sha256(rules_path.read_bytes()).hexdigest()

    service_restarted = False
    service_error = None
    service = _whids_service_name()
    if restart_service:
        if service:
            try:
                proc = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-Command",
                     f"Restart-Service -Name '{service}' -Force"],
                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
                )
                service_restarted = proc.returncode == 0
                if not service_restarted:
                    service_error = (proc.stderr or proc.stdout).strip()[:300]
            except (OSError, subprocess.TimeoutExpired) as exc:
                service_error = str(exc)[:300]
        else:
            service_error = "WHIDS service not found"

    entry = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "action": "whids.push",
        "rules_file": str(rules_path),
        "rules_sha256": rules_hash,
        "backup": str(backup) if backup else None,
        "indicators": len(indicators),
        "expressions": len(rule.get("Matches") or []),
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
        "rules_sha256": rules_hash,
        "backup": str(backup) if backup else None,
        "journal": str(journal),
        "service": service,
        "service_restarted": service_restarted,
        "service_error": service_error,
    }


def status(root: str | Path | None = None, events_path: str | Path | None = None) -> dict:
    whids_root = Path(root) if root else default_root()
    events_file = Path(events_path) if events_path else default_events_path()
    alerts = alert_files(whids_root)
    alert_count = 0
    for path in alerts:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                # v1.7.0 nests match info under GeneInfo; later lines use Detection
                if line and ('"Detection"' in line or '"GeneInfo"' in line):
                    alert_count += 1

    rules_file = whids_root / "Database" / "Rules" / "plasma-iocs.gen"
    rules = read_rules(rules_file)

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
        "whids_root": str(whids_root),
        "whids_service": _whids_service_name(),
        "whids_alert_files": len(alerts),
        "whids_alerts": alert_count,
        "plasma_events": str(events_file),
        "plasma_events_present": events_file.exists(),
        "rules_file": str(rules_file),
        "rules_present": rules_file.exists(),
        "rules_expressions": len((rules or {}).get("Matches") or []),
        "last_push": last,
    }
