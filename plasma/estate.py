"""Estate edge ledger: compact, continuously mergeable cross-host identity.

Each endpoint reduces a bounded window of its own store into counts: who was
seen, from where, with which process and file hash. It ships counts, not
events. The desk pulls those small ledgers, replaces the host's previous
ledger, merges them into one estate ledger and answers the questions a single
box cannot: one account on fifty hosts, one source address across a subnet,
a host that stopped reporting.

The ledger is deliberately lossy. It never contains command lines, file
paths, destination addresses outside the identity edge, or raw rows.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .query import _load_rows

SCHEMA = 1
DEFAULT_WINDOW_MINUTES = 60
DEFAULT_MAX_ROWS = 20000
DEFAULT_THRESHOLD = 5
DEFAULT_MAX_AGE_MINUTES = 180
DEFAULT_MAX_IDENTITY_AGE_MINUTES = 180
MAX_USERS = 200
MAX_SOURCES = 10
MAX_PROCESSES = 200
MAX_HASHES = 100
MAX_LEDGER_BYTES = 262144
ESTATE_MAX_USERS = 5000
ESTATE_MAX_PROCESSES = 5000
ESTATE_MAX_HASHES = 5000
ESTATE_MAX_HASH_HOST_PAIRS = 20000

# Audit IDs that make a row part of the identity feed. The identity collector
# normalises most of these to kind="auth"; the ID set also catches imported
# rows from other sources.
AUTH_IDS = frozenset({
    4624, 4625, 4648, 4662, 4672, 4720, 4722, 4724, 4725, 4726, 4728,
    4732, 4738, 4740, 4756, 4767, 4768, 4769, 4770, 4771, 4776,
})
KERBEROS_IDS = frozenset({4768, 4769, 4770, 4771})
MAX_KINDS = 8
DC_ROLES = frozenset({"dc", "domain-controller", "domain_controller", "kdc"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _stamp(value) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _user(value) -> str | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    account = text.replace("\\", "/").split("/")[-1].split("@")[0]
    if not account or account.endswith("$") or account in (
            "system", "local service", "network service", "-"):
        return None
    return account


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _digest(body: dict) -> str:
    return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()


def sign_ledger(ledger: dict) -> dict:
    body = {key: value for key, value in ledger.items() if key != "integrity"}
    ledger["integrity"] = {"sha256": _digest(body)}
    return ledger


def verify_ledger(ledger: dict) -> dict:
    stored = (ledger.get("integrity") or {}).get("sha256")
    if not stored:
        return {"ok": False, "reason": "ledger has no integrity hash"}
    expected = _digest({key: value for key, value in ledger.items()
                        if key != "integrity"})
    return {"ok": stored == expected, "expected": expected, "stored": stored,
            "reason": None if stored == expected else "integrity mismatch"}


def _table(value) -> dict:
    """A dict view of an untrusted JSON field, or an empty dict."""
    return value if isinstance(value, dict) else {}


def _top(counter: Counter, limit: int) -> dict:
    return dict(sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:limit])


def _identity_pull(events_path) -> dict | None:
    """Read the sidecar written by the last identity pull, if any."""
    path = Path(events_path).parent / "identity-pull.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    error = data.get("error")
    return {
        "ts": data.get("ts"),
        "ok": bool(data["ok"]) if "ok" in data else not bool(error),
        "events_seen": int(data.get("events_seen") or 0),
        "written": int(data.get("written") or 0),
        "error": str(error)[:300] if error else None,
    }


def build(events_path, host: str | None = None, role: str = "member",
          window_minutes: int = DEFAULT_WINDOW_MINUTES,
          max_rows: int = DEFAULT_MAX_ROWS) -> dict:
    """Reduce one host's recent store to a compact identity ledger."""
    window = max(1, min(int(window_minutes), 1440))
    if not Path(events_path).exists():
        raise FileNotFoundError(f"events not found: {events_path}")
    rows = _load_rows(events_path, max_rows=max(1, int(max_rows)))
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=window)
    users: dict[str, dict] = {}
    processes: Counter = Counter()
    hashes: Counter = Counter()
    kinds: Counter = Counter()
    identity_events = 0
    kerberos_events = 0
    last_identity = None
    last_event = None
    identity_before_window = False
    used = 0
    for row in rows:
        stamp = _stamp(row.get("ts"))
        if stamp is None:
            continue
        kind = str(row.get("kind") or "unknown").strip().lower() or "unknown"
        try:
            event_id = int(row.get("event_id") or 0)
        except (TypeError, ValueError):
            event_id = 0
        is_identity = kind == "auth" or event_id in AUTH_IDS
        if stamp < start:
            if is_identity:
                identity_before_window = True
            continue
        used += 1
        last_event = stamp if last_event is None else max(last_event, stamp)
        kinds[kind] += 1
        if is_identity:
            identity_events += 1
            last_identity = (stamp if last_identity is None
                             else max(last_identity, stamp))
            if event_id in KERBEROS_IDS:
                kerberos_events += 1
        user = _user(row.get("user"))
        if not user:
            continue
        entry = users.setdefault(user, {
            "count": 0, "first": None, "last": None,
            "sources": Counter(), "logon_types": Counter(),
        })
        entry["count"] += 1
        entry["first"] = stamp if entry["first"] is None else min(entry["first"], stamp)
        entry["last"] = stamp if entry["last"] is None else max(entry["last"], stamp)
        source = str(row.get("dest_ip") or "").strip()
        if source:
            entry["sources"][source[:45]] += 1
        description = str(row.get("description") or "")
        if "type=" in description:
            token = description.split("type=", 1)[1][:2]
            if token.isdigit():
                entry["logon_types"][token] += 1
        process = str(row.get("process") or "").strip().lower()
        if process:
            processes[f"{user}>{process}"] += 1
        file_hash = str(row.get("file_hash") or "").strip().lower()
        if file_hash:
            hashes[file_hash] += 1

    ordered = sorted(users.items(), key=lambda item: (-item[1]["count"],
                                                      item[0]))[:MAX_USERS]
    rendered = {}
    for user, entry in ordered:
        rendered[user] = {
            "count": entry["count"],
            "first": entry["first"].isoformat().replace("+00:00", "Z"),
            "last": entry["last"].isoformat().replace("+00:00", "Z"),
            "sources": _top(entry["sources"], MAX_SOURCES),
            "logon_types": dict(entry["logon_types"]),
        }
    ledger = {
        "schema": SCHEMA,
        "kind": "host-edge-ledger",
        "host": str(host or socket.gethostname()),
        "role": str(role or "member"),
        "generated_at": end.isoformat().replace("+00:00", "Z"),
        "window": {"minutes": window,
                   "start": start.isoformat().replace("+00:00", "Z"),
                   "end": end.isoformat().replace("+00:00", "Z")},
        "n": used,
        "users": rendered,
        "processes": _top(processes, MAX_PROCESSES),
        "hashes": _top(hashes, MAX_HASHES),
        "truncated": {
            "users": max(0, len(users) - len(rendered)),
            "processes": max(0, len(processes) - MAX_PROCESSES),
            "hashes": max(0, len(hashes) - MAX_HASHES),
        },
        "coverage": {
            "rows": used,
            "identity_events": identity_events,
            "kerberos_events": kerberos_events,
            "last_event": (last_event.isoformat().replace("+00:00", "Z")
                           if last_event else None),
            "last_identity_event": (last_identity.isoformat().replace(
                "+00:00", "Z") if last_identity else None),
            "kinds": _top(kinds, MAX_KINDS),
            "identity_before_window": identity_before_window,
            "identity_pull": _identity_pull(events_path),
        },
    }
    ledger = sign_ledger(ledger)
    blob = len(json.dumps(ledger, separators=(",", ":")))
    if blob > MAX_LEDGER_BYTES:
        # Keep the identity spine; shed the optional heavy tables first.
        ledger["hashes"] = {}
        ledger["processes"] = _top(Counter(ledger["processes"]), 50)
        ledger["size_after_trim"] = len(
            json.dumps(ledger, separators=(",", ":")))
        ledger = sign_ledger(ledger)
    return ledger


def load(path) -> dict:
    ledger = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(ledger, dict):
        raise TypeError("ledger must be a JSON object")
    if int(ledger.get("schema") or 0) != SCHEMA:
        raise ValueError(f"unsupported ledger schema {ledger.get('schema')!r}")
    verdict = verify_ledger(ledger)
    if not verdict.get("ok"):
        raise ValueError(verdict.get("reason") or "ledger integrity failed")
    return ledger


def save(path, ledger: dict) -> dict:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    signed = sign_ledger({key: value for key, value in ledger.items()
                          if key != "integrity"})
    tmp = target.with_name(f"{target.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(signed, indent=1, sort_keys=True) + "\n",
                   encoding="utf-8")
    os.replace(tmp, target)
    return {"ok": True, "ledger": str(target),
            "bytes": target.stat().st_size, "host": signed.get("host")}


def merge(ledgers: list[dict], max_age_minutes: int = DEFAULT_MAX_AGE_MINUTES,
          now: datetime | None = None) -> dict:
    """Merge host ledgers into one estate ledger, replacing older copies."""
    if not ledgers:
        raise ValueError("no ledgers to merge")
    now = now or datetime.now(timezone.utc)
    by_host: dict[str, dict] = {}
    for ledger in ledgers:
        host = str(ledger.get("host") or "").strip()
        if not host:
            raise ValueError("ledger has no host")
        existing = by_host.get(host)
        if existing is None or str(ledger.get("generated_at") or "") >= str(
                existing.get("generated_at") or ""):
            by_host[host] = ledger
    users: dict[str, dict] = {}
    processes: Counter = Counter()
    hashes: Counter = Counter()
    hash_hosts: dict[str, set] = defaultdict(set)
    hosts = {}
    window = 0
    max_age = max(1, int(max_age_minutes))
    for host, ledger in by_host.items():
        generated = _stamp(ledger.get("generated_at"))
        stale = generated is None or (now - generated) > timedelta(
            minutes=max_age)
        hosts[host] = {
            "role": ledger.get("role", "member"),
            "generated_at": ledger.get("generated_at"),
            "n": int(ledger.get("n") or 0),
            "users": len(ledger.get("users") or {}),
            "stale": bool(stale),
            "coverage": ledger.get("coverage") or {},
        }
        window = max(window, int((ledger.get("window") or {}).get("minutes") or 0))
        for user, entry in _table(ledger.get("users")).items():
            if not isinstance(entry, dict):
                continue
            target = users.setdefault(user, {"total": 0, "hosts": {}})
            target["total"] += int(entry.get("count") or 0)
            target["hosts"][host] = {
                "count": int(entry.get("count") or 0),
                "first": entry.get("first"),
                "last": entry.get("last"),
                "sources": dict(_table(entry.get("sources"))),
                "logon_types": dict(_table(entry.get("logon_types"))),
            }
        for key, count in _table(ledger.get("processes")).items():
            processes[key] += int(count or 0)
        for key, count in _table(ledger.get("hashes")).items():
            hashes[key] += int(count or 0)
            hash_hosts[key].add(host)
    ordered_users = dict(sorted(users.items(), key=lambda item: (
        -len(item[1]["hosts"]), -item[1]["total"], item[0]))[:ESTATE_MAX_USERS])
    shared_candidates = sorted(
        ((key, seen_on) for key, seen_on in hash_hosts.items() if len(seen_on) >= 2),
        key=lambda item: (-len(item[1]), item[0]))
    shared_hashes = {}
    pairs = 0
    for key, seen_on in shared_candidates:
        if len(shared_hashes) >= ESTATE_MAX_HASHES or \
                pairs + len(seen_on) > ESTATE_MAX_HASH_HOST_PAIRS:
            break
        shared_hashes[key] = sorted(seen_on)
        pairs += len(shared_hashes[key])
    estate = {
        "schema": SCHEMA,
        "kind": "estate-edge-ledger",
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "window_minutes": window,
        "hosts": hosts,
        "users": ordered_users,
        "processes": _top(processes, ESTATE_MAX_PROCESSES),
        "hashes": _top(hashes, ESTATE_MAX_HASHES),
        "hash_hosts": shared_hashes,
        "truncated": {
            "users": max(0, len(users) - len(ordered_users)),
            "hash_hosts": max(0, len(shared_candidates) - len(shared_hashes)),
        },
    }
    return sign_ledger(estate)


def _hosts_view(estate: dict) -> dict:
    """Hosts map for a merged estate ledger or a single host ledger."""
    hosts = estate.get("hosts")
    if hosts:
        return hosts
    if estate.get("kind") == "host-edge-ledger":
        host = str(estate.get("host") or "local")
        return {host: {
            "role": estate.get("role", "member"),
            "generated_at": estate.get("generated_at"),
            "n": int(estate.get("n") or 0),
            "users": len(estate.get("users") or {}),
            "stale": False,
            "coverage": estate.get("coverage") or {},
        }}
    return {}


def _coverage_findings(hosts: dict, now: datetime,
                       max_identity_age_minutes: int) -> list[dict]:
    """Distinguish "nothing happened" from "the identity feed was blind"."""
    found = []
    max_age = max(1, int(max_identity_age_minutes))
    for host, details in hosts.items():
        if details.get("stale"):
            continue
        coverage = details.get("coverage")
        if not isinstance(coverage, dict) or not coverage:
            continue
        pull = coverage.get("identity_pull")
        if not isinstance(pull, dict):
            pull = {}
        rows = int(coverage.get("rows") or 0)
        identity = int(coverage.get("identity_events") or 0)
        kerberos = int(coverage.get("kerberos_events") or 0)
        role = str(details.get("role") or "").lower()
        if pull.get("ok") is False:
            found.append({
                "type": "estate_identity_blind",
                "key": f"host:{host}",
                "score": 9,
                "host": host,
                "reason": "identity_pull_failed",
                "rows": rows,
                "identity_events": identity,
                "error": pull.get("error"),
                "detail": (f"host {host} identity pull failed"
                           + (f": {pull.get('error')}" if pull.get("error") else "")),
            })
        elif rows > 0 and identity == 0:
            # A pull that answered with events proves the feed is alive even
            # when the correlation window itself holds no auth rows; treat
            # that as unverified, not blind.
            answered = bool(pull.get("ok")) and int(
                pull.get("events_seen") or 0) > 0
            if coverage.get("identity_before_window") and not answered:
                found.append({
                    "type": "estate_identity_blind",
                    "key": f"host:{host}",
                    "score": 9,
                    "host": host,
                    "reason": "identity_stopped",
                    "rows": rows,
                    "identity_events": 0,
                    "detail": (f"host {host} had identity events before this "
                               "window but none inside it and the last pull "
                               "brought nothing — the feed may have stopped"),
                })
            else:
                found.append({
                    "type": "estate_identity_unverified",
                    "key": f"host:{host}",
                    "score": 7,
                    "host": host,
                    "reason": ("identity_outside_window"
                               if coverage.get("identity_before_window")
                               else "no_identity_evidence"),
                    "rows": rows,
                    "identity_events": 0,
                    "detail": (f"host {host} recorded {rows} non-identity rows "
                               "and no identity evidence in the window — no "
                               "fan-out cannot be claimed"),
                })
        if rows == 0 and pull.get("ok") is not False:
            found.append({
                "type": "estate_no_telemetry",
                "key": f"host:{host}",
                "score": 8,
                "host": host,
                "rows": 0,
                "detail": (f"host {host} reported no rows in the window — "
                           "quiet or blind; verify the sensor"),
            })
        if role in DC_ROLES and rows > 0 and kerberos == 0:
            found.append({
                "type": "estate_kerberos_blind",
                "key": f"host:{host}",
                "score": 8,
                "host": host,
                "role": role,
                "rows": rows,
                "detail": (f"domain controller {host} recorded no 4768/4769 "
                           "events — Kerberos auditing may be missing"),
            })
        pulled = _stamp(pull.get("ts"))
        if pulled is not None and now - pulled > timedelta(minutes=max_age):
            found.append({
                "type": "estate_identity_stale",
                "key": f"host:{host}",
                "score": 8,
                "host": host,
                "last_pull": pull.get("ts"),
                "age_minutes": int((now - pulled).total_seconds() // 60),
                "detail": (f"host {host} identity pull has not run for "
                           f"{int((now - pulled).total_seconds() // 60)} minutes"),
            })
    return found


def findings(estate: dict, threshold: int = DEFAULT_THRESHOLD,
             baseline: dict | None = None,
             max_identity_age_minutes: int = DEFAULT_MAX_IDENTITY_AGE_MINUTES) -> dict:
    """Correlate the estate ledger into cross-host findings."""
    threshold = max(2, min(int(threshold), 10000))
    found = []
    users = _table(estate.get("users"))
    for user, entry in users.items():
        hosts = entry.get("hosts") or {}
        if len(hosts) < threshold:
            continue
        ordered = sorted(hosts.items(), key=lambda item: (
            str(item[1].get("first") or ""), item[0]))
        source_hosts: dict[str, set] = defaultdict(set)
        for host, details in hosts.items():
            for source in _table(details.get("sources")):
                source_hosts[source].add(host)
        linked = any(len(value) >= 2 for value in source_hosts.values())
        shared = sorted(source for source, value in source_hosts.items()
                        if len(value) >= 2)
        found.append({
            "type": "estate_user_fanout",
            "key": f"user:{user}",
            "score": 9 if linked else 7,
            "user": user,
            "hosts": [host for host, _ in ordered],
            "host_count": len(hosts),
            "linked": linked,
            "shared_sources": shared[:10],
            "detail": (f"user '{user}' appeared on {len(hosts)} hosts"
                       + (" with a shared source address"
                          if linked else " (same-name pattern; verify)")),
        })
    source_hosts: dict[str, set] = defaultdict(set)
    source_users: dict[str, set] = defaultdict(set)
    for user, entry in users.items():
        for host, details in _table(entry.get("hosts")).items():
            for source in _table(details.get("sources")):
                source_hosts[source].add(host)
                source_users[source].add(user)
    for source, hosts in source_hosts.items():
        if len(hosts) < threshold:
            continue
        found.append({
            "type": "estate_source_fanout",
            "key": f"source:{source}",
            "score": 9,
            "source": source,
            "hosts": sorted(hosts),
            "host_count": len(hosts),
            "users": sorted(source_users[source])[:10],
            "detail": f"source {source} touched {len(hosts)} hosts",
        })
    for digest, hosts in _table(estate.get("hash_hosts")).items():
        if len(hosts) < threshold:
            continue
        found.append({
            "type": "estate_hash_fanout",
            "key": f"hash:{digest}",
            "score": 8,
            "hash": digest,
            "hosts": sorted(hosts),
            "host_count": len(hosts),
            "detail": f"file hash {digest[:12]}… appeared on {len(hosts)} hosts",
        })
    for host, details in (estate.get("hosts") or {}).items():
        if details.get("stale"):
            found.append({
                "type": "estate_stale_host",
                "key": f"host:{host}",
                "score": 8,
                "host": host,
                "generated_at": details.get("generated_at"),
                "detail": f"host {host} ledger is stale",
            })
    found.extend(_coverage_findings(_hosts_view(estate),
                                    datetime.now(timezone.utc),
                                    max_identity_age_minutes))
    if baseline:
        old_edges = _baseline_edges(baseline)
        new_edges = []
        for user, entry in users.items():
            hosts = sorted((entry.get("hosts") or {}).keys())
            if len(hosts) < 2:
                continue
            for host in hosts:
                key = f"{user}|{host}"
                if key not in old_edges:
                    new_edges.append({"user": user, "host": host})
        if new_edges:
            found.append({
                "type": "estate_new_host_edge",
                "key": "edges:new",
                "score": 7,
                "edges": new_edges[:50],
                "detail": f"{len(new_edges)} user/host edges not in the baseline",
            })
    found.sort(key=lambda item: (-item["score"], item["type"], item["key"]))
    return {
        "ok": True,
        "generated_at": _now(),
        "threshold": threshold,
        "hosts": len(estate.get("hosts") or {}),
        "users": len(users),
        "findings": found,
        "top_score": found[0]["score"] if found else 0,
    }


def _baseline_edges(baseline: dict) -> set[str]:
    edges = set()
    if isinstance(baseline.get("edges"), list):
        edges.update(str(item) for item in baseline["edges"])
    for user, entry in (baseline.get("users") or {}).items():
        for host in (entry.get("hosts") or {}):
            edges.add(f"{user}|{host}")
    return edges


def status(estate: dict) -> dict:
    hosts = estate.get("hosts") or {}
    return {
        "ok": True,
        "kind": estate.get("kind"),
        "generated_at": estate.get("generated_at"),
        "window_minutes": estate.get("window_minutes")
        or (estate.get("window") or {}).get("minutes"),
        "host": estate.get("host"),
        "hosts": len(hosts) if hosts else (
            1 if estate.get("kind") == "host-edge-ledger" else 0),
        "stale_hosts": sorted(host for host, details in hosts.items()
                              if details.get("stale")),
        "users": len(estate.get("users") or {}),
        "processes": len(estate.get("processes") or {}),
        "hashes": len(estate.get("hashes") or {}),
        "bytes": len(json.dumps(estate, separators=(",", ":"))),
        "truncated": estate.get("truncated") or {},
        "coverage": _coverage_summary(_hosts_view(estate)),
        "integrity": verify_ledger(estate),
    }


def _coverage_summary(hosts: dict) -> dict:
    items = _coverage_findings(hosts, datetime.now(timezone.utc),
                               DEFAULT_MAX_IDENTITY_AGE_MINUTES)
    summary = {"identity_blind": [], "identity_unverified": [],
               "no_telemetry": [], "kerberos_blind": [],
               "identity_stale": [], "unknown": []}
    for item in items:
        key = item["type"].removeprefix("estate_")
        summary.setdefault(key, []).append(item["host"])
    # Hosts whose ledger predates coverage blocks cannot be checked at all;
    # name them instead of letting the gap hide inside a clean summary.
    summary["unknown"] = sorted(
        host for host, details in hosts.items()
        if not details.get("stale") and not (details.get("coverage") or {}))
    return summary


# ---------------------------------------------------------------------------
# sync
# ---------------------------------------------------------------------------

def _ps_quote(value) -> str:
    return str(value).replace("'", "''")


def _profile_from_winrm(entry, window_minutes: int, role: str) -> dict:
    try:
        import winrm
    except ImportError:
        return {"error": "pywinrm not installed (pip install 'plasma-edr[desk]')"}
    password = os.environ.get(entry["password_env"], "")
    if not password:
        return {"error": f"environment variable {entry['password_env']} is not set"}
    exe = entry.get("plasma_exe") or r"C:\ProgramData\Plasma\bin\plasma.exe"
    events = entry.get("events_path") or r"C:\ProgramData\Plasma\data\events.jsonl"
    host = entry["name"]
    tmp = rf"C:\Windows\Temp\plasma-estate-{host}.json"
    script = (
        "$ErrorActionPreference='Stop';"
        f"& '{_ps_quote(exe)}' estate build --events '{_ps_quote(events)}' "
        f"--window {int(window_minutes)} --host '{_ps_quote(host)}' "
        f"--role '{_ps_quote(role)}' --out '{_ps_quote(tmp)}' | Out-Null; "
        f"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{_ps_quote(tmp)}'));"
        f"Remove-Item '{_ps_quote(tmp)}' -Force"
    )
    try:
        session = winrm.Session(entry["endpoint"],
                                auth=(entry.get("username", "Administrator"),
                                      password),
                                transport="ntlm", read_timeout_sec=180)
        result = session.run_ps(script)
        if result.status_code != 0:
            return {"error": (result.std_err.decode(errors="replace")
                              or f"remote exit {result.status_code}")[:300]}
        for token in result.std_out.decode(errors="replace").split():
            try:
                blob = base64.b64decode(token, validate=True)
                ledger = json.loads(blob.decode("utf-8"))
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(ledger, dict):
                verdict = verify_ledger(ledger)
                if not verdict.get("ok"):
                    return {"error": "remote ledger integrity failed"}
                if str(ledger.get("host") or "") != str(host):
                    return {"error": (f"remote ledger is for host "
                                      f"{ledger.get('host')!r}, expected {host!r}")}
                if ledger.get("kind") != "host-edge-ledger":
                    return {"error": (f"remote returned kind "
                                      f"{ledger.get('kind')!r}, expected "
                                      "host-edge-ledger")}
                return ledger
        return {"error": "remote returned no ledger JSON"}
    except Exception as exc:  # noqa: BLE001 — endpoint failures are data
        return {"error": f"winrm failed: {str(exc)[:300]}"}


def _one_ledger(entry, window_minutes: int, role: str) -> dict:
    transport = entry.get("transport", "file")
    if transport == "file":
        path = entry.get("ledger_path")
        if path:
            try:
                return load(path)
            except (OSError, ValueError) as exc:
                return {"error": f"ledger read failed: {exc}"}
        events = entry.get("events_path")
        if not events:
            return {"error": "file transport needs events_path or ledger_path"}
        if not Path(events).exists():
            return {"error": f"events not found: {events}"}
        try:
            return build(events, host=entry["name"], role=role,
                         window_minutes=window_minutes)
        except (OSError, ValueError) as exc:
            return {"error": str(exc)[:300]}
    return _profile_from_winrm(entry, window_minutes, role)


def sync(inventory_path, out_dir, window_minutes: int = DEFAULT_WINDOW_MINUTES,
         workers: int = 8, threshold: int = DEFAULT_THRESHOLD,
         max_age_minutes: int = DEFAULT_MAX_AGE_MINUTES,
         role: str = "member", loop: bool = False,
         interval: int = 300, baseline=None,
         max_identity_age_minutes: int = DEFAULT_MAX_IDENTITY_AGE_MINUTES) -> dict:
    """Pull one ledger per host, merge, correlate and persist the snapshot."""
    from . import fleet

    entries = fleet.load_inventory(inventory_path)
    out = Path(out_dir)
    hosts_dir = out / "hosts"
    hosts_dir.mkdir(parents=True, exist_ok=True)
    workers = max(1, min(int(workers), 32))
    base = None
    if baseline:
        try:
            base = json.loads(Path(baseline).read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            base = None

    def cycle() -> dict:
        ledgers, failures = [], []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_one_ledger, entry, window_minutes,
                                   role): entry for entry in entries}
            for future, entry in futures.items():
                try:
                    ledger = future.result()
                except Exception as exc:  # noqa: BLE001 - one host must not stop a cycle
                    failures.append({"host": entry["name"],
                                     "error": f"pull failed: {exc}"[:300]})
                    continue
                if "error" in ledger:
                    failures.append({"host": entry["name"],
                                     "error": ledger["error"]})
                    continue
                try:
                    saved = save(hosts_dir / f"{entry['name']}.json", ledger)
                except OSError as exc:
                    failures.append({"host": entry["name"],
                                     "error": f"save failed: {exc}"})
                    continue
                ledger["_path"] = saved["ledger"]
                ledgers.append(ledger)
        if not ledgers:
            return {"ok": False, "error": "no host ledger could be built",
                    "failures": failures, "hosts": len(entries)}
        estate = merge(ledgers, max_age_minutes=max_age_minutes)
        saved = save(out / "estate.json", estate)
        report = findings(estate, threshold=threshold, baseline=base,
                          max_identity_age_minutes=max_identity_age_minutes)
        finding_path = out / "findings.json"
        finding_tmp = out / f"findings.json.{os.getpid()}.tmp"
        finding_tmp.write_text(
            json.dumps(report, indent=1, sort_keys=True) + "\n",
            encoding="utf-8")
        os.replace(finding_tmp, finding_path)
        return {
            "ok": True,
            "out_dir": str(out),
            "hosts": len(entries),
            "pulled": len(ledgers),
            "failures": failures,
            "estate": {"path": saved["ledger"], "bytes": saved["bytes"],
                       "hosts": len(estate["hosts"]),
                       "users": len(estate["users"]),
                       "stale": [host for host, details in estate["hosts"].items()
                                 if details.get("stale")]},
            "findings": report,
        }

    if not loop:
        return cycle()
    while True:
        result = cycle()
        print(json.dumps(result, separators=(",", ":"), default=str), flush=True)
        if not result.get("ok"):
            time.sleep(max(10, int(interval)))
            continue
        time.sleep(max(10, int(interval)))
