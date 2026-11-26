"""Plasma watch: periodic self-check sweep with notifications.

Not a standing collector — a sweep the operator (or Task Scheduler) runs
on demand or on a cadence:  health verdict + drift score + canary +
new-WHIDS-alert count, delivered through notify channels when something
crosses a threshold. `--once` for cron, `--loop N` for long-running.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path

from . import agentstate, health, notify, observatory

# WHIDS alert directory. A module constant so tests and alternate installs
# can point the sweep at the real location without patching Path.
ALERTS_DIR = Path(r"C:\Program Files\Whids\Logs\Alerts")
ALERT_OFFSETS_FILE = "watch-alert-offsets.json"
CANARY_ACCOUNT_STATE = "watch-canary-accounts-state.json"
HIGH_CRITICALITY = 8.0
_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@$-]{0,63}$")


def _events_path(root) -> Path:
    """Use the configured store, then the conventional root/data path."""
    cfg = agentstate.read_json(Path(root) / "config.json", {}) or {}
    configured = cfg.get("events_path") if isinstance(cfg, dict) else None
    return Path(configured) if configured else Path(root) / "data" / "events.jsonl"


def _configured_canary_accounts(root) -> list[str]:
    cfg = agentstate.read_json(Path(root) / "config.json", {}) or {}
    if not isinstance(cfg, dict):
        return []
    block = cfg.get("canary") if isinstance(cfg.get("canary"), dict) else {}
    values = block.get("accounts")
    if values is None:
        values = cfg.get("canary_accounts")
    if not isinstance(values, (list, tuple)):
        return []
    out = []
    for value in values:
        text = str(value).strip()
        if _ACCOUNT_RE.match(text) and text not in out:
            out.append(text)
    return out[:20]


def _canary_account_findings(root, accounts) -> list[dict]:
    """Query the Security channel for configured canary accounts.

    The query is bounded (observatory caps it at 500 rows / 7 days) and the
    result is deduplicated by event identity, so a five-minute watch loop
    does not re-alert the same logon forever.
    """
    accounts = [str(a) for a in (accounts or []) if _ACCOUNT_RE.match(str(a))]
    if not accounts:
        return []
    answer = observatory.run_question("canary", canaries=accounts)
    if not isinstance(answer, dict):
        return [{"type": "canary_account_scan_error", "score": 5,
                 "detail": "canary account collector returned no answer"}]
    if answer.get("error"):
        return [{"type": "canary_account_scan_error", "score": 5,
                 "detail": str(answer["error"])[:200]}]
    state_path = Path(root) / CANARY_ACCOUNT_STATE
    state = agentstate.read_json(state_path, {}) or {}
    seen = set(state.get("seen") or []) if isinstance(state, dict) else set()
    new_seen = set(seen)
    findings = []
    for hit in answer.get("hits") or []:
        if not isinstance(hit, dict):
            continue
        key = hashlib.sha256(json.dumps({
            "when": hit.get("when"), "id": hit.get("id"),
            "user": hit.get("user"), "source_ip": hit.get("source_ip"),
            "logon_type": hit.get("logon_type"),
        }, sort_keys=True).encode()).hexdigest()[:32]
        if key in new_seen:
            continue
        event_id = hit.get("id")
        source_ip = hit.get("source_ip")
        user = hit.get("user") or accounts[0]
        detail = (f"canary account '{user}' logon event {event_id}"
                  + (f" from {source_ip}" if source_ip not in (None, "", "-")
                     else ""))
        findings.append({
            "type": "canary_account_tripped", "score": 10,
            "detail": detail[:200], "user": user,
            "event_id": event_id,
            "dest_ip": None if source_ip in (None, "", "-") else source_ip,
            "ts": hit.get("when"),
        })
        new_seen.add(key)
    agentstate.write_json(state_path, {"seen": list(new_seen)[-2000:]})
    return findings


def _canary_token_findings(root) -> tuple[list[dict], list[str]]:
    """Collect DNS/HTTP token hits; return findings plus non-fatal info."""
    from . import canary_tokens

    findings: list[dict] = []
    info: list[str] = []
    store = _events_path(root)
    dns = canary_tokens.collect_dns_hits(root, store)
    for hit in dns.get("hits") or []:
        event = hit.get("event") or {}
        findings.append({
            "type": "canary_dns_tripped", "score": 8,
            "detail": str(event.get("description") or "canary DNS token hit")[:200],
            "pid": event.get("pid"), "process": event.get("process"),
            "user": event.get("user"), "dest_ip": event.get("dest_ip"),
            "dns_query": event.get("dns_query"),
            "alert_id": event.get("alert_id"), "ts": event.get("ts"),
        })
    if dns.get("error"):
        findings.append({"type": "canary_token_scan_error", "score": 5,
                         "detail": str(dns["error"])[:200]})
    elif dns.get("sysmon_error"):
        info.append("canary DNS: " + str(dns["sysmon_error"])[:160])

    http = canary_tokens.collect_http_hits(root, store)
    for hit in http.get("hits") or []:
        event = hit.get("event") or {}
        findings.append({
            "type": "canary_http_tripped", "score": 8,
            "detail": str(event.get("description") or "canary HTTP token hit")[:200],
            "dest_ip": event.get("dest_ip"),
            "alert_id": event.get("alert_id"), "ts": event.get("ts"),
        })
    if http.get("error"):
        findings.append({"type": "canary_token_scan_error", "score": 5,
                         "detail": str(http["error"])[:200]})
    return findings, info


def sweep(root, since_alerts: int = 25, drift_question: str = "attest",
          canary_accounts=None) -> dict:
    root = Path(root)
    findings = []
    info = []

    # 1. health verdict
    hv = health.verdict(root)
    if hv["status"] != "ok":
        findings.append({"type": "health", "score": (10 if hv["status"] == "down" else 6),
                         "detail": f"health {hv['status']}: {', '.join(hv['failed'])}"})

    # 2. drift on a live observatory answer (attest = witness blindness + sensors)
    from . import drift
    try:
        answer = observatory.run_question(drift_question)
        result = drift.score(root, drift_question, answer)
        drift_rows = result.get("drift", [])
        for d in drift_rows:
            findings.append({"type": f"drift_{d['type']}", "score": d.get("score", 5),
                             "detail": str(d.get("detail"))[:200]})
        if not drift_rows and "no baseline" in str(result.get("error", "")):
            info.append(f"no {drift_question} baseline yet — run: "
                        f"plasma drift record --question {drift_question}")
    except Exception as exc:  # noqa: BLE001 — collector failures are data
        findings.append({"type": "sweep_error", "score": 5,
                         "detail": str(exc)[:160]})

    # 3. NEW WHIDS alert rows sitting on disk since the last sweep
    #    (whids.pull never truncates rotated files, so comparing against the
    #    absolute row count would re-fire forever; only growth is a finding)
    alerts_dir = Path(ALERTS_DIR)
    alert_rows = 0
    if alerts_dir.is_dir():
        for f in alerts_dir.rglob("*"):
            if (f.is_file() and f.suffix != ".gz"
                    and ".old-" not in str(f)):
                alert_rows += sum(1 for ln in f.read_text(errors="replace").splitlines()
                                  if ln.strip().startswith("{"))
    alert_state_path = root / "watch-alerts-state.json"
    seen_alert_rows = 0
    if alert_state_path.exists():
        try:
            seen_alert_rows = int(json.loads(
                alert_state_path.read_text(encoding="utf-8-sig")).get("seen_alert_rows", 0))
        except (ValueError, json.JSONDecodeError):
            seen_alert_rows = 0
    new_alert_rows = max(0, alert_rows - seen_alert_rows)
    if new_alert_rows > since_alerts:
        findings.append({"type": "unpulled_whids_alerts", "score": 6,
                         "detail": f"{new_alert_rows} new alert rows since last sweep "
                                   f"— run: plasma whids pull"})
    try:
        alert_state_path.write_text(
            json.dumps({"seen_alert_rows": alert_rows}) + "\n", encoding="utf-8")
    except OSError:
        pass

    # 3b. Surface genuinely high-criticality WHIDS alerts immediately.
    # Counting rows is not enough: a single criticality-9 gene alert would
    # sit unseen until 25 more rows arrived. Read only bytes appended since
    # the last sweep (per-file offsets, reset on truncation/rotation).
    try:
        findings.extend(_new_high_alerts(root, alerts_dir))
    except Exception as exc:  # noqa: BLE001 — collector failures are data
        findings.append({"type": "alert_scan_error", "score": 5,
                         "detail": str(exc)[:160]})

    # 4. chain stories over the events tail (deterministic sequences —
    #    "this happened, then this": phish spawn, brute-force-success, ...)
    try:
        from . import chain as chain_mod
        store = root / "data" / "events.jsonl"
        if store.exists():
            cres = chain_mod.scan_store(store)
            # Chain findings are stateless over the event tail: without a
            # last-fired signature, watch re-reports the same story every
            # sweep until it ages out. Track one signature per chain type
            # (bounded by the chain count) next to the alert state.
            chain_state_path = root / "watch-chain-state.json"
            seen_sigs: dict = {}
            try:
                loaded = json.loads(chain_state_path.read_text(
                    encoding="utf-8-sig"))
                if isinstance(loaded, dict):
                    seen_sigs = loaded
            except (OSError, json.JSONDecodeError, ValueError):
                seen_sigs = {}
            new_sigs = dict(seen_sigs)
            for f in cres.get("findings", []):
                first = (f.get("events") or [{}])[0]
                sig = (f"{f.get('type')}:{first.get('ts')}:"
                       f"{','.join(f.get('users') or [])}")
                if seen_sigs.get(str(f.get("type"))) == sig:
                    continue
                new_sigs[str(f.get("type"))] = sig
                findings.append({"type": f["type"], "score": f["score"],
                                 "detail": str(f["detail"])[:200],
                                 "users": f.get("users"),
                                 "events": f.get("events")})
            if new_sigs != seen_sigs:
                try:
                    chain_state_path.write_text(
                        json.dumps(new_sigs, sort_keys=True) + "\n",
                        encoding="utf-8")
                except OSError:
                    pass
    except Exception as exc:  # noqa: BLE001 — collector failures are data
        findings.append({"type": "chain_scan_error", "score": 5,
                         "detail": str(exc)[:160]})

    # 5. canary files — decoys whose only purpose is to be touched.
    #    A missing or modified canary is impact detection (T1486), score 10.
    try:
        from . import canary as canary_mod
        can = canary_mod.verify(root)
        for t in can.get("tripped", []):
            findings.append({
                "type": "canary_tripped", "score": 10,
                "detail": f"canary {t['reason']}: {t['path']}"[:200],
                "path": t.get("path"), "reason": t.get("reason")})
    except Exception as exc:  # noqa: BLE001 — collector failures are data
        findings.append({"type": "canary_scan_error", "score": 5,
                         "detail": str(exc)[:160]})

    # 5b. native canary tokens — DNS tripwires and local HTTP callbacks.
    try:
        token_findings, token_info = _canary_token_findings(root)
        findings.extend(token_findings)
        info.extend(token_info)
    except Exception as exc:  # noqa: BLE001 — collector failures are data
        findings.append({"type": "canary_token_scan_error", "score": 5,
                         "detail": str(exc)[:160]})

    # 5c. canary accounts — configured in config.json under canary.accounts.
    try:
        accounts = (canary_accounts if canary_accounts is not None
                    else _configured_canary_accounts(root))
        findings.extend(_canary_account_findings(root, accounts))
    except Exception as exc:  # noqa: BLE001 — collector failures are data
        findings.append({"type": "canary_account_scan_error", "score": 5,
                         "detail": str(exc)[:160]})

    # 6. critical-file integrity — configurable FIM baseline.
    try:
        from . import fim as fim_mod
        fres = fim_mod.verify(root)
        for f in fres.get("findings", []):
            findings.append({
                "type": f["type"], "score": f["score"],
                "detail": f"{f['path']}: {f['detail']}"[:200],
                "path": f.get("path")})
    except Exception as exc:  # noqa: BLE001 — collector failures are data
        findings.append({"type": "fim_scan_error", "score": 5,
                         "detail": str(exc)[:160]})

    top = max((f["score"] for f in findings), default=0)
    return {"info": info, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "health": hv["status"], "findings": findings, "top_score": top,
            "verdict": ("clean" if top == 0 else
                        "investigate" if top < 8 else "act now")}


def _head_token(path: Path, limit: int = 512) -> str:
    """Fingerprint of the first *limit* bytes, capped at 512.

    Hashing the whole current file would change on every append and look
    like a replaced file.  Hashing exactly the bytes already consumed keeps
    append-only growth stable while still detecting a rewrite.
    """
    limit = max(0, min(int(limit), 512))
    if not limit:
        return ""
    try:
        with path.open("rb") as fh:
            return hashlib.sha1(fh.read(limit), usedforsecurity=False).hexdigest()
    except OSError:
        return ""


def _new_high_alerts(root, alerts_dir: Path) -> list[dict]:
    """Parse alert bytes appended since the last sweep.

    Offsets advance only over complete lines. A rotated/truncated file is
    read from zero. Findings are capped so a burst cannot flood a sweep.
    """
    from . import agentstate, whids

    state_path = Path(root) / ALERT_OFFSETS_FILE
    state = agentstate.read_json(state_path, {}) or {}
    offsets = state.get("files") if isinstance(state, dict) else {}
    offsets = dict(offsets or {})
    out: list[dict] = []
    if not Path(alerts_dir).is_dir():
        return out

    for path in sorted(Path(alerts_dir).rglob("*")):
        if (not path.is_file() or path.suffix == ".gz"
                or ".old-" in str(path)):
            continue
        key = str(path)
        try:
            size = path.stat().st_size
        except OSError:
            continue
        previous = offsets.get(key) or {}
        if not previous:
            # First sight (fresh install or upgrade): start at the current
            # end. Re-alerting the entire alert history on the first sweep
            # would flood an operator; history is available via `whids pull`.
            offsets[key] = {"offset": size, "size": size,
                            "head": _head_token(path, min(size, 512))}
            continue
        start = int(previous.get("offset", 0) or 0)
        head = _head_token(path, min(start, 512))
        # A smaller file is truncated; a different prefix is a replaced
        # file. Either way, the old offset points into the wrong content.
        if size < start or (previous.get("head") and previous["head"] != head):
            start = 0
            head = ""
        if size == start:
            offsets[key] = {"offset": size, "size": size, "head": head}
            continue
        try:
            with path.open("rb") as fh:
                fh.seek(start)
                blob = fh.read(4 << 20)    # bounded per file per sweep
        except OSError:
            continue
        # Only consume complete lines; leave a partial tail for next sweep.
        cut = blob.rfind(b"\n")
        if cut < 0:
            offsets[key] = {"offset": start, "size": size, "head": head}
            continue
        consumed = start + cut + 1
        for line in blob[:cut + 1].splitlines():
            try:
                record = json.loads(line.decode("utf-8", "replace"))
                event = whids.normalize_alert(record)
            except (json.JSONDecodeError, UnicodeError, TypeError,
                    ValueError, KeyError):
                # One malformed alert must not abort the sweep or prevent
                # the offset from advancing. Otherwise the same line is
                # re-read forever and detection goes dark.
                continue
            if not event:
                continue
            try:
                criticality = float(event.get("score") or 0) * 10.0
            except (TypeError, ValueError):
                continue
            if criticality < HIGH_CRITICALITY:
                continue
            out.append({
                "type": "whids_high_criticality",
                "score": round(criticality),
                "detail": (f"{event.get('description') or 'WHIDS detection'}"
                           f" on {event.get('process') or 'unknown process'}"
                           f" ({event.get('technique') or 'no technique'})")[:200],
                # Structured entities so enforcement can act on the finding
                # instead of re-parsing its human-readable detail.
                "pid": event.get("pid"),
                "user": event.get("user"),
                "process": event.get("process"),
                "dest_ip": event.get("dest_ip"),
                "technique": event.get("technique"),
                "alert_id": event.get("alert_id"),
            })
        offsets[key] = {"offset": consumed, "size": size,
                        "head": _head_token(path, min(consumed, 512))}

    agentstate.write_json(state_path, {"files": offsets})
    # Collapse identical findings from a loop (same rule/process) so one
    # storm does not consume the whole ten-item budget.
    grouped: dict[tuple, dict] = {}
    for item in out:
        key = (item["type"], item["detail"])
        if key in grouped:
            grouped[key]["occurrences"] += 1
            grouped[key]["score"] = max(grouped[key]["score"], item["score"])
        else:
            grouped[key] = dict(item, occurrences=1)
    collapsed = list(grouped.values())
    for item in collapsed:
        if item["occurrences"] > 1:
            item["detail"] = f"{item['detail']} (x{item['occurrences']})"[:200]
    return collapsed[:10]


def watch_once(root, quiet_clean: bool = True, canary_accounts=None) -> dict:
    result = sweep(root, canary_accounts=canary_accounts)
    should_notify = (not quiet_clean) or result["top_score"] > 0
    delivered = None
    if should_notify:
        title = f"Plasma watch: {result['verdict']} ({result['top_score']}/10)"
        body = "\n".join(f"- [{f['score']}] {f['type']}: {f['detail']}"
                         for f in result["findings"]) or "clean"
        # throttle key = the loudest finding's type: at most one message per
        # finding-type per hour, even on a noisy day
        loudest = max(result["findings"], key=lambda f: f["score"], default=None)
        delivered = notify.notify_all(root, title, body,
                                      score=result["top_score"],
                                      throttle_key=loudest["type"] if loudest else None)
    result["notify"] = delivered
    state = Path(root) / "watch-state.json"
    state.write_text(json.dumps(result, indent=1, default=str) + "\n", encoding="utf-8")
    return result
