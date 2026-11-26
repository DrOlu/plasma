"""Detection-engineering harness: validate, diff and replay written rules.

Plasma's detection content is deterministic JSON. This module gives an
operator a local loop that does not need a running WHIDS service:

    plasma detect validate --rules sensors/plasma-baseline.gen
    plasma detect diff --old old.gen --new new.gen
    plasma detect replay --events captured.jsonl

Validation compiles every regex expression and checks condition variables.
Diff reports added, removed and changed rules by name and content hash.
Replay runs the chain engine and a bounded summary over a captured store,
so a rule change can be reviewed against real history before promotion.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from . import chain, summarize

_NAME_KEYS = ("Name", "name", "title", "Title")
_REGEX = re.compile(r"~=\s*(['\"])(.*?)\1", re.DOTALL)


class DetectError(ValueError):
    """Invalid rule file or rule shape."""


def _name(rule: dict, index: int) -> str:
    for key in _NAME_KEYS:
        if rule.get(key):
            return str(rule[key])[:120]
    meta = rule.get("Meta") if isinstance(rule.get("Meta"), dict) else {}
    if meta.get("RuleID"):
        return str(meta["RuleID"])[:120]
    return f"rule-{index}"


def _sha(rule: dict) -> str:
    payload = json.dumps(rule, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_rules(path) -> list[dict]:
    path = Path(path)
    if not path.exists():
        raise DetectError(f"rule file does not exist: {path}")
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise DetectError(f"cannot read {path}: {exc}") from exc
    rules = []
    if path.suffix.lower() in (".json",) or text.lstrip().startswith("["):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise DetectError(f"invalid JSON: {exc}") from exc
        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            raise DetectError("rule file must be a JSON object or array")
        rules = [row for row in payload if isinstance(row, dict)]
    else:
        for line_no, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise DetectError(f"line {line_no}: invalid JSON: {exc}") from exc
            if not isinstance(row, dict):
                raise DetectError(f"line {line_no}: rule is not an object")
            rules.append(row)
    if not rules:
        raise DetectError("rule file contains no rules")
    return rules


# WHIDS forwards alerts strictly above this criticality (sensors/whids.toml,
# `criticality-treshold = 5`). A gene at or below it is compiled by the engine
# but never written to the alert log, so Plasma never sees the detection.
MIN_FORWARDED_CRITICALITY = 5


def validate(rules_path) -> dict:
    """Compile regexes and check condition variables without a sensor."""
    rules = load_rules(rules_path)
    errors, warnings = [], []
    names = {}
    for index, rule in enumerate(rules, 1):
        name = _name(rule, index)
        names.setdefault(name, []).append(index)
        meta = rule.get("Meta")
        if isinstance(meta, dict):
            # Sigma-converted rules store Criticality as a string ("9");
            # coerce before comparing or the warning is a silent no-op.
            try:
                criticality = int(meta.get("Criticality"))
            except (TypeError, ValueError):
                criticality = None
            if (criticality is not None
                    and criticality <= MIN_FORWARDED_CRITICALITY):
                warnings.append({
                    "rule": name,
                    "warning": f"criticality {criticality} is at or below "
                               f"WHIDS criticality-treshold "
                               f"{MIN_FORWARDED_CRITICALITY}; the alert will "
                               "not be logged",
                })
        matches = rule.get("Matches")
        if not isinstance(matches, list) or not matches:
            errors.append({"rule": name, "error": "missing Matches list"})
            continue
        variables = set()
        for expression in matches:
            if not isinstance(expression, str):
                errors.append({"rule": name, "error": "non-string Matches entry"})
                continue
            if ":" in expression:
                variables.add(expression.split(":", 1)[0].strip())
            for quote, pattern in _REGEX.findall(expression):
                try:
                    re.compile(pattern)
                except re.error as exc:
                    errors.append({"rule": name,
                                   "error": f"bad regex {pattern!r}: {exc}"})
        condition = rule.get("Condition")
        if condition:
            used = set(re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*", str(condition)))
            unknown = sorted(used - variables)
            if unknown:
                warnings.append({"rule": name,
                                 "warning": "condition references unknown "
                                            "variable(s): " + ", ".join(unknown)})
    duplicates = [{"rule": name, "lines": rows}
                  for name, rows in names.items() if len(rows) > 1]
    return {"ok": not errors, "path": str(rules_path), "rules": len(rules),
            "errors": errors, "warnings": warnings,
            "duplicates": duplicates}


def diff(old_path, new_path) -> dict:
    old = {_name(rule, i): rule for i, rule in enumerate(load_rules(old_path), 1)}
    new = {_name(rule, i): rule for i, rule in enumerate(load_rules(new_path), 1)}
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed = sorted(name for name in set(old) & set(new)
                     if _sha(old[name]) != _sha(new[name]))
    return {
        "ok": True,
        "old": str(old_path), "new": str(new_path),
        "old_count": len(old), "new_count": len(new),
        "added": [{"rule": name, "sha256": _sha(new[name])} for name in added],
        "removed": [{"rule": name, "sha256": _sha(old[name])} for name in removed],
        "changed": [{"rule": name, "old_sha256": _sha(old[name]),
                     "new_sha256": _sha(new[name])} for name in changed],
        "summary": {"added": len(added), "removed": len(removed),
                    "changed": len(changed),
                    "unchanged": len(set(old) & set(new)) - len(changed)},
    }


def replay(events_path, rules_path=None, max_rows: int = 5000) -> dict:
    """Run the deterministic story engine and summary over a captured store.

    With `--rules`, the candidate rule file is validated first and the
    verdict is part of the output: replay is the pre-promotion review, so a
    broken rule file must not look identical to a clean one."""
    rules = None
    validation = None
    if rules_path:
        rules = load_rules(rules_path)
        validation = validate(rules_path)
    chains = chain.scan_store(events_path, max_rows=max_rows)
    digest = summarize.summarize(events_path, max_rows=max_rows)
    ok = True
    if validation is not None:
        ok = not validation.get("errors")
    return {
        "ok": ok,
        "events": str(events_path),
        "rules": {"path": str(rules_path), "count": len(rules)} if rules
        else {"path": None, "count": 0},
        "chains": chains,
        "validation": validation,
        "summary": {
            "checked": digest.get("checked"),
            "counts": digest.get("counts"),
            "score_bands": digest.get("score_bands"),
            "sources": digest.get("sources"),
        },
    }


# ---------------------------------------------------------------------------
# Deterministic regression suite
# ---------------------------------------------------------------------------

def _row(ts, **fields):
    return {"ts": ts, **fields}


BUILTIN_CASES = [
    {
        "name": "phish story hits",
        "chain": "phish_spawn_chain",
        "expect": "hit",
        "score": 9,
        "events": [
            _row("2026-11-20T10:00:00Z", kind="process", process="winword.exe",
                 user="sam"),
            _row("2026-11-20T10:01:00Z", kind="process",
                 process="powershell.exe", user="sam",
                 description="powershell -enc SQBFAFgA"),
            _row("2026-11-20T10:02:00Z", kind="network", process="powershell.exe",
                 user="sam", dest_ip="203.0.113.9"),
        ],
    },
    {
        "name": "phish without script host misses",
        "chain": "phish_spawn_chain",
        "expect": "miss",
        "events": [
            _row("2026-11-20T10:00:00Z", kind="process", process="winword.exe"),
            _row("2026-11-20T10:02:00Z", kind="network", dest_ip="203.0.113.9"),
        ],
    },
    {
        "name": "brute force then same-user success hits",
        "chain": "brute_force_success",
        "expect": "hit",
        "score": 8,
        "events": [
            *[_row(f"2026-11-20T10:0{i}:00Z", kind="auth", event_id=4625,
                   user="CORP\\olu") for i in range(5)],
            _row("2026-11-20T10:10:00Z", kind="auth", event_id=4624,
                 user="CORP\\olu"),
        ],
    },
    {
        "name": "brute force success for another user misses",
        "chain": "brute_force_success",
        "expect": "miss",
        "events": [
            *[_row(f"2026-11-20T10:0{i}:00Z", kind="auth", event_id=4625,
                   user="CORP\\olu") for i in range(5)],
            _row("2026-11-20T10:10:00Z", kind="auth", event_id=4624,
                 user="CORP\\admin"),
        ],
    },
    {
        "name": "Kerberos spray then TGT hits",
        "chain": "kerberos_brute_force",
        "expect": "hit",
        "score": 9,
        "events": [
            *[_row(f"2026-11-20T10:0{i}:00Z", kind="auth", event_id=4771,
                   user="olu@CORP.LOCAL") for i in range(5)],
            _row("2026-11-20T10:10:00Z", kind="auth", event_id=4768,
                 user="olu@CORP.LOCAL"),
        ],
    },
    {
        "name": "privilege change then persistence hits",
        "chain": "persistence_after_privilege",
        "expect": "hit",
        "score": 9,
        "events": [
            _row("2026-11-20T10:00:00Z", kind="process",
                 description="net localgroup administrators svc /add"),
            _row("2026-11-20T10:05:00Z", kind="process",
                 description="schtasks /create /tn x /tr cmd.exe"),
        ],
    },
    {
        "name": "account change then service persistence hits",
        "chain": "persistence_after_privilege",
        "expect": "hit",
        "score": 9,
        "events": [
            _row("2026-11-20T10:00:00Z", kind="process",
                 description="net user svc P@ss /add"),
            _row("2026-11-20T10:05:00Z", kind="process",
                 description="sc.exe create EvilService binPath= cmd.exe"),
        ],
    },
    {
        "name": "account change then run-key persistence hits",
        "chain": "persistence_after_privilege",
        "expect": "hit",
        "score": 9,
        "events": [
            _row("2026-11-20T10:00:00Z", kind="process",
                 description="net localgroup administrators svc /add"),
            _row("2026-11-20T10:05:00Z", kind="process",
                 description="reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Evil /d cmd.exe"),
        ],
    },
    {
        "name": "account change then scheduled-task query misses",
        "chain": "persistence_after_privilege",
        "expect": "miss",
        "events": [
            _row("2026-11-20T10:00:00Z", kind="process",
                 description="net localgroup administrators svc /add"),
            _row("2026-11-20T10:05:00Z", kind="process",
                 description="powershell.exe -Command Get-ScheduledTask"),
        ],
    },
    {
        "name": "account change then schtasks delete misses",
        "chain": "persistence_after_privilege",
        "expect": "miss",
        "events": [
            _row("2026-11-20T10:00:00Z", kind="process",
                 description="net localgroup administrators svc /add"),
            _row("2026-11-20T10:05:00Z", kind="process", process="schtasks.exe",
                 description="schtasks /delete /tn spawn /f"),
        ],
    },
    {
        "name": "plasma task registration after account change misses",
        "chain": "persistence_after_privilege",
        "expect": "miss",
        "events": [
            _row("2026-11-20T10:00:00Z", kind="process",
                 description="net localgroup administrators svc /add"),
            _row("2026-11-20T10:05:00Z", kind="process", process="powershell.exe",
                 parent="plasma-1.26.6.exe",
                 description="powershell.exe -Command Register-ScheduledTask"),
        ],
    },
    {
        "name": "account creation then privileged group hits",
        "chain": "account_creation_privilege",
        "expect": "hit",
        "score": 9,
        "events": [
            _row("2026-11-20T10:00:00Z", kind="auth", event_id=4720,
                 user="CORP\\svc-temp"),
            _row("2026-11-20T10:05:00Z", kind="auth", event_id=4728,
                 user="CORP\\Domain Admins",
                 description="global group membership added: CORP\\svc-temp "
                             "to Domain Admins by CORP\\admin"),
        ],
    },
    {
        "name": "group add of a different member misses",
        "chain": "account_creation_privilege",
        "expect": "miss",
        "events": [
            _row("2026-11-20T10:00:00Z", kind="auth", event_id=4720,
                 user="CORP\\svc-temp"),
            _row("2026-11-20T10:05:00Z", kind="auth", event_id=4732,
                 user="CORP\\Sales-RO",
                 description="local group membership added: CORP\\sales-ro "
                             "to Sales-RO by CORP\\admin"),
        ],
    },
    {
        "name": "account creation alone misses",
        "chain": "account_creation_privilege",
        "expect": "miss",
        "events": [
            _row("2026-11-20T10:00:00Z", kind="auth", event_id=4720,
                 user="CORP\\svc-temp"),
        ],
    },
    {
        "name": "remote RWX then thread hits",
        "chain": "injection_chain",
        "expect": "hit",
        "score": 9,
        "events": [
            _row("2026-11-20T10:00:00Z", kind="trace", process="evil.exe",
                 description='dtrace inject-rwx "self": 0 target=1234'),
            _row("2026-11-20T10:00:05Z", kind="trace", process="evil.exe",
                 description="dtrace inject-remote-thread target=1234"),
        ],
    },
    {
        "name": "RWX alone misses",
        "chain": "injection_chain",
        "expect": "miss",
        "events": [
            _row("2026-11-20T10:00:00Z", kind="trace", process="evil.exe",
                 description='dtrace inject-rwx "self": 0 target=1234'),
        ],
    },
]


def _load_cases(path):
    path = Path(path)
    try:
        if path.stat().st_size > (4 << 20):
            raise DetectError("case file is larger than 4 MiB")
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DetectError(f"cannot read cases {path}: {exc}") from exc
    rows = payload.get("cases") if isinstance(payload, dict) else payload
    if not isinstance(rows, list) or not rows:
        raise DetectError("case file must contain a non-empty cases array")
    if len(rows) > 500:
        raise DetectError("case file is limited to 500 cases")
    return rows


def test_cases(cases=None) -> dict:
    """Run hit/miss regression cases against the chain engine."""
    cases = cases if cases is not None else BUILTIN_CASES
    results = []
    for index, case in enumerate(cases, 1):
        if not isinstance(case, dict):
            results.append({"name": f"case-{index}", "passed": False,
                            "error": "case is not an object"})
            continue
        name = str(case.get("name") or f"case-{index}")
        chain_name = str(case.get("chain") or "")
        expect = str(case.get("expect") or "hit").lower()
        events = case.get("events")
        if not chain_name or not isinstance(events, list):
            results.append({"name": name, "passed": False,
                            "error": "case needs chain and events"})
            continue
        findings = chain.scan(events)
        matched = [f for f in findings if f.get("type") == f"chain_{chain_name}"]
        hit = bool(matched)
        score = float(case.get("score") or 0)
        score_ok = not hit or float(matched[0].get("score") or 0) >= score
        passed = (hit if expect == "hit" else not hit) and score_ok
        results.append({
            "name": name, "chain": chain_name, "expect": expect,
            "hit": hit, "score": matched[0].get("score") if hit else None,
            "passed": passed,
        })
    failed = [row for row in results if not row.get("passed")]
    return {"ok": not failed, "cases": len(results),
            "passed": len(results) - len(failed), "failed": failed,
            "results": results}
