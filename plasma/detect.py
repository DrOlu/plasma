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


def validate(rules_path) -> dict:
    """Compile regexes and check condition variables without a sensor."""
    rules = load_rules(rules_path)
    errors, warnings = [], []
    names = {}
    for index, rule in enumerate(rules, 1):
        name = _name(rule, index)
        names.setdefault(name, []).append(index)
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
    """Run the deterministic story engine and summary over a captured store."""
    rules = None
    if rules_path:
        rules = load_rules(rules_path)
    chains = chain.scan_store(events_path, max_rows=max_rows)
    digest = summarize.summarize(events_path, max_rows=max_rows)
    return {
        "ok": True,
        "events": str(events_path),
        "rules": {"path": str(rules_path), "count": len(rules)} if rules
        else {"path": None, "count": 0},
        "chains": chains,
        "summary": {
            "checked": digest.get("checked"),
            "counts": digest.get("counts"),
            "score_bands": digest.get("score_bands"),
            "sources": digest.get("sources"),
        },
    }
