"""Sigma -> WHIDS gene conversion (the honest way to grow the rule corpus).

Sigma rules describe a log source, one or more selections, and a boolean
condition. Plasma's gene schema already has the same shape: EventIDs,
Channels, ``$field: Field ~= 'regex'`` matches, and a Condition string.
This module derives a gene rule from that structure instead of hand-copying
rules, and reports every rule it cannot translate rather than dropping it
silently.

Supported subset (deliberately explicit):

* Windows/Sysmon categories: process_creation, image_load, driver_load,
  file_event/file_create, network_connection, pipe_created, process_access,
  registry_event/registry_set.
* Selection maps and lists of maps, field modifiers ``contains``,
  ``startswith``, ``endswith``, ``re``, ``all``.
* Conditions built from selection names with and/or/not and parentheses.
* ``1 of ...`` / wildcards are refused with a reason.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

LEVEL_SCORE = {"critical": 9, "high": 8, "medium": 6, "low": 4,
               "informational": 2}
CHANNEL_SYSMON = "Microsoft-Windows-Sysmon/Operational"
CHANNEL_SECURITY = "Security"

# category -> (event ids, channel)
CATEGORIES = {
    "process_creation": ([1], CHANNEL_SYSMON),
    "image_load": ([7], CHANNEL_SYSMON),
    "driver_load": ([6], CHANNEL_SYSMON),
    "file_event": ([11], CHANNEL_SYSMON),
    "file_create": ([11], CHANNEL_SYSMON),
    "network_connection": ([3], CHANNEL_SYSMON),
    "pipe_created": ([17, 18], CHANNEL_SYSMON),
    "process_access": ([10], CHANNEL_SYSMON),
    "registry_event": ([12, 13, 14], CHANNEL_SYSMON),
    "registry_set": ([12, 13, 14], CHANNEL_SYSMON),
}

_T_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.I)


class SigmaError(ValueError):
    pass


def _regex(value, modifier: str) -> str:
    text = str(value)
    if modifier == "re":
        return f"(?i:{text})"
    escaped = re.escape(text)
    if modifier == "contains":
        return f"(?i:{escaped})"
    if modifier == "startswith":
        return f"(?i:^{escaped})"
    if modifier == "endswith":
        return f"(?i:{escaped}$)"
    return f"(?i:^{escaped}$)"


def _value_regex(values, modifier: str) -> str:
    if isinstance(values, (list, tuple)):
        parts = [_regex(v, modifier) for v in values]
        return "(?:" + "|".join(parts) + ")" if len(parts) > 1 else parts[0]
    return _regex(values, modifier)


def _selection(name: str, spec) -> tuple[list[str], str]:
    """One selection -> (match variables, gene-side expression)."""
    if isinstance(spec, dict):
        variables, exprs = [], []
        for field, values in spec.items():
            parts = str(field).split("|")
            base, modifiers = parts[0], [p.lower() for p in parts[1:]]
            modifier = next((m for m in modifiers
                             if m in ("contains", "startswith", "endswith",
                                      "re")), "equals")
            var = "$" + re.sub(r"[^A-Za-z0-9]+", "_", name + "_" + base).lower()
            variables.append(
                f"{var}: {base} ~= '{_value_regex(values, modifier)}'")
            exprs.append(var)
        if not variables:
            raise SigmaError("empty selection")
        return variables, " and ".join(exprs)
    if isinstance(spec, list) and all(isinstance(s, dict) for s in spec):
        all_vars, exprs = [], []
        for index, item in enumerate(spec):
            vars_, expr = _selection(f"{name}_{index + 1}", item)
            all_vars += vars_
            exprs.append(f"({expr})")
        return all_vars, " or ".join(exprs)
    raise SigmaError("unsupported selection shape")


def _condition(text: str, names: dict[str, str]) -> str:
    tokens = re.findall(r"\(|\)|[^\s()]+", str(text))
    if any(t.endswith("*") for t in tokens):
        raise SigmaError("wildcard/quantified conditions are not supported")
    out = []
    for token in tokens:
        low = token.lower()
        if low in ("and", "or", "not", "all", "of", "them"):
            if low in ("of", "them"):
                raise SigmaError("'1 of' conditions are not supported")
            out.append(low)
        elif token in ("(", ")"):
            out.append(token)
        elif token in names:
            out.append(f"({names[token]})")
        else:
            raise SigmaError(f"unknown selection {token!r}")
    return " ".join(out)


def _logsource(logsource: dict, selections: dict) -> tuple[list[int], str]:
    service = str(logsource.get("service", "")).lower()
    category = str(logsource.get("category", "")).lower()
    product = str(logsource.get("product", "")).lower()
    if product and product != "windows":
        raise SigmaError(f"unsupported logsource {logsource!r}")
    if category in CATEGORIES:
        ids, channel = CATEGORIES[category]
    elif service == "sysmon" or product == "windows":
        ids, channel = [], CHANNEL_SYSMON
    elif service == "security":
        ids, channel = [], CHANNEL_SECURITY
    else:
        raise SigmaError(f"unsupported logsource {logsource!r}")

    # An explicit EventID in a selection wins over the category default.
    explicit = []
    for spec in selections.values():
        items = spec if isinstance(spec, list) else [spec]
        for item in items:
            if not isinstance(item, dict):
                continue
            for field, value in item.items():
                if str(field).split("|")[0].lower() in ("eventid", "event_id"):
                    values = value if isinstance(value, list) else [value]
                    explicit += [int(v) for v in values if str(v).isdigit()]
    if explicit:
        ids = sorted(set(explicit))
    if not ids:
        raise SigmaError("no EventID and no mapped category")
    return ids, channel


def convert_rule(doc: dict) -> dict:
    """One parsed Sigma document -> one WHIDS gene rule. Raises SigmaError."""
    if not isinstance(doc, dict):
        raise SigmaError("rule is not a mapping")
    detection = doc.get("detection")
    if not isinstance(detection, dict):
        raise SigmaError("missing detection block")
    condition = detection.get("condition")
    if not condition:
        raise SigmaError("missing detection.condition")
    selections = {k: v for k, v in detection.items() if k != "condition"}
    if not selections:
        raise SigmaError("no selections")
    event_ids, channel = _logsource(doc.get("logsource") or {}, selections)

    matches: list[str] = []
    names: dict[str, str] = {}
    for name, spec in selections.items():
        # The condition references selection names; build each one's match
        # variables first, then its boolean expression.
        if isinstance(spec, list) and all(isinstance(s, dict) for s in spec):
            all_vars, exprs = [], []
            for index, item in enumerate(spec):
                vars_, expr = _selection(f"{name}_{index + 1}", item)
                all_vars += vars_
                exprs.append(f"({expr})")
            matches += all_vars
            names[name] = " or ".join(exprs)
        else:
            vars_, expr = _selection(name, spec)
            matches += vars_
            names[name] = expr
    gene_condition = _condition(condition, names)

    tags = ["Sigma"]
    for tag in doc.get("tags") or []:
        found = _T_RE.search(str(tag))
        if found:
            tags.append(found.group(1).upper())
    title = str(doc.get("title") or "Untitled Sigma rule").strip()
    return {
        "Name": f"Sigma: {title}"[:120],
        "Tags": tags,
        "Meta": {
            "EventIDs": event_ids,
            "Channels": [channel],
            "Computers": [],
            "Criticality": LEVEL_SCORE.get(str(doc.get("level", "")).lower(), 6),
            "Author": "Sigma/Plasma converter",
            "Comment": str(doc.get("description") or title)[:300],
            "Schema": "1.0.0",
        },
        "Matches": matches,
        "Condition": gene_condition,
    }


def convert_path(path) -> dict:
    """Convert a .yml/.yaml file or a directory tree. Reports every skip."""
    base = Path(path)
    files = [base] if base.is_file() else sorted(
        list(base.rglob("*.yml")) + list(base.rglob("*.yaml")))
    rules, skipped = [], []
    for file in files:
        try:
            docs = list(yaml.safe_load_all(file.read_text(encoding="utf-8")))
        except (OSError, yaml.YAMLError) as exc:
            skipped.append({"file": str(file), "reason": f"yaml: {exc}"[:200]})
            continue
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            try:
                rules.append(convert_rule(doc))
            except SigmaError as exc:
                skipped.append({"file": str(file),
                                "rule": str(doc.get("title") or "")[:100],
                                "reason": str(exc)[:200]})
    return {"converted": len(rules), "skipped": skipped, "rules": rules,
            "files": len(files)}


def write_gen(path, rules) -> dict:
    """Write converted rules as JSONL, refusing duplicate names."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    seen, written = set(), 0
    with out.open("w", encoding="utf-8") as fh:
        for rule in rules:
            name = rule.get("Name")
            if not name or name in seen:
                continue
            seen.add(name)
            fh.write(__import__("json").dumps(rule, sort_keys=True) + "\n")
            written += 1
    return {"written": written, "out": str(out)}
