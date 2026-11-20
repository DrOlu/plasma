"""Plasma coverage: which ATT&CK techniques does Plasma actually watch?

Detection depth is not only more alerts — it is knowing your holes. This
module reads the shipped rule sets (tap rules + gene baseline + IOC feed),
collects the ATT&CK technique IDs they cover, and diffs that against a
curated core list of on-box Windows techniques. Output: covered / blind /
coverage percentage — one honest sentence about the sensor surface.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

# curated core on-box Windows techniques (detection-relevant, endpoint scope)
CORE_TECHNIQUES = {
    "T1003": "OS Credential Dumping",
    "T1003.001": "LSASS Memory",
    "T1003.002": "Security Account Manager (SAM)",
    "T1047": "Windows Management Instrumentation",
    "T1053.005": "Scheduled Task",
    "T1055": "Process Injection",
    "T1055.001": "Dynamic-link Library Injection",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1056": "Input Capture",
    "T1056.001": "Keylogging",
    "T1070": "Indicator Removal",
    "T1070.004": "File Deletion",
    "T1071": "Application Layer Protocol",
    "T1071.001": "Web Protocols",
    "T1071.004": "DNS",
    "T1021": "Remote Services",
    "T1078": "Valid Accounts",
    "T1078.003": "Local Accounts",
    "T1098": "Account Manipulation",
    "T1105": "Ingress Tool Transfer",
    "T1112": "Modify Registry",
    "T1134": "Access Token Manipulation",
    "T1136": "Create Account",
    "T1136.001": "Local Account",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1197": "BITS Jobs",
    "T1204.002": "Malicious File",
    "T1218.005": "Mshta",
    "T1218.011": "Rundll32",
    "T1486": "Data Encrypted for Impact",
    "T1543.003": "Windows Service",
    "T1546.003": "WMI Event Subscription",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1560.001": "Archive via Utility",
    "T1562.001": "Impair Defenses",
    "T1564.003": "Hidden Window",
}

_T_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

# Sysmon config element -> event IDs it enables. A rule whose EventIDs are
# not enabled by the shipped config cannot fire; that is inventory, not
# coverage. Derived from the config, never declared per rule.
SYSMON_EIDS = {
    "ProcessCreate": {1}, "FileCreateTime": {2}, "NetworkConnect": {3},
    "ProcessTerminate": {5}, "DriverLoad": {6}, "ImageLoad": {7},
    "CreateRemoteThread": {8}, "RawAccessRead": {9}, "ProcessAccess": {10},
    "FileCreate": {11}, "RegistryEvent": {12, 13, 14},
    "FileCreateStreamHash": {15}, "ServiceConfiguration": {16},
    "PipeEvent": {17, 18}, "WmiEvent": {19, 20, 21}, "DnsQuery": {22},
    "FileDelete": {23}, "ClipboardChange": {24}, "ProcessTampering": {25},
    "FileDeleteDetected": {26}, "FileBlockExecutable": {27},
    "FileBlockShredding": {28}, "FileExecutableDetected": {29},
}


def enabled_event_ids(sensors_dir=None,
                      filename: str = "sysmon-config.xml") -> set[int] | None:
    """Event IDs the shipped Sysmon config actually enables.

    None means the config is unavailable (custom sensor dir, non-Windows
    desk): telemetry is then unknown, not assumed live.
    """
    sensors = Path(sensors_dir) if sensors_dir else _repo_sensors()
    path = sensors / filename
    if not path.exists():
        return None
    try:
        if path.stat().st_size > (8 << 20):
            return None
        text = path.read_text(encoding="utf-8")
        # Sysmon configs never need a DTD or external entity. Refuse both
        # before handing the document to the XML parser.
        low = text.lower()
        if "<!doctype" in low or "<!entity" in low:
            return None
        root = ET.fromstring(text)  # nosec B314 - local config, DTD refused
    except (OSError, ET.ParseError):
        return None
    filtering = root.find("EventFiltering")
    if filtering is None:
        return None
    ids: set[int] = set()
    for child in filtering:
        if child.tag == "PipeEvent":
            # 17 = CreatePipe, 18 = ConnectPipe. An include filter that
            # names only one type does not enable the other.
            types = {el.text for el in child
                     if el.tag == "EventType" and el.text}
            if child.get("onmatch") == "include" and types:
                if "CreatePipe" in types:
                    ids.add(17)
                if "ConnectPipe" in types:
                    ids.add(18)
            else:
                ids |= {17, 18}
            continue
        ids |= SYSMON_EIDS.get(child.tag, set())
    return ids


def _telemetry(event_ids, enabled) -> str:
    if enabled is None:
        return "unknown"
    ids = set(event_ids or [])
    if not ids:
        return "unknown"
    live = ids & enabled
    if live == ids:
        return "live"
    return "partial" if live else "dormant"


def _repo_sensors() -> Path:
    """Locate the sensor payload on a dev checkout or an installed node.

    The frozen bundle keeps it at <_MEIPASS>/embedded/sensors; without that
    candidate `plasma coverage` failed on every installed host (WS2).
    """
    import sys
    candidates = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / "embedded" / "sensors")
    candidates += [Path(__file__).resolve().parent.parent / "sensors",
                   Path(__file__).resolve().parent / "sensors",
                   Path.cwd() / "sensors",
                   Path.cwd() / "embedded" / "sensors"]
    for cand in candidates:
        if (cand / "plasma-tap-rules.json").exists():
            return cand
    raise FileNotFoundError("plasma-tap-rules.json not found (repo or embedded)")


FIDELITY_WEIGHTS = {"high": 1.0, "medium": 0.7, "low": 0.4}
FIDELITY_RANK = {"high": 3, "medium": 2, "low": 1}

# Match keys a tap rule can carry. A rule whose matches are all `substr` is a
# keyword match over provider text; anything structured (field equals/regex)
# is behavioural evidence. Deriving this from the rule shape means the label
# cannot drift away from the rule the way a hand-maintained "evidence" field
# would.
TAP_MATCH_KEYS = ("substr", "regex", "equals", "contains", "startswith",
                  "endswith")
KEYWORD_MATCH_KEYS = {"substr"}


def rule_evidence(rule: dict) -> str:
    """Evidence class for one tap rule, derived from its match shape."""
    kinds = {key for key in TAP_MATCH_KEYS if key in rule}
    if not kinds:
        # Unknown shape: do not claim behavioural evidence we cannot see.
        return "keyword"
    return "keyword" if kinds <= KEYWORD_MATCH_KEYS else "behavioural"

# Gene rules carry no fidelity field in the WHIDS schema; the judgement lives
# here, next to the coverage math that consumes it.
GENE_FIDELITY = {
    "Plasma LOLBin Certutil": "high",
    "Plasma Office Spawning Shell": "high",
    "Plasma SAM Hive Dump": "high",
    "Plasma Bitsadmin Transfer": "medium",
    "Plasma Mshta Network": "high",
    "Plasma Rundll32 JS": "high",
    "Plasma Net Account Add": "high",
    "Plasma Encoded Cmd": "medium",
    "Plasma Scheduled Task Create": "medium",
    "Plasma Wmic Process Call": "medium",
    "Plasma File Delete by LOLBin": "medium",
    "Plasma Run Key Persistence": "high",
    "Plasma Service Registry Persistence": "high",
    "Plasma Privileged Group Add": "high",
    "Plasma Execution From User Paths": "medium",
    "Plasma LSASS Access": "high",
    "Plasma Unsigned Driver Load": "high",
    "Plasma Suspicious Named Pipe": "medium",
}


def _norm_fidelity(value) -> str:
    value = str(value or "").lower()
    return value if value in FIDELITY_WEIGHTS else "medium"


def collect_rule_techniques(sensors_dir=None) -> dict:
    """Technique -> [{"rule": label, "fidelity": high|medium|low}] across
    tap rules + gene baseline + IOC feed."""
    sensors = Path(sensors_dir) if sensors_dir else _repo_sensors()
    covered: dict[str, list[dict]] = {}

    enabled = enabled_event_ids(sensors)

    def add(tech, label, fidelity, evidence="behavioural", event_ids=None,
            telemetry=None):
        covered.setdefault(tech, []).append(
            {"rule": label, "fidelity": _norm_fidelity(fidelity),
             "evidence": ("keyword" if str(evidence).lower() == "keyword"
                          else "behavioural"),
             "telemetry": telemetry or _telemetry(event_ids, enabled)})

    tap_doc = json.loads((sensors / "plasma-tap-rules.json").read_text(encoding="utf-8"))
    for rule in tap_doc.get("rules", []):
        tech = rule.get("technique", "")
        if _T_RE.fullmatch(tech):
            add(tech, f"tap:{rule['name']}", rule.get("fidelity"),
                rule_evidence(rule), telemetry="live")

    def gene_file(path, label):
        if not path.exists():
            return
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            for tag in obj.get("Tags", []):
                if not _T_RE.fullmatch(str(tag)):
                    continue
                if label == "sigma":
                    # Converted SigmaHQ rules carry the upstream level as
                    # criticality; weight them by that, not by name.
                    try:
                        criticality = int((obj.get("Meta") or {}).get(
                            "Criticality", 6) or 6)
                    except (TypeError, ValueError):
                        criticality = 6
                    fidelity = ("high" if criticality >= 8 else
                                "medium" if criticality >= 6 else "low")
                else:
                    fidelity = GENE_FIDELITY.get(obj.get("Name"), "medium")
                add(tag, f"{label}:{obj.get('Name')}", fidelity,
                    event_ids=(obj.get("Meta") or {}).get("EventIDs"))

    gene_file(sensors / "plasma-baseline.gen", "gene")
    gene_file(sensors / "plasma-sigma.gen", "sigma")

    iocs = sensors / "plasma-iocs.gen"
    if iocs.exists():
        for line in iocs.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            for tag in obj.get("Tags", []):
                if _T_RE.fullmatch(str(tag)):
                    add(tag, f"ioc:{obj['Name']}", "high",
                        event_ids=(obj.get("Meta") or {}).get("EventIDs"))
    return covered


def _best_fidelity(rules: list[dict]) -> str:
    ranked = sorted((_norm_fidelity(r.get("fidelity")) for r in rules),
                    key=lambda f: FIDELITY_RANK[f], reverse=True)
    return ranked[0] if ranked else "medium"


# Capabilities that watch a technique without a Sysmon/ETW rule. They are
# reported with explicit provenance so a reader can see what backs the claim.
CAPABILITY_RULES = {
    "T1486": [{"rule": "canary:verify", "fidelity": "high",
               "telemetry": "live"}],
}


def coverage(sensors_dir=None) -> dict:
    """Coverage matrix over the curated core list.

    Two numbers are reported deliberately:
      * `coverage_exact_pct` — techniques with a rule tagged for that exact ID;
      * `coverage_pct` — the same, but a parent technique counts as covered
        when any of its sub-techniques is covered (ATT&CK rollup).
    `weighted_pct` additionally discounts low/medium-fidelity rules, so
    100% breadth can never mask weak evidence.
    """
    covered = collect_rule_techniques(sensors_dir)
    for tech, rules in CAPABILITY_RULES.items():
        covered.setdefault(tech, []).extend(dict(r) for r in rules)
    total = len(CORE_TECHNIQUES)

    exact_core = {t: rules for t, rules in covered.items() if t in CORE_TECHNIQUES}
    rollup_core: dict[str, list[dict]] = dict(exact_core)
    for parent in CORE_TECHNIQUES:
        if parent in rollup_core:
            continue
        subs = [rules for t, rules in covered.items()
                if t.startswith(parent + ".") and t in CORE_TECHNIQUES]
        if subs:
            rollup_core[parent] = [r for group in subs for r in group]

    blind = {t: CORE_TECHNIQUES[t] for t in CORE_TECHNIQUES if t not in rollup_core}
    extra = {t: rules for t, rules in covered.items() if t not in CORE_TECHNIQUES}

    covered_out = {}
    weighted_sum = 0.0
    weighted_all_sum = 0.0
    fidelity_breakdown = {"high": 0, "medium": 0, "low": 0}
    telemetry_breakdown = {"live": 0, "partial": 0, "dormant": 0, "unknown": 0}
    keyword_only = []
    dormant_techniques = []
    for t, rules in sorted(rollup_core.items()):
        best = _best_fidelity(rules)
        solely_keyword = all(
            str(r.get("evidence", "behavioural")).lower() == "keyword"
            for r in rules)
        # Telemetry is the third provenance axis: a rule whose event IDs the
        # shipped config does not enable cannot fire. Weight only what can
        # actually run; keep the all-rules number for comparison.
        live_rules = [r for r in rules if r.get("telemetry") == "live"]
        partial_rules = [r for r in rules if r.get("telemetry") == "partial"]
        if live_rules:
            telemetry = "live"
            weight = FIDELITY_WEIGHTS[_best_fidelity(live_rules)]
        elif partial_rules:
            telemetry = "partial"
            weight = 0.5 * FIDELITY_WEIGHTS[_best_fidelity(partial_rules)]
        elif any(r.get("telemetry") == "unknown" for r in rules):
            telemetry = "unknown"
            weight = FIDELITY_WEIGHTS[best]
        else:
            telemetry = "dormant"
            weight = 0.0
            dormant_techniques.append(t)
        # A keyword-only technique keeps its breadth but cannot carry the
        # same weight as behavioural evidence.
        weighted_sum += weight * (0.5 if solely_keyword else 1.0)
        weighted_all_sum += (FIDELITY_WEIGHTS[best]
                             * (0.5 if solely_keyword else 1.0))
        fidelity_breakdown[best] += 1
        telemetry_breakdown[telemetry] += 1
        if solely_keyword:
            keyword_only.append(t)
        covered_out[t] = {
            "name": CORE_TECHNIQUES[t],
            "rules": rules,
            "fidelity": best,
            "evidence": "keyword-only" if solely_keyword else "behavioural",
            "telemetry": telemetry,
            "via_subtechnique": t not in exact_core,
        }

    def pct(count):
        return round(100 * count / total, 1) if total else 0.0

    return {
        "core_total": total,
        "core_covered": len(rollup_core),
        "coverage_pct": pct(len(rollup_core)),
        "coverage_exact_pct": pct(len(exact_core)),
        "weighted_pct": round(100 * weighted_sum / total, 1) if total else 0.0,
        "weighted_all_pct": round(100 * weighted_all_sum / total, 1) if total else 0.0,
        "fidelity_breakdown": fidelity_breakdown,
        "telemetry_breakdown": telemetry_breakdown,
        "dormant_techniques": dormant_techniques,
        "evidence_breakdown": {
            "behavioural": len(rollup_core) - len(keyword_only),
            "keyword_only": len(keyword_only),
        },
        "keyword_only": keyword_only,
        "covered": covered_out,
        "blind": dict(sorted(blind.items())),
        "extra_coverage": {t: rules for t, rules in sorted(extra.items())},
    }
