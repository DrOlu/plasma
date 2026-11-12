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


def _repo_sensors() -> Path:
    here = Path(__file__).resolve().parent.parent
    cand = here / "sensors"
    if (cand / "plasma-tap-rules.json").exists():
        return cand
    # frozen/embedded layout
    for base in (Path(__file__).resolve().parent, Path.cwd()):
        cand = base / "sensors"
        if (cand / "plasma-tap-rules.json").exists():
            return cand
    raise FileNotFoundError("plasma-tap-rules.json not found (repo or embedded)")


FIDELITY_WEIGHTS = {"high": 1.0, "medium": 0.7, "low": 0.4}
FIDELITY_RANK = {"high": 3, "medium": 2, "low": 1}

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
}


def _norm_fidelity(value) -> str:
    value = str(value or "").lower()
    return value if value in FIDELITY_WEIGHTS else "medium"


def collect_rule_techniques(sensors_dir=None) -> dict:
    """Technique -> [{"rule": label, "fidelity": high|medium|low}] across
    tap rules + gene baseline + IOC feed."""
    sensors = Path(sensors_dir) if sensors_dir else _repo_sensors()
    covered: dict[str, list[dict]] = {}

    def add(tech, label, fidelity):
        covered.setdefault(tech, []).append(
            {"rule": label, "fidelity": _norm_fidelity(fidelity)})

    tap_doc = json.loads((sensors / "plasma-tap-rules.json").read_text(encoding="utf-8"))
    for rule in tap_doc.get("rules", []):
        tech = rule.get("technique", "")
        if _T_RE.fullmatch(tech):
            add(tech, f"tap:{rule['name']}", rule.get("fidelity"))

    gen = sensors / "plasma-baseline.gen"
    if gen.exists():
        for line in gen.read_text(encoding="utf-8").splitlines():
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
                    add(tag, f"gene:{obj['Name']}",
                        GENE_FIDELITY.get(obj.get("Name"), "medium"))

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
                    add(tag, f"ioc:{obj['Name']}", "high")
    return covered


def _best_fidelity(rules: list[dict]) -> str:
    ranked = sorted((_norm_fidelity(r.get("fidelity")) for r in rules),
                    key=lambda f: FIDELITY_RANK[f], reverse=True)
    return ranked[0] if ranked else "medium"


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
    fidelity_breakdown = {"high": 0, "medium": 0, "low": 0}
    for t, rules in sorted(rollup_core.items()):
        best = _best_fidelity(rules)
        weighted_sum += FIDELITY_WEIGHTS[best]
        fidelity_breakdown[best] += 1
        covered_out[t] = {
            "name": CORE_TECHNIQUES[t],
            "rules": rules,
            "fidelity": best,
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
        "fidelity_breakdown": fidelity_breakdown,
        "covered": covered_out,
        "blind": dict(sorted(blind.items())),
        "extra_coverage": {t: rules for t, rules in sorted(extra.items())},
    }
