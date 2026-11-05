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


def collect_rule_techniques(sensors_dir=None) -> dict:
    """Technique -> list of rule names across tap rules + gene baseline."""
    sensors = Path(sensors_dir) if sensors_dir else _repo_sensors()
    covered: dict[str, list[str]] = {}

    tap_doc = json.loads((sensors / "plasma-tap-rules.json").read_text(encoding="utf-8"))
    for rule in tap_doc.get("rules", []):
        tech = rule.get("technique", "")
        if _T_RE.fullmatch(tech):
            covered.setdefault(tech, []).append(f"tap:{rule['name']}")

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
                    covered.setdefault(tag, []).append(f"gene:{obj['Name']}")

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
                    covered.setdefault(tag, []).append(f"ioc:{obj['Name']}")
    return covered


def coverage(sensors_dir=None) -> dict:
    """Coverage matrix over the curated core technique list."""
    covered = collect_rule_techniques(sensors_dir)
    core_covered = {t: names for t, names in covered.items() if t in CORE_TECHNIQUES}
    blind = {t: CORE_TECHNIQUES[t] for t in CORE_TECHNIQUES if t not in core_covered}
    extra = {t: cov_names for t, cov_names in covered.items()
             if t not in CORE_TECHNIQUES}
    total = len(CORE_TECHNIQUES)
    pct = round(100 * len(core_covered) / total, 1) if total else 0.0
    return {
        "core_total": total,
        "core_covered": len(core_covered),
        "coverage_pct": pct,
        "covered": {t: {"name": CORE_TECHNIQUES[t], "rules": names}
                    for t, names in sorted(core_covered.items())},
        "blind": dict(sorted(blind.items())),
        "extra_coverage": {t: names for t, names in sorted(extra.items())},
    }
