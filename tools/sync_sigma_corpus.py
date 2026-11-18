#!/usr/bin/env python3
"""Rebuild sensors/plasma-sigma.gen from a SigmaHQ checkout.

The converter is deliberately conservative: rules with unsupported log
sources, modifiers or quantified conditions are skipped and counted, never
silently mistranslated. The output is data under DRL 1.1, not MIT.

Typical use:

    git clone https://github.com/SigmaHQ/sigma /tmp/sigma
    git -C /tmp/sigma rev-parse HEAD
    python tools/sync_sigma_corpus.py --source /tmp/sigma/rules/windows \\
        --commit <sha>

Requires PyYAML (the converter imports it lazily).
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from plasma import sigma

ALLOWED_IDS = {1, 3, 6, 7, 10, 11, 12, 13, 14, 17, 18}


def primary_technique(rule):
    tags = [t for t in rule["Tags"]
            if t.startswith("T") and (t[1:].isdigit() or "." in t)]
    return tags[0] if tags else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True,
                    help="path to SigmaHQ/rules/windows")
    ap.add_argument("--commit", required=True, help="upstream commit SHA")
    ap.add_argument("--max", type=int, default=300)
    ap.add_argument("--per-technique", type=int, default=2)
    ap.add_argument("--min-criticality", type=int, default=6)
    args = ap.parse_args()

    result = sigma.convert_path(args.source)
    candidates = []
    for rule in result["rules"]:
        ids = set(rule["Meta"]["EventIDs"])
        if rule["Meta"]["Criticality"] < args.min_criticality:
            continue
        if not ids or not ids <= ALLOWED_IDS:
            continue
        if not primary_technique(rule):
            continue
        candidates.append(rule)

    seen, deduped = set(), []
    for rule in candidates:
        key = (tuple(rule["Meta"]["EventIDs"]),
               tuple(sorted(rule["Matches"])), rule["Condition"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(rule)

    groups = collections.defaultdict(list)
    for rule in deduped:
        groups[primary_technique(rule)].append(rule)
    for tech in groups:
        groups[tech].sort(key=lambda r: (-r["Meta"]["Criticality"], r["Name"]))

    selected = []
    for round_index in range(args.per_technique):
        for tech in sorted(groups):
            if round_index < len(groups[tech]):
                selected.append(groups[tech][round_index])
                if len(selected) >= args.max:
                    break
        if len(selected) >= args.max:
            break

    counts = collections.Counter()
    for rule in selected:
        counts[rule["Name"]] += 1
        if counts[rule["Name"]] > 1:
            rule["Name"] = f"{rule['Name']} #{counts[rule['Name']]}"

    out = ROOT / "sensors" / "plasma-sigma.gen"
    out.write_text("".join(json.dumps(r, sort_keys=True) + "\n"
                           for r in selected), encoding="utf-8")

    meta = {
        "upstream": "https://github.com/SigmaHQ/sigma",
        "commit": args.commit,
        "path": "rules/windows",
        "generated": "2026-11-15",
        "license": "Detection Rule License (DRL) 1.1",
        "license_file": "sensors/SIGMA-DRL-1.1.md",
        "files_scanned": result["files"],
        "converted": result["converted"],
        "candidates_after_filter": len(deduped),
        "selected": len(selected),
        "levels": dict(collections.Counter(
            r["Meta"]["Criticality"] for r in selected)),
        "techniques": len({primary_technique(r) for r in selected}),
        "selection": (f"Windows/Sysmon categories, level "
                      f"{args.min_criticality}+, Sysmon event IDs "
                      f"{sorted(ALLOWED_IDS)}, one primary technique per "
                      f"rule, deduplicated, up to {args.per_technique} per "
                      f"technique, cap {args.max}"),
        "skipped_reasons": dict(collections.Counter(
            s["reason"].split(":")[0] for s in result["skipped"])),
        "note": ("Converted rules preserve the upstream author and name the "
                 "source file in Meta.Comment. This file is data under DRL "
                 "1.1, not MIT; see the license file."),
    }
    (ROOT / "sensors" / "sigma-sources.json").write_text(
        json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(meta, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
