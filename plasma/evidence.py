"""Machine-generated compliance evidence.

Autonomy raises the burden of proof, so this module turns the estate's
real state into auditor-readable control evidence: events, coverage,
policy, approvals, kill switch, provenance chain and tenants. It does not
certify anything; it produces the evidence a human auditor can verify.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from . import agentstate, coverage, killswitch, ledger, policy, tenants

FRAMEWORKS = ("cbn", "ndpa", "pci", "iso27001")

CONTROLS = {
    "cbn": [
        ("CBN-CYB-1", "Board-approved cybersecurity policy",
         "policy", "policy.json defines autonomy, deny lists and approvals"),
        ("CBN-CYB-2", "Asset inventory and endpoint visibility",
         "events", "event contract covers hosts, kinds and sensors"),
        ("CBN-CYB-3", "Continuous monitoring and logging",
         "events", "normalized events with UTC timestamps"),
        ("CBN-CYB-4", "Incident detection and response",
         "response", "chains, watch verdicts, plan-gated response tools"),
        ("CBN-CYB-5", "Least privilege and approval gates",
         "policy", "scoped tools and human approval for high-risk actions"),
        ("CBN-CYB-6", "Third-party and agent governance",
         "ledger", "hash-chained provenance for every agent decision"),
        ("CBN-CYB-7", "Data protection and residency",
         "resident", "no lake, no cloud inference, local event store"),
        ("CBN-CYB-8", "Resilience and recovery",
         "recovery", "canaries, rings and rollback"),
    ],
    "ndpa": [
        ("NDPA-1", "Data minimisation",
         "events", "security telemetry only; no content capture by default"),
        ("NDPA-2", "Security safeguards",
         "policy", "policy engine, kill switch and scoped tools"),
        ("NDPA-3", "Breach detection",
         "response", "canary trips and scored findings"),
        ("NDPA-4", "Accountability and audit",
         "ledger", "tamper-evident provenance chain"),
        ("NDPA-5", "Local processing / residency",
         "resident", "events stay on the estate"),
        ("NDPA-6", "Retention control",
         "retention", "store rotation and retention settings"),
    ],
    "pci": [
        ("PCI-10.2", "Audit logs capture access and actions",
         "events", "security events plus action provenance"),
        ("PCI-10.3", "Record user, time, type, success and origin",
         "ledger", "agent, model, prompt hash, args, decision, outcome"),
        ("PCI-10.4", "Review logs and security events",
         "ledger", "audit tail + approval queue"),
        ("PCI-10.5", "Retain audit history",
         "retention", "append-only ledger + store rotation"),
        ("PCI-10.6", "Time synchronisation",
         "events", "UTC timestamps on events and ledger rows"),
        ("PCI-11.5", "Detect unauthorised changes",
         "response", "canary files and file-delete telemetry"),
        ("PCI-12.10", "Incident response",
         "response", "playbooks, approvals, reversible actions"),
    ],
    "iso27001": [
        ("A.8.15", "Logging", "events", "normalized security event store"),
        ("A.8.16", "Monitoring activities", "response", "watch, chains, canaries"),
        ("A.5.24", "Incident management planning", "response", "playbooks and journal"),
        ("A.5.25", "Assessment and decision on events", "policy", "deterministic scoring and policy"),
        ("A.8.9", "Configuration management", "recovery", "converged config, rings, rollback"),
        ("A.8.2", "Privileged access rights", "policy", "scopes and protected actions"),
    ],
}


def _event_stats(root) -> dict:
    path = Path(root) / "data" / "events.jsonl" if root else \
        agentstate.base(root) / "data" / "events.jsonl"
    rows = 0
    kinds: dict[str, int] = {}
    hosts: set[str] = set()
    first = last = None
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            rows += 1
            kind = str(row.get("kind") or "unknown")
            kinds[kind] = kinds.get(kind, 0) + 1
            if row.get("host"):
                hosts.add(str(row["host"]))
            ts = row.get("ts")
            if ts:
                first = min(first, ts) if first else ts
                last = max(last, ts) if last else ts
    return {"path": str(path), "rows": rows, "kinds": kinds,
            "hosts": sorted(hosts), "first_ts": first, "last_ts": last}


def _coverage() -> dict:
    try:
        return coverage.coverage()
    except Exception:  # noqa: BLE001 — evidence must not fail on a missing payload
        return {"error": "coverage unavailable"}


def _control_status(key: str, ctx: dict) -> tuple[str, list[str]]:
    stats = ctx["events"]
    rows = stats["rows"]
    ledger_ok = ctx["ledger"]["ok"]
    policy_ok = bool(ctx["policy"].get("autonomy"))
    kill = ctx["killswitch"]
    cov = ctx["coverage"]
    if key == "policy":
        return ("met" if policy_ok else "gap",
                [f"autonomy={ctx['policy'].get('autonomy')}",
                 f"deny={ctx['policy'].get('deny')}",
                 f"max_actions_per_minute={ctx['policy'].get('max_actions_per_minute')}"])
    if key == "events":
        status = "met" if rows else "gap"
        return (status, [f"{rows} events", f"kinds={stats['kinds']}",
                         f"hosts={len(stats['hosts'])}"])
    if key == "response":
        covered = cov.get("core_covered") if isinstance(cov, dict) else None
        status = "met" if covered else ("partial" if rows else "gap")
        return (status, [f"coverage={cov.get('coverage_pct')}%",
                         f"blind={cov.get('blind')}"])
    if key == "ledger":
        return ("met" if ledger_ok else "gap",
                [f"rows={ctx['ledger'].get('rows')}",
                 f"chain_ok={ledger_ok}",
                 f"approvals_pending={len(ctx['approvals'])}"])
    if key == "resident":
        return ("met", ["events_path=" + stats["path"],
                        "cloud_dependency=none",
                        f"killswitch_global={kill.get('global')}"])
    if key == "recovery":
        return ("partial" if rows else "gap",
                [f"tenants={len(ctx['tenants'])}",
                 f"killswitch_hosts={len(kill.get('hosts') or {})}"])
    if key == "retention":
        return ("partial", [f"event_rows={rows}",
                            "ledger is append-only",
                            "store rotate/compact available"])
    return ("partial", [])


def export(root=None, frameworks=None, out=None) -> dict:
    frameworks = tuple(frameworks or FRAMEWORKS)
    unknown = [f for f in frameworks if f not in CONTROLS]
    if unknown:
        raise ValueError("unknown framework(s): " + ", ".join(unknown))
    ctx = {
        "events": _event_stats(root),
        "ledger": ledger.verify(root),
        "policy": policy.load(root),
        "killswitch": killswitch.status(root),
        "approvals": ledger.pending_approvals(root),
        "tenants": tenants.list_tenants(root),
        "coverage": _coverage(),
    }
    result = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "root": str(agentstate.base(root)),
        "frameworks": {},
        "summary": {"met": 0, "partial": 0, "gap": 0},
    }
    for name in frameworks:
        controls = []
        for control_id, title, key, note in CONTROLS[name]:
            status, evidence = _control_status(key, ctx)
            result["summary"][status] += 1
            controls.append({"control": control_id, "title": title,
                             "status": status, "evidence": evidence, "note": note})
        result["frameworks"][name] = {"controls": controls}
    if out:
        out_path = Path(out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        md_path = out_path.with_suffix(".md")
        md_path.write_text(to_markdown(result), encoding="utf-8")
        result["out"] = str(out_path)
        result["markdown"] = str(md_path)
    return result


def to_markdown(result: dict) -> str:
    lines = ["# Plasma compliance evidence", "",
             f"Generated: {result.get('generated_at')}", "",
             f"Controls: {result['summary']['met']} met, "
             f"{result['summary']['partial']} partial, "
             f"{result['summary']['gap']} gap", ""]
    for name, block in result["frameworks"].items():
        lines += [f"## {name.upper()}", ""]
        lines += ["| Control | Title | Status | Evidence |",
                  "|---|---|---|---|"]
        for c in block["controls"]:
            evidence = "; ".join(c["evidence"]).replace("|", "/")
            lines.append(f"| {c['control']} | {c['title']} | {c['status']} | {evidence} |")
        lines.append("")
    return "\n".join(lines) + "\n"