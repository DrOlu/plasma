"""Assurance artifacts: SBOM, safety case and a redacted support bundle."""

from __future__ import annotations

import json
import platform
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, agentstate, coverage, health, killswitch, ledger, policy, rings, tenants

THIRD_PARTY = [
    {"name": "WHIDS", "version": "1.7.0", "license": "AGPL-3.0",
     "note": "bundled detection payload; source offer required"},
    {"name": "pydantic", "license": "MIT"},
    {"name": "pydantic-core", "license": "MIT"},
    {"name": "pywinrm", "license": "MIT", "note": "optional desk-side dependency"},
    {"name": "neuralOS engine/model", "license": "see bundled notices",
     "note": "frozen on-device model; selection only"},
]


def sbom(root=None) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    components = []
    for item in THIRD_PARTY:
        component = {"type": "library", "name": item["name"]}
        if item.get("version"):
            component["version"] = item["version"]
        component["licenses"] = [{"license": {"id": item["license"]}}]
        if item.get("note"):
            component["description"] = item["note"]
        components.append(component)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "component": {
                "type": "application",
                "name": "plasma",
                "version": __version__,
                "licenses": [{"license": {"id": "MIT"}}],
            },
        },
        "components": components,
    }


def write_sbom(root=None, out=None) -> dict:
    data = sbom(root)
    if out:
        path = Path(out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        data = dict(data)
        data["out"] = str(path)
    return data


def third_party_notices() -> str:
    lines = ["# Third-party notices", ""]
    for item in THIRD_PARTY:
        lines.append(f"- **{item['name']}** — {item['license']}"
                     + (f" ({item['note']})" if item.get("note") else ""))
    return "\n".join(lines) + "\n"


def support_bundle(root=None, out=None) -> dict:
    base = agentstate.base(root)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = Path(out) if out else base / "support" / f"plasma-support-{stamp}.zip"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {}
    for name in ("config.json", "policy.json", "killswitch.json",
                 "tenants.json", "rings.json"):
        path = base / name
        if path.exists():
            try:
                payload[name] = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                payload[name] = {"error": "unreadable"}
    payload["ledger_tail"] = ledger.tail(root, 200)
    payload["ledger_verify"] = ledger.verify(root)
    payload["rings"] = rings.status(root)
    payload["tenants"] = tenants.list_tenants(root)
    payload["killswitch"] = killswitch.status(root)
    try:
        payload["health"] = health.verdict(root)
    except Exception:  # noqa: BLE001 — a support bundle must still build
        payload["health"] = {"error": "health unavailable"}
    try:
        payload["coverage"] = coverage.coverage()
    except Exception:  # noqa: BLE001
        payload["coverage"] = {"error": "coverage unavailable"}
    payload["system"] = {
        "version": __version__,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("support.json", json.dumps(payload, indent=2, default=str))
        zf.writestr("README.txt",
                    "Plasma support bundle. No passwords or API tokens are included.\n"
                    "Ledger and policy are included for provenance review.\n")
    return {"ok": True, "out": str(out_path),
            "bytes": out_path.stat().st_size,
            "ledger_ok": payload["ledger_verify"].get("ok")}


def safety_case(root=None, out=None) -> dict:
    from . import evals
    evaluation = evals.run(root)
    policy_state = policy.load(root)
    lines = [
        "# Plasma agent safety case",
        "",
        f"Version: {__version__}",
        "",
        "## Claim",
        "",
        "An agent harness can investigate and respond on a Plasma node without",
        "gaining arbitrary execution, unbounded blast radius, or an unauditable",
        "action path.",
        "",
        "## Controls",
        "",
        f"- Autonomy tier: **{policy_state.get('autonomy')}**",
        f"- Tools are typed and scoped; mutating tools are dry-run-only in MCP.",
        f"- High/critical actions require approval: {policy_state.get('require_approval')}",
        f"- Blast radius limit: {policy_state.get('max_hosts_per_action')} host(s)",
        f"- Rate limit: {policy_state.get('max_actions_per_minute')} actions/min",
        "- Every decision and action is appended to a hash-chained ledger.",
        "- A global/per-host kill switch blocks mutating actions.",
        "- Telemetry is untrusted data; tool arguments are schema-validated.",
        "",
        "## Evaluation",
        "",
        f"- Scenarios: {evaluation['total']}, passed: {evaluation['passed']}, failed: {evaluation['failed']}",
        "",
        "## Known limits",
        "",
        "- No kernel driver or memory scanning.",
        "- ATT&CK coverage is rollup-weighted with named blind spots.",
        "- Windows-only today.",
        "- WHIDS is bundled under AGPL-3.0.",
        "- Autonomous containment should begin at the supervised tier.",
        "",
    ]
    text = "\n".join(lines)
    if out:
        path = Path(out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return {"ok": evaluation["failed"] == 0, "evaluation": evaluation,
            "out": str(out) if out else None, "markdown": text}