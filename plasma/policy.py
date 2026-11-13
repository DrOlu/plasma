"""Deterministic autonomy policy for agent-driven Plasma.

The model never authorises an action. This module decides, using a local
JSON policy: autonomy tier, deny/allow lists, scope checks, blast-radius
limits, rate limits and risk-tier approval rules. The decision is recorded
in the provenance ledger before anything is returned to the harness.
"""

from __future__ import annotations

import copy
from pathlib import Path

from . import agentstate, tools

POLICY_FILE = "policy.json"

DEFAULT_POLICY: dict = {
    "version": 1,
    "autonomy": "supervised",          # assist | supervised | autonomous
    "allow": [],                        # tool names explicitly allowed
    "deny": [],                         # tool names (or "*") refused
    "require_approval": {"high": True, "critical": True},
    "allow_critical": False,
    "max_actions_per_minute": 30,
    "max_hosts_per_action": 1,
}

AUTONOMY = ("assist", "supervised", "autonomous")


def policy_path(root=None) -> Path:
    return agentstate.base(root) / POLICY_FILE


def load(root=None) -> dict:
    data = agentstate.read_json(policy_path(root), {}) or {}
    merged = copy.deepcopy(DEFAULT_POLICY)
    if isinstance(data, dict):
        for key, value in data.items():
            merged[key] = value
    if merged.get("autonomy") not in AUTONOMY:
        merged["autonomy"] = "supervised"
    return merged


def save(root, policy: dict) -> dict:
    merged = copy.deepcopy(DEFAULT_POLICY)
    merged.update(policy or {})
    if merged.get("autonomy") not in AUTONOMY:
        raise ValueError("autonomy must be assist, supervised or autonomous")
    agentstate.write_json(policy_path(root), merged)
    return merged


def _scopes_ok(tool: tools.ToolSpec, context: dict) -> tuple[bool, list[str]]:
    scopes = context.get("scopes") or ["*"]
    if "*" in scopes:
        return True, []
    missing = [s for s in tool.scopes if s not in scopes]
    return not missing, missing


def evaluate(tool_name: str, args: dict | None, context: dict | None = None,
             policy: dict | None = None, recent_actions: int = 0,
             killswitch_blocked: bool = False) -> dict:
    """Return a deterministic decision. The model is never consulted."""
    policy = policy or load()
    context = context or {}
    args = args or {}
    reasons: list[str] = []
    risk = "critical"
    try:
        spec = tools.get(tool_name)
        risk = spec.risk
    except tools.ToolError:
        return {"allowed": False, "approval_required": False, "code": "denied",
                "risk": "unknown", "autonomy": policy.get("autonomy"),
                "reasons": [f"unknown tool {tool_name!r}"],
                "policy_sha256": agentstate.sha256_obj(policy)}

    deny = set(policy.get("deny") or [])
    if "*" in deny or tool_name in deny:
        reasons.append("tool is on the deny list")
        return _decision(False, False, "denied", spec, policy, reasons)

    ok, missing = _scopes_ok(spec, context)
    if not ok:
        reasons.append("missing scope(s): " + ", ".join(missing))
        return _decision(False, False, "denied", spec, policy, reasons)

    if killswitch_blocked and risk != "read":
        reasons.append("kill switch is engaged for this host")
        return _decision(False, False, "denied", spec, policy, reasons)

    hosts = []
    if isinstance(args.get("hosts"), list):
        hosts = args["hosts"]
    elif args.get("host"):
        hosts = [args["host"]]
    cap = int(policy.get("max_hosts_per_action") or 1)
    if len(hosts) > cap:
        reasons.append(f"blast radius {len(hosts)} exceeds limit {cap}")
        return _decision(False, False, "denied", spec, policy, reasons)

    limit = int(policy.get("max_actions_per_minute") or 0)
    if limit and recent_actions >= limit:
        reasons.append(f"rate limit reached ({limit}/min)")
        return _decision(False, False, "denied", spec, policy, reasons)

    if risk == "read":
        return _decision(True, False, "allow", spec, policy, ["read-only tool"])

    allow = set(policy.get("allow") or [])
    if tool_name in allow and risk != "critical":
        return _decision(True, False, "allow", spec, policy,
                         ["tool is explicitly allowed"])

    autonomy = policy.get("autonomy", "supervised")
    if autonomy == "assist":
        return _decision(False, True, "approval_required", spec, policy,
                         ["assist mode: every action needs approval"])

    if autonomy == "supervised":
        needs = bool((policy.get("require_approval") or {}).get(risk, False))
        if needs:
            return _decision(False, True, "approval_required", spec, policy,
                             [f"{risk}-risk action in supervised mode"])
        return _decision(True, False, "allow", spec, policy,
                         [f"{risk}-risk action permitted in supervised mode"])

    # autonomous
    if risk == "critical" and not policy.get("allow_critical", False):
        return _decision(False, True, "approval_required", spec, policy,
                         ["critical action requires approval unless allow_critical"])
    if tool_name in allow:
        return _decision(True, False, "allow", spec, policy,
                         ["tool is explicitly allowed"])
    return _decision(True, False, "allow", spec, policy,
                     [f"autonomous mode permits {risk}-risk actions"])


def _decision(allowed: bool, approval: bool, code: str, spec: tools.ToolSpec,
              policy: dict, reasons: list[str]) -> dict:
    return {
        "allowed": bool(allowed),
        "approval_required": bool(approval),
        "code": code,
        "risk": spec.risk,
        "autonomy": policy.get("autonomy"),
        "reasons": reasons,
        "policy_sha256": agentstate.sha256_obj(policy),
    }