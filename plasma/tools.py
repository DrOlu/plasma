"""Capability contract for agent-driven Plasma.

Every action an agent can take is a typed tool with a scope, a risk tier,
a JSON schema, and explicit refusal semantics. The harness can only call
what is in this registry; it cannot invent actions and it cannot pass
arbitrary shell.

Mutating tools are ``dry_run_only`` in the MCP surface: the agent gets a
plan and an approval reference. Execution stays behind the CLI's
plan/approval gate. That keeps an autonomous harness useful without
letting a hallucinating or prompt-injected model change a host.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

RISK_ORDER = {"read": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class ToolError(ValueError):
    """Invalid tool name or arguments — refused, never guessed."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    scopes: tuple[str, ...]
    risk: str = "read"
    input_schema: dict[str, Any] = field(default_factory=dict)
    idempotent: bool = True
    dry_run_only: bool = False
    reversible: bool = False
    preconditions: tuple[str, ...] = ()
    postconditions: tuple[str, ...] = ()

    def to_mcp(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": {
                "risk": self.risk,
                "scopes": list(self.scopes),
                "idempotent": self.idempotent,
                "dry_run_only": self.dry_run_only,
                "reversible": self.reversible,
            },
        }


def _schema(properties: dict | None = None, required: list[str] | None = None) -> dict:
    return {
        "type": "object",
        "properties": properties or {},
        "required": required or [],
        "additionalProperties": False,
    }


TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "read_events",
        "Read the bounded tail of the local events contract.",
        ("events:read",),
        "read",
        _schema({"limit": {"type": "integer", "minimum": 1, "maximum": 1000},
                 "since_minutes": {"type": "integer", "minimum": 1, "maximum": 10080},
                 "kind": {"type": "string", "maxLength": 32}}),
    ),
    ToolSpec(
        "list_findings",
        "List scored findings above a threshold from the local store.",
        ("events:read",),
        "read",
        _schema({"min_score": {"type": "number", "minimum": 0, "maximum": 1},
                 "limit": {"type": "integer", "minimum": 1, "maximum": 1000}}),
    ),
    ToolSpec(
        "get_health",
        "Return the node health verdict and checks.",
        ("health:read",),
        "read",
        _schema(),
    ),
    ToolSpec(
        "read_policy",
        "Return the active autonomy policy and kill-switch state.",
        ("policy:read",),
        "read",
        _schema(),
    ),
    ToolSpec(
        "list_approvals",
        "List actions waiting for a human decision.",
        ("approvals:read",),
        "read",
        _schema({"limit": {"type": "integer", "minimum": 1, "maximum": 500}}),
    ),
    ToolSpec(
        "audit_tail",
        "Read the provenance ledger tail. Hash-chained and tenant-scoped.",
        ("audit:read",),
        "read",
        _schema({"limit": {"type": "integer", "minimum": 1, "maximum": 500}}),
    ),
    ToolSpec(
        "deploy_canary",
        "Plan canary/decoy deployment for impact detection (T1486).",
        ("response:canary",),
        "medium",
        _schema({"extra_dirs": {"type": "array",
                                "items": {"type": "string", "maxLength": 260},
                                "maxItems": 10}}),
        idempotent=True,
        dry_run_only=True,
        reversible=True,
        postconditions=("canaries are present and hashed",),
    ),
    ToolSpec(
        "contain_user",
        "Plan containment of a local account (disable, then snapshot).",
        ("response:identity",),
        "high",
        _schema({"user": {"type": "string", "minLength": 1, "maxLength": 128}}, ["user"]),
        idempotent=True,
        dry_run_only=True,
        reversible=True,
        preconditions=("account is not on the protected list",),
        postconditions=("account disabled; undo payload journaled",),
    ),
    ToolSpec(
        "isolate_host",
        "Plan network isolation while keeping RDP/WinRM management open.",
        ("response:network",),
        "critical",
        _schema({"host": {"type": "string", "minLength": 1, "maxLength": 128}}, ["host"]),
        idempotent=True,
        dry_run_only=True,
        reversible=True,
        preconditions=("management ports stay allowed",),
        postconditions=("isolation rules journaled with undo",),
    ),
    ToolSpec(
        "quarantine_file",
        "Plan moving a file to the quarantine directory.",
        ("response:file",),
        "high",
        _schema({"path": {"type": "string", "minLength": 1, "maxLength": 512}}, ["path"]),
        idempotent=True,
        dry_run_only=True,
        reversible=True,
    ),
    ToolSpec(
        "kill_process",
        "Plan terminating a process after capturing identity evidence.",
        ("response:process",),
        "critical",
        _schema({"pid": {"type": "integer", "minimum": 1, "maximum": 2147483647}}, ["pid"]),
        idempotent=False,
        dry_run_only=True,
        reversible=False,
        preconditions=("process is not on the protected list",),
    ),
)

TOOL_BY_NAME = {t.name: t for t in TOOLS}


def get(name: str) -> ToolSpec:
    spec = TOOL_BY_NAME.get(name)
    if spec is None:
        raise ToolError(f"unknown tool {name!r}")
    return spec


def list_tools() -> list[ToolSpec]:
    return list(TOOLS)


def action_fingerprint(name: str, args: dict) -> str:
    payload = json.dumps({"tool": name, "args": args}, sort_keys=True,
                         separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _type_ok(value: Any, typ: str) -> bool:
    if typ == "string":
        return isinstance(value, str)
    if typ == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if typ == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if typ == "boolean":
        return isinstance(value, bool)
    if typ == "array":
        return isinstance(value, list)
    if typ == "object":
        return isinstance(value, dict)
    return True


def validate_args(name: str, args: dict | None) -> dict:
    """Validate arguments against the tool schema. Raises ToolError."""
    spec = get(name)
    args = {} if args is None else args
    if not isinstance(args, dict):
        raise ToolError("arguments must be a JSON object")
    schema = spec.input_schema
    props = schema.get("properties", {})
    required = set(schema.get("required", []))
    if schema.get("additionalProperties") is False:
        extra = set(args) - set(props)
        if extra:
            raise ToolError(f"unexpected argument(s): {', '.join(sorted(extra))}")
    missing = required - set(args)
    if missing:
        raise ToolError(f"missing required argument(s): {', '.join(sorted(missing))}")
    for key, value in args.items():
        rule = props.get(key, {})
        typ = rule.get("type")
        if typ and not _type_ok(value, typ):
            raise ToolError(f"{key} must be {typ}")
        if typ == "string":
            if "minLength" in rule and len(value) < rule["minLength"]:
                raise ToolError(f"{key} is too short")
            if "maxLength" in rule and len(value) > rule["maxLength"]:
                raise ToolError(f"{key} is too long")
        if typ in ("integer", "number"):
            if "minimum" in rule and value < rule["minimum"]:
                raise ToolError(f"{key} is below the minimum")
            if "maximum" in rule and value > rule["maximum"]:
                raise ToolError(f"{key} is above the maximum")
        if typ == "array":
            if "maxItems" in rule and len(value) > rule["maxItems"]:
                raise ToolError(f"{key} has too many items")
            item_type = (rule.get("items") or {}).get("type")
            if item_type and not all(_type_ok(v, item_type) for v in value):
                raise ToolError(f"{key} items must be {item_type}")
    return args