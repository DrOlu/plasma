"""Harness-agnostic MCP server for Plasma.

JSON-RPC over stdio. The harness lists the typed tools, calls one, and gets
back a schema-validated result or a structured refusal/approval request.
Policy, kill switch and provenance are enforced here, not in the model.

Mutating tools are dry-run-only in this surface: the agent gets a plan and
an approval reference. Execution stays behind the CLI gate.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, agentstate, health, killswitch, ledger, policy, tenants, tools

PROTOCOL_VERSION = "2024-11-05"


def _event_path(root) -> Path:
    return agentstate.base(root) / "data" / "events.jsonl"


def _read_rows(root) -> list[dict]:
    path = _event_path(root)
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _since(row: dict, minutes: int) -> bool:
    ts = row.get("ts")
    if not ts:
        return False
    try:
        stamp = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return False
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - stamp).total_seconds() <= minutes * 60


def _handler_read_events(root, args, context):
    limit = int(args.get("limit", 100))
    rows = _read_rows(root)
    if args.get("since_minutes"):
        rows = [r for r in rows if _since(r, int(args["since_minutes"]))]
    if args.get("kind"):
        rows = [r for r in rows if str(r.get("kind")) == args["kind"]]
    return {"ok": True, "count": len(rows[-limit:]), "events": rows[-limit:]}


def _handler_list_findings(root, args, context):
    minimum = float(args.get("min_score", 0.7))
    limit = int(args.get("limit", 100))
    rows = [r for r in _read_rows(root)
            if isinstance(r.get("score"), (int, float)) and float(r["score"]) >= minimum]
    rows.sort(key=lambda r: float(r.get("score", 0)), reverse=True)
    return {"ok": True, "count": len(rows[:limit]), "findings": rows[:limit]}


def _handler_health(root, args, context):
    return {"ok": True, "health": health.verdict(root)}


def _handler_policy(root, args, context):
    return {"ok": True, "policy": policy.load(root),
            "killswitch": killswitch.status(root)}


def _handler_approvals(root, args, context):
    return {"ok": True, "approvals": ledger.pending_approvals(
        root, limit=int(args.get("limit", 100)))}


def _handler_audit(root, args, context):
    return {"ok": True, "ledger_ok": ledger.verify(root),
            "rows": ledger.tail(root, int(args.get("limit", 50)))}


def _plan(tool, args, steps, note):
    return {"ok": True, "dry_run": True, "tool": tool, "arguments": args,
            "plan": steps, "note": note,
            "execute_with": "plasma actuate dry-run, then --apply --plan <id>"}


def _handler_canary(root, args, context):
    return _plan("deploy_canary", args,
                 ["create six decoy documents", "hash and record the manifest",
                  "verify on every watch sweep"],
                 "No file was written. Run plasma canary deploy to apply.")


def _handler_contain(root, args, context):
    user = str(args.get("user", ""))
    protected = user.lower() in {"administrator", "system", "local service",
                                 "network service"}
    return _plan("contain_user", args,
                 ["snapshot host state", "disable the local account"],
                 "Protected account refused." if protected else
                 "No account was changed. Destroy the approval to execute.") | {
                     "refused": protected}


def _handler_isolate(root, args, context):
    return _plan("isolate_host", args,
                 ["apply inbound/outbound isolation rules",
                  "keep RDP 3389 and WinRM 5985 open"],
                 "No firewall rule was changed. Management access stays available.")


def _handler_quarantine(root, args, context):
    return _plan("quarantine_file", args,
                 ["hash the file", "move it to the quarantine directory",
                  "journal the original path"],
                 "No file was moved.")


def _handler_kill(root, args, context):
    return _plan("kill_process", args,
                 ["capture process identity and command line",
                  "terminate the process"],
                 "No process was killed; this action is not reversible.")


HANDLERS = {
    "read_events": _handler_read_events,
    "list_findings": _handler_list_findings,
    "get_health": _handler_health,
    "read_policy": _handler_policy,
    "list_approvals": _handler_approvals,
    "audit_tail": _handler_audit,
    "deploy_canary": _handler_canary,
    "contain_user": _handler_contain,
    "isolate_host": _handler_isolate,
    "quarantine_file": _handler_quarantine,
    "kill_process": _handler_kill,
}


def _context(params: dict) -> dict:
    meta = params.get("_meta") or {}
    return {
        "agent": meta.get("agent") or os.environ.get("PLASMA_AGENT", "mcp"),
        "model": meta.get("model") or os.environ.get("PLASMA_MODEL"),
        "prompt_sha256": meta.get("prompt_sha256")
        or os.environ.get("PLASMA_PROMPT_SHA256"),
        "tenant": meta.get("tenant") or os.environ.get("PLASMA_TENANT", "default"),
        "scopes": meta.get("scopes") or ["*"],
        "host": meta.get("host"),
    }


def _text_result(payload: dict, error: bool = False) -> dict:
    return {"content": [{"type": "text",
                         "text": json.dumps(payload, default=str)}],
            "isError": error}


def handle(request: dict, root=None) -> dict | None:
    method = request.get("method")
    req_id = request.get("id")
    params = request.get("params") or {}

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "plasma", "version": __version__},
        }}
    if method in ("notifications/initialized", "initialized"):
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "tools": [t.to_mcp() for t in tools.list_tools()]}}
    if method == "resources/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"resources": []}}
    if method != "tools/call":
        return {"jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32601, "message": f"unknown method {method!r}"}}

    name = params.get("name")
    args = params.get("arguments") or {}
    context = _context(params)
    try:
        spec = tools.get(name)
        tools.validate_args(name, args)
    except tools.ToolError as exc:
        return {"jsonrpc": "2.0", "id": req_id,
                "result": _text_result({"ok": False, "code": "INVALID_ARGS",
                                        "error": str(exc)}, error=True)}

    host = args.get("host") or context.get("host")
    context_tenant = context.get("tenant")
    if context_tenant and host and not tenants.allows(root, context_tenant, host):
        decision = {"allowed": False, "approval_required": False, "code": "denied",
                    "risk": spec.risk, "autonomy": policy.load(root).get("autonomy"),
                    "reasons": [f"tenant {context_tenant!r} does not own host {host!r}"],
                    "policy_sha256": agentstate.sha256_obj(policy.load(root))}
        row = ledger.record(root, tool=name, args=args, decision=decision,
                            context=context, outcome="denied")
        return {"jsonrpc": "2.0", "id": req_id, "result": _text_result({
            "ok": False, "code": "DENIED", "audit_id": row["seq"],
            "reasons": decision["reasons"]})}
    blocked = killswitch.blocked(root, host=host, risk=spec.risk)
    recent = ledger.count_recent(root, 60)
    active_policy = policy.load(root)
    decision = policy.evaluate(name, args, context=context, policy=active_policy,
                               recent_actions=recent, killswitch_blocked=blocked)

    approval_id = params.get("approval_id")
    if decision["approval_required"] and approval_id is not None:
        args_sha = agentstate.sha256_obj({"tool": name, "args": args})
        approval = ledger.consume_approval(
            root, int(approval_id), name, args_sha,
            tenant=context.get("tenant", "default"),
            agent=context.get("agent"))
        if approval:
            decision = dict(decision, allowed=True, approval_required=False,
                            code="allow",
                            reasons=decision["reasons"]
                            + [f"approved by {approval.get('approver', 'operator')}"])
        else:
            row = ledger.record(root, tool=name, args=args, decision=decision,
                                context=context, outcome="approval_invalid")
            return {"jsonrpc": "2.0", "id": req_id, "result": _text_result({
                "ok": False, "code": "APPROVAL_INVALID", "audit_id": row["seq"],
                "error": "approval is missing, denied, bound to another action, or already used",
            }, error=True)}

    if decision["code"] == "denied":
        row = ledger.record(root, tool=name, args=args, decision=decision,
                            context=context, outcome="denied")
        return {"jsonrpc": "2.0", "id": req_id, "result": _text_result({
            "ok": False, "code": "DENIED", "audit_id": row["seq"],
            "risk": decision["risk"], "reasons": decision["reasons"]})}

    if decision["approval_required"]:
        row = ledger.record(root, tool=name, args=args, decision=decision,
                            context=context, outcome="approval_required")
        return {"jsonrpc": "2.0", "id": req_id, "result": _text_result({
            "ok": False, "code": "APPROVAL_REQUIRED", "audit_id": row["seq"],
            "approval_id": row["seq"], "tool": name,
            "args_sha256": row["args_sha256"], "risk": decision["risk"],
            "reasons": decision["reasons"],
            "next": "approve with: plasma control approvals approve <id>"})}

    if not decision["allowed"]:
        row = ledger.record(root, tool=name, args=args, decision=decision,
                            context=context, outcome="denied")
        return {"jsonrpc": "2.0", "id": req_id, "result": _text_result({
            "ok": False, "code": "DENIED", "audit_id": row["seq"],
            "risk": decision["risk"], "reasons": decision["reasons"]})}

    handler = HANDLERS.get(name)
    if handler is None:
        return {"jsonrpc": "2.0", "id": req_id,
                "result": _text_result({"ok": False, "code": "NO_HANDLER",
                                        "error": f"no handler for {name}"}, error=True)}
    try:
        result = handler(root, args, context)
    except Exception as exc:  # noqa: BLE001 — surface the error as data
        row = ledger.record(root, tool=name, args=args, decision=decision,
                            context=context, outcome="error",
                            detail=str(exc)[:300])
        return {"jsonrpc": "2.0", "id": req_id, "result": _text_result({
            "ok": False, "code": "TOOL_ERROR", "audit_id": row["seq"],
            "error": str(exc)[:300]}, error=True)}

    outcome = "dry_run" if spec.dry_run_only else "ok"
    row = ledger.record(root, tool=name, args=args, decision=decision,
                        context=context, outcome=outcome,
                        approval_id=int(approval_id) if approval_id else None)
    result = dict(result, audit_id=row["seq"])
    return {"jsonrpc": "2.0", "id": req_id, "result": _text_result(result)}


def serve(root=None, stdin=None, stdout=None) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for stream in (stdin, stdout):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            response = {"jsonrpc": "2.0", "id": None,
                        "error": {"code": -32700, "message": "parse error"}}
        else:
            if not isinstance(request, dict):
                response = {"jsonrpc": "2.0", "id": None,
                            "error": {"code": -32600, "message": "invalid request"}}
            else:
                response = handle(request, root)
        if response is not None:
            stdout.write(json.dumps(response, default=str) + "\n")
            stdout.flush()
    return 0