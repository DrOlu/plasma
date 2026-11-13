# Agent-native operation

Plasma is designed to be driven by an agent harness — Claude Code, Codex,
OpenCode, or a customer's own orchestrator — without giving that harness
arbitrary execution.

The rule is simple: **the model may investigate and propose; the policy
engine decides; the ledger remembers.** Autonomy is a policy setting, not a
property of the model.

## The capability contract

Every action is a typed tool with a scope, a risk tier and a JSON schema.
Unknown tools and unexpected arguments are refused before anything runs.

| Tool | Risk | Scope | In MCP |
|---|---|---|---|
| `read_events` | read | `events:read` | executes |
| `list_findings` | read | `events:read` | executes |
| `get_health` | read | `health:read` | executes |
| `read_policy` | read | `policy:read` | executes |
| `list_approvals` | read | `approvals:read` | executes |
| `audit_tail` | read | `audit:read` | executes |
| `deploy_canary` | medium | `response:canary` | dry-run plan |
| `contain_user` | high | `response:identity` | dry-run plan |
| `isolate_host` | critical | `response:network` | dry-run plan |
| `quarantine_file` | high | `response:file` | dry-run plan |
| `kill_process` | critical | `response:process` | dry-run plan |

Mutating tools are **dry-run-only in the MCP surface**. The agent receives a
plan, a risk tier and (when required) an approval reference. Applying the
action stays behind the CLI's plan/approval gate. A hallucinating or
prompt-injected model cannot change a host through the tool API.

## Autonomy tiers

Set the node's posture with `plasma control policy set --autonomy …`.

| Tier | Read tools | Low / medium | High | Critical |
|---|---|---|---|---|
| `assist` | allowed | approval | approval | approval |
| `supervised` (default) | allowed | allowed | approval | approval |
| `autonomous` | allowed | allowed | allowed | approval unless `allow_critical` |

Start at `supervised`. Move to `autonomous` only after the eval suite and a
purple-team drill pass in that estate.

## Policy

The policy is a local JSON file (`policy.json` under the Plasma root). The
model never edits it.

```json
{
  "version": 1,
  "autonomy": "supervised",
  "allow": [],
  "deny": ["kill_process"],
  "require_approval": {"high": true, "critical": true},
  "allow_critical": false,
  "max_actions_per_minute": 30,
  "max_hosts_per_action": 1
}
```

```powershell
plasma control policy show
plasma control policy set --autonomy supervised --deny kill_process
plasma control policy set --max-actions 20 --max-hosts 1
```

The policy check is deterministic and runs before every tool call: deny
list, scopes, blast radius, rate limit, risk tier, autonomy tier.

## Approvals

A high-risk call returns a structured refusal with an `approval_id`:

```json
{
  "ok": false,
  "code": "APPROVAL_REQUIRED",
  "approval_id": 42,
  "tool": "isolate_host",
  "args_sha256": "…",
  "risk": "critical"
}
```

A human reviews and decides:

```powershell
plasma control approvals list
plasma control approvals approve 42 --approver ciso --note "confirmed beacon"
plasma control approvals deny 42 --approver ciso --note "false positive"
```

The approval is bound to the action and the argument hash and can be used
once. The agent re-calls the tool with `"approval_id": 42`; the dry-run plan
is then returned and recorded.

## Provenance ledger

Every decision and action is appended to a hash-chained JSONL ledger before
the result is returned to the harness:

```json
{
  "seq": 42,
  "ts": "2026-11-13T19:00:00Z",
  "tenant": "default",
  "kind": "action",
  "agent": "claude-code",
  "model": "…",
  "prompt_sha256": "…",
  "tool": "isolate_host",
  "args": {"host": "WS1"},
  "args_sha256": "…",
  "risk": "critical",
  "decision": "approval_required",
  "policy_sha256": "…",
  "prev": "…",
  "hash": "…"
}
```

```powershell
plasma control audit tail --last 20
plasma control audit verify      # exit 2 if the chain is broken
```

This is the answer to "why did the agent do that?" — harness, model, prompt
digest, arguments, policy digest, approval and outcome, in one chain.

## Kill switch

```powershell
plasma control killswitch status
plasma control killswitch on --reason "incident drill"
plasma control killswitch on --host WS1 --reason "quarantine"
plasma control killswitch off
```

Reads remain available; every mutating tool is blocked while the switch is
engaged.

## Multi-tenant isolation

```powershell
plasma control tenants add acme --name "Acme Bank" --host WS9 --host WS10
plasma control tenants list
```

Ledger rows carry the tenant, and policy checks can scope an agent to one
tenant. `default` cannot be removed.

## MCP server

Plasma speaks MCP over stdio, so any harness can discover and call the
tools.

Register it with Claude Code (bin name varies by release):

```json
{
  "mcpServers": {
    "plasma": {
      "command": "C:\\ProgramData\\Plasma\\bin\\plasma-1.5.0-windows-x64.exe",
      "args": ["mcp", "serve", "--root", "C:\\ProgramData\\Plasma"]
    }
  }
}
```

Minimal session:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_events","arguments":{"limit":20}}}
```

## Safety evals

```powershell
plasma eval run
```

The suite covers read/action separation, tier behaviour, deny lists, scopes,
blast radius, rate limits, kill switch, unknown tools, extra arguments, and
prompt-injection strings in arguments. It exits `2` on any failure.

## Limits

- The model never authorises action; it only chooses among typed tools.
- Telemetry is untrusted data. A filename cannot change policy.
- No arbitrary shell is exposed through MCP.
- Mutating tools are dry-run in MCP; execution is a separate human gate.
- Autonomous critical action should be enabled only with `allow_critical`
  after an estate-specific drill.
