# Interception

Interception is the layer between a sensor and a responder: it sees an
attempt at the boundary and can **allow, deny, or record a would-be denial**.

Plasma does not ship a kernel driver. It brokers typed rules into gates
Windows already owns:

| Point | Native gate | Enforced by |
|---|---|---|
| File write / delete | NTFS deny ACE | Windows file system |
| Network connect | Windows Firewall | Windows Filtering Platform |
| Agent tool call | MCP boundary | Plasma gateway |
| Process exec | AppLocker / WDAC | `plasma prevent` |
| Credential access | Defender ASR | `plasma prevent` |

The model may propose a rule. It cannot apply one without the plan gate.

## The four phases

### Phase 0 — shadow evaluation

```powershell
plasma intercept rules add --file rules.json
plasma intercept evaluate --events C:\ProgramData\Plasma\data\events.jsonl
```

Reads a bounded tail of the event store and reports `would_block` decisions
without touching the host. Use this to tune rules before enforcement.

### Phase 1 — canary protection

```powershell
plasma intercept protect-canary
plasma intercept protect-canary --apply --plan 7 --reason "canary protection"
```

Adds a deny ACE for write/delete by Everyone to every file in the canary
manifest. The canary becomes both a tripwire and a small safe: a destructive
writer is denied and the attempt is still evidence. The prior SDDL is saved
for rollback.

If the operator token lacks `SeSecurityPrivilege`, the audit rule is skipped
and the deny ACE is still applied. Enable File System auditing separately to
receive failure events in the Security log.

### Phase 2 — agent tool-call gateway

The MCP `tools/call` path evaluates intercept rules **before** policy,
handlers or mutations:

```json
{
  "id": "no-isolate",
  "point": "agent_tool_call",
  "action": "deny",
  "backend": "gateway",
  "mode": "enforce",
  "match": {"tool": "isolate_host"}
}
```

A denied call returns `INTERCEPTED` with the rule id and an audit ledger
entry. A `mode: "shadow"` rule is audited but does not block.

### Phase 3 — native policy broker

```powershell
plasma intercept rules add --file rules.json
plasma intercept apply block-test-net            # dry-run
plasma intercept apply block-test-net --apply --plan 12 --reason "IR-42"
plasma intercept rollback --id 12                # dry-run
plasma intercept rollback --id 12 --apply --plan 15 --reason "test complete"
```

Enforcing backends:

- `acl` — canary file deny/audit ACL.
- `firewall` — outbound Windows Firewall block for one IPv4 destination.
- `gateway` — MCP boundary; no host mutation.

AppLocker and ASR remain available through `plasma prevent` with the same
dry-run, plan, journal and rollback discipline.

## Rule shape

```json
{
  "id": "protect-finance-canary",
  "point": "file_write",
  "action": "deny",
  "backend": "acl",
  "mode": "enforce",
  "match": {"path_prefix": "D:\\Finance"},
  "priority": 10,
  "ttl_seconds": 3600,
  "reason": "canary protection"
}
```

Supported points: `file_write`, `file_delete`, `file_read`, `process_exec`,
`network_connect`, `dns_query`, `credential_access`, `agent_tool_call`.

Supported match fields: `path_prefix`, `process`, `user`, `host`, `dest_ip`,
`dest_port`, `technique`, `event_id`, `tool`, `tenant`.

The highest `priority` wins; ties resolve `deny` > `require_approval` >
`allow` > `audit`.

## Safety model

- **Dry-run first.** Apply requires the plan id from a seen dry-run with the
  same payload digest.
- **Single-use plan.** A plan cannot be applied twice.
- **Kill switch.** Blocks ACL, firewall and rollback execution; dry-runs
  remain available.
- **Bounded.** The shadow evaluator reads a capped tail; no raw stream.
- **Reversible.** ACL rollback restores the exact prior SDDL; firewall
  rollback removes the named rule.
- **No arbitrary shell.** Paths, IPs and rule fields are validated; the
  only PowerShell is generated from typed fields.
- **No kernel driver.** The broker owns policy, not the kernel.

## What it will not do

- It will not stop kernel-mode malware, malicious drivers or direct
  syscalls; that would require a driver.
- It will not stop an administrator from disabling it.
- It will not inspect encrypted C2 without a TLS proxy.
- It will not replace backups, least privilege or detection.

## Estate evidence

On WS1 and WS2 (Windows Server 2022):

- shadow rules matched the synthetic event store;
- the canary ACL denied a write and rollback restored write access;
- a `203.0.113.9` outbound firewall rule appeared and was removed;
- the MCP gateway returned `INTERCEPTED` for a denied `get_health` call.
