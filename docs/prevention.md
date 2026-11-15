# Prevention and blocking

Plasma has two prevention tiers, and they are deliberately different things.

| Tier | Mechanism | Blocks first execution? | Latency |
|---|---|---|---|
| **0 — Containment** | `plasma enforce` turns findings into allowlisted, reversible actions | No | seconds to minutes |
| **1 — Enforcement points** | `plasma prevent` configures AppLocker, Windows Firewall, Defender ASR and LSA protection | **Yes** | at execution / connection |

Plasma does **not** ship a kernel driver. Inline blocking at the file,
process and network boundary belongs to Microsoft's signed components;
Plasma generates, applies, verifies and rolls back their policy. That is a
deliberate trade: policy you can roll back beats a driver you cannot
crash-test.

## Tier 0 — policy-gated containment

```powershell
plasma enforce status
plasma enforce run                 # dry-run: proposals only
plasma enforce run --apply         # arm this run (policy still gates each action)
plasma enforce pending
plasma enforce approve --id 4      # dry-run of the stored request
plasma enforce approve --id 4 --apply
plasma enforce run --findings findings.json   # evaluate supplied findings
```

Findings map to actions:

| Finding | Action | Default |
|---|---|---|
| injection technique (T1055 family) with a PID | `kill_process` | automatic when armed |
| `chain_injection_chain` / `chain_injection_apc_chain` | `kill_process` on the image PID | automatic when armed |
| `canary_tripped` | `isolate_host` | approval required |

Policy lives in `config.json`:

```json
{
  "enforcement": {
    "enabled": true,
    "mode": "enforce",
    "min_score": 9,
    "allowed_actions": ["kill_process"],
    "require_approval": ["isolate_host"],
    "cooldown_minutes": 30,
    "max_actions_per_run": 2
  }
}
```

Guardrails are code, not convention:

- **Off by default** and `dry-run` unless the mode is explicitly `enforce`.
- **Allowlist** — a finding cannot select an action outside the policy lists.
- **Approval gate** — high/critical actions queue as pending; nothing runs
  until a human approves.
- **Blast radius** — score floor, per-run cap, per-action+target cooldown.
- **Kill switch** — actuate's kill switch still blocks every apply.
- **Journal** — `enforce-journal.jsonl` records the finding digest, decision,
  reasons, plan id and verification.

Every apply still goes through actuate: dry-run first, plan id required,
undo recipe recorded. Run it from cron or Task Scheduler with
`plasma watch once --enforce`.

## Tier 1 — Windows enforcement points

```powershell
plasma prevent status
plasma prevent applocker --mode audit                     # plan only
plasma prevent applocker --mode audit --apply --plan 3 --reason "pilot"
plasma prevent egress --allow 10.0.0.0/8 --allow 1.2.3.4:443
plasma prevent asr --ids <GUID> --action Audit
plasma prevent lsa
plasma prevent rollback --id 7 --apply
```

All controls are **dry-run first and plan-gated**: the apply requires the id
of a dry-run whose rendered payload digest still matches, plus a reason.

### AppLocker

Generates an Exe policy with allow rules for `%WINDIR%`, Program Files
(both), optional `--allow-path` entries, and a permanent Administrators
path rule so an enforcement mistake cannot lock the operator out of their
own tooling. Default mode is **audit**; `--mode enforce` turns it into
blocking. Rollback restores the previous effective policy, or clears the
local SrpV2 policy when there was none.

AppLocker controls execution, not scripts; pair it with PowerShell logging
and constrained language mode where appropriate.

### Firewall egress

Creates `PlasmaPrevent-Egress-*` rules: one allow per destination, then a
default-block outbound rule (Windows gives explicit allows precedence). An
allowlist is mandatory — blocking all egress without DNS and update
destinations locks the host out of patching. Rollback removes the prefix
rules.

Blocking **outbound** does not affect inbound WinRM/RDP, but it will break
anything that needs the internet; pilot it and keep the allowlist current.

### Defender ASR

Applies attack-surface-reduction rule GUIDs in `Audit`, `Enabled` (block)
or `Disabled` mode. Requires Defender to be present and not fully managed
by policy that overrides local settings. Rollback restores each rule's
previous action.

### LSA protection

Sets `RunAsPPL=1` under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`.
Takes effect after a reboot. Rollback removes the value. Check third-party
LSA plugins before enabling it in production.

## What this is not

- **Not a driver.** There is no file-write prevention, no pre-execution
  process veto, and no packet-level inline blocking from Plasma itself.
- **Not agentless prevention.** AppLocker and ASR are endpoint-local
  controls; a host that is offline from management still enforces its own
  policy.
- **Not a substitute for backups.** Every control here is reversible, and
  the journal is the audit trail that proves what changed.

## Verification

```powershell
plasma prevent status
plasma enforce status
Get-NetFirewallRule -DisplayName 'PlasmaPrevent-*'
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
```
