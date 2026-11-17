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

## Measured default (1.17.0+)

Containment is **armed by default, but narrow**:

- automatic actions: `snapshot`, then `kill_process`;
- score floor: **9**;
- per-run cap: **2**;
- per-target cooldown: **30 minutes**;
- everything else — isolation, quarantine, disabling users, removing
  admins, stopping services, credential rotation, task/Run-key/WMI removal
  and IP blocking — **requires human approval**;
- the installer registers `PlasmaWatch`, a SYSTEM task that runs
  `watch once --enforce` every 5 minutes.

```powershell
plasma protect status
plasma protect protected
plasma protect disarm --reason "change window"
plasma protect arm
plasma protect arm --apply-prevention --reason "pilot AppLocker audit"
```

`--no-autoprotect` installs the old dry-run posture and removes the
`PlasmaWatch` task. Upgrades replace exactly the pre-1.17 `enabled: false`
block; a custom operator block is preserved.

## Tier 0 — policy-gated containment

```powershell
plasma protect status
plasma enforce status
plasma enforce run                 # dry-run: proposals only
plasma enforce run --apply         # policy still gates each action
plasma enforce pending
plasma enforce approve --id 4      # dry-run of the stored request
plasma enforce approve --id 4 --apply
plasma enforce run --findings findings.json   # evaluate supplied findings
```

Findings map to actions:

| Finding | Action | Default |
|---|---|---|
| injection technique (T1055 family) with a PID | `snapshot`, then `kill_process` | automatic when armed |
| `chain_injection_chain` / `chain_injection_apc_chain` | `snapshot`, then `kill_process` on the image PID | automatic when armed |
| `canary_tripped` | `isolate_host` | approval required |

Policy lives in `config.json`:

```json
{
  "enforcement": {
    "enabled": true,
    "mode": "enforce",
    "min_score": 9,
    "allowed_actions": ["snapshot", "kill_process"],
    "require_approval": [
      "isolate_host", "quarantine_file", "disable_user", "remove_admin",
      "stop_service", "rotate_credential", "delete_task", "disable_task",
      "remove_run_key", "disable_wmi_sub", "block_ip"
    ],
    "cooldown_minutes": 30,
    "max_actions_per_run": 2,
    "watch_task": "PlasmaWatch",
    "watch_every_minutes": 5
  }
}
```

**Evidence before containment.** A kill destroys the in-memory artifact the
injection detection exists to surface. Before the first automatic kill in a
run, Plasma writes one host-state snapshot through the same dry-run + plan
gate. The snapshot is a read-only export (users, admins, services, tasks,
firewall, audit policy) — it does not capture process memory. If the
snapshot fails, containment still proceeds and the journal records
`capture: failed`.

Operators who want forensics ahead of speed can either:

- remove `"snapshot"` from `allowed_actions` to skip the capture, or
- move `"kill_process"` into `require_approval` so every kill is
  human-gated and the capture can be examined first.

Guardrails are code, not convention:

- **Armed by default, narrow** — only `snapshot` + `kill_process` at score
  9+, with a per-run cap and cooldown.
- **Allowlist** — a finding cannot select an action outside the policy lists.
- **Approval gate** — high/critical actions queue as pending; nothing runs
  until a human approves.
- **Blast radius** — score floor, per-run cap, per-action+target cooldown.
- **Kill switch** — actuate's kill switch still blocks every apply.
- **Journal** — `enforce-journal.jsonl` records the finding digest, decision,
  reasons, plan id and verification.

Every apply still goes through actuate: dry-run first, plan id required,
undo recipe recorded. The installer registers `PlasmaWatch`, which runs
`plasma watch once --enforce` every 5 minutes as SYSTEM. Run it manually
with `plasma watch once --enforce`, or remove the task with
`--no-autoprotect` and use `plasma protect disarm`.

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
an allowlist is mandatory — blocking all egress without DNS and update
destinations locks the host out of patching. Plasma warns when no port-53
destination is present, but it does not guess your DNS servers; add them
explicitly. Rollback removes the prefix rules.

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
