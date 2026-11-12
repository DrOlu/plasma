# Response

Plasma's response layer follows one promise: **a human decides, a machine
executes carefully — and everything is reversible or visibly not.**

## The gate

```powershell
# 1. render the exact payload (nothing runs)
plasma actuate apply block_ip --target 203.0.113.9 --reason "C2" --root C:\ProgramData\Plasma

# 2. the dry-run is journaled with an id (say, 7). Apply THAT plan:
plasma actuate apply block_ip --target 203.0.113.9 --reason "C2" --apply --plan 7

# 3. if it was wrong:
plasma actuate undo --id 8 --apply
```

Rules enforced by code, not documentation:

- **`--apply` without `--plan` is refused.** The plan id must reference a
  seen dry-run of the **same action and target**, and the rendered payload
  digest must still match (state moved on → re-run the dry-run).
- **Allowlisted actions only.** There is no `run_command`.
- **Protected targets** (WinRM, TermService, Winlogon, csrss, lsass,
  Sysmon, WHIDS, Administrator, …) are refused before any payload runs.
- **Journal first.** Every dry-run, apply, failure and undo is appended to
  `actuate-journal.jsonl`. A torn line cannot brick the journal.
- **Undo where possible.** Each action carries an undo payload or a
  structured recipe; actions that cannot be undone are marked
  `undoable: false` and the CLI says so.

## Actions

| Action | Target | What it does | Undo |
|---|---|---|---|
| `block_ip` | IPv4 | Inbound + outbound firewall block (two named rules) | remove rules |
| `isolate_host` | — | Block all traffic **after** creating RDP-3389 and WinRM-5985 allow rules | remove rules |
| `disable_user` | local user | `Disable-LocalUser` | enable |
| `remove_admin` | local user | remove from Administrators | re-add |
| `kill_process` | PID | capture identity, then `Stop-Process -Force` | none (by design) |
| `quarantine_file` | absolute path | move to `C:\ProgramData\Plasma\Quarantine` | move back |
| `stop_service` | service | `Stop-Service -Force` | start |
| `disable_task` | task name | back up XML, disable the task | enable |
| `delete_task` | task name | back up XML, unregister | re-register from XML |
| `remove_run_key` | `HKLM:\…\Run|Name` | capture the value, delete it (string values only, allowlisted keys) | restore value |
| `disable_wmi_sub` | — | remove filter-to-consumer bindings; definitions kept | re-bind |
| `rotate_credential` | local user | new random password, printed once, never journaled | none |
| `snapshot` | — | users, admins, services, tasks, firewall, audit policy → JSON | none (it is the backup) |

`isolate_host` is deliberately lockout-proof: Windows evaluates more-specific
allow rules first, so management access survives full isolation. That
ordering is tested.

## Playbooks

A playbook is a fixed sequence of the actions above, applied as **one**
plan-gated unit:

| Playbook | Steps |
|---|---|
| `contain-user <user>` | `disable_user` → `snapshot` |
| `isolate-box` | `isolate_host` → `snapshot` |

```powershell
plasma playbook apply contain-user --target bob --reason "lateral hop, no ticket"
# → journals one dry-run per step + a playbook dry-run; returns its id

plasma playbook apply contain-user --target bob --reason "lateral hop, no ticket" --apply --plan 12

# reverse the succeeded steps, last-first (non-undoable steps are skipped, visibly)
plasma playbook undo --id 13 --apply
```

Behavior: abort on the first failing step (the journal records exactly how
far it got), and reversal walks backward so dependent steps are undone in
the right order.

## Journal

```powershell
plasma actuate journal --last 20
```

Each entry: `id`, `ts`, `action`, `target`, `reason`, `mode`
(`dry-run`/`applied`), `payload_sha256`, `result` (rc + bounded output),
`verification`, `undo`, and for playbooks `steps[]` / `aborted_at`.

## Safety rules of thumb

1. **Snapshot before containment.** `plasma actuate apply snapshot` costs
   seconds and gives you the pre-change world.
2. **Isolate, don't kill.** `isolate_host` keeps the management channel;
   `kill_process` cannot be undone.
3. **Verify, don't assume.** Every apply runs a verification payload; a
   failed verification exits non-zero.
4. **Read the payload.** The dry-run is the contract. If you would not type
   that PowerShell yourself, do not apply it.
