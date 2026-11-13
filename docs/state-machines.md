# State machines

Several Plasma workflows used to keep their state implicitly — in a file
that might exist, a service that might be pending, or a journal row that
was never marked used. v1.7.2 makes the risky ones explicit and closes the
transitions that could double-execute or leave a half-finished phase.

| Machine | States | Invariant | Fix in 1.7.2 |
|---|---|---|---|
| **Update** | `idle → staged → verified → installing → installed → rotated`; `failed` | A host can only be in one phase; a new run resets the phase and keeps history | Persisted `state/update.json`; `update check` reports it; atomic bin rotation with recovery |
| **Approval** | `pending → approved/denied → consumed` | An approval is single-use and bound to `tool + args_sha256` | `ledger.consume_approval()` checks and marks consumption under the ledger lock |
| **Actuate plan** | `dry-run → applied` | A plan runs once; the payload digest must still match | Reusing a plan is refused |
| **Actuate undo** | `undo dry-run → undo applied` | Undo is dry-run first, single-use, digest-bound | `--plan` required (or a prior undo dry-run); double undo refused |
| **Playbook** | `dry-run → applied / aborted` | A playbook plan runs once; steps apply in order | Reusing a playbook plan is refused |
| **Playbook undo** | `undo dry-run → undo applied` | Each step is undone once, last-first | `--plan` required; double undo refused |
| **Tenant ownership** | `unassigned → tenant` | A host belongs to at most one tenant; unassigned falls back to `default` | `tenants.add` removes the host from every other tenant |
| **Ring membership** | `host → one ring`; `current` ring | A host is in one ring; updates check membership | `assign` removes the host from other rings; `update apply --ring` gate |
| **Canary** | `absent → deployed → intact / tripped` | The manifest is never half-written; duplicate paths are recorded once | Atomic manifest write and path dedupe |
| **WHIDS service** | `stopped → startpending → running → stopping`; `hung` | A hung `StartPending` is force-stopped then started | Watchdog `whids ensure`; supervised install start |
| **DTrace** | `unavailable → installed → enabled(pending reboot) → available` | Provisioning is idempotent; a reboot is required after enabling | Capability-based readiness; explicit `reboot_required` |
| **Ledger** | append-only hash chain | Every decision/action is ordered and tamper-evident | Approval consumption is its own `approval_use` row |

## Inspecting state

```powershell
plasma update check                     # includes "state"
plasma control approvals list           # pending
plasma control audit verify             # chain integrity
plasma ring status
plasma control tenants list
plasma whids diagnose                   # service phase + watchdog
plasma trace check
```

## Recovery

- **Update failed mid-phase**: `update check` shows `failed`; re-run
  `update apply`. `rotate_bin` restores a missing bin from `.old` if the
  previous run died between renames.
- **Approval already used**: the tool returns `APPROVAL_INVALID`; create a
  new dry-run and approve it again.
- **Undo needed**: run the undo dry-run, then `--apply --plan <id>`. A
  second undo is refused.
- **Host in the wrong tenant**: re-add it to the intended tenant; ownership
  moves atomically.
- **Canary manifest damaged**: `canary deploy` re-hashes existing files
  and writes a fresh manifest atomically.

## Design rule

A transition that can change a host must have one of: a typed tool and a
policy decision, a single-use plan, or a single-use approval. If a step can
be repeated by retrying a request, it is a bug.
