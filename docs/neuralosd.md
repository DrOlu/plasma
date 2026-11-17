# neuralOSd orchestrator

neuralOSd is an optional, local orchestrator that sits in front of Plasma. It
turns a natural-language question into a closed list of typed probes, refuses
when no probe matches, and returns a signed envelope. The model never sees a
host credential or a shell; the bridge runs allowlisted Plasma CLI verbs over
WinRM.

Plasma's built-in MCP server remains the zero-dependency agent surface.
neuralOSd is for teams that want a local model, a refusal gate and a probe menu
in front of the same typed tools.

## What it adds

| Layer | Plasma alone | With neuralOSd |
|---|---|---|
| Question routing | MCP client chooses a tool | 121M on-device model chooses from a closed probe menu |
| Refusal | Tool errors and policy denials | Typed refusal reasons (`no_probe_matches`, `action_intent`, `dropped_filter`, `low_coverage`) |
| Response | CLI plan → apply → undo | Model mints the plan; operator applies and undoes |
| Evidence | Hash-chained ledger | Signed envelope with menu and gate versions |
| Deployment | Single exe, no Python | Separate instance on a desk; WinRM to the estate |

## The `plasma-estate` instance

The reference instance lives at `~/neuralos-instances/plasma-estate/` and has
20 probes:

| Group | Probes |
|---|---|
| Estate | health, coverage, events (kind/severity filters), estate report |
| Response plans | block IP, isolate, snapshot, disable user, quarantine file, remove admin, stop service, delete task, disable task, remove run key, disable WMI subscription, kill process |
| Observatory | attest, sketch, edges, explain, flowstats, pslogs, attackmap, regedges, canary, sysmon health |
| Security checks | chain, WHIDS, canary, FIM, prevention, audit, playbook, enforcement, deep, eval, evidence, SBOM, policy, approvals, kill switch, tenants, drift, store stats, trace, tap, identity |
| Advanced | trace list/selftest/run, prevention dry-runs, playbook dry-runs, kill switch on/off, identity pull |
| Fleet | cross-host pull, correlate and report from the desk |

## Safety boundary

The model can propose; the operator disposes.

1. The model selects a probe and fills typed arguments.
2. The bridge runs an allowlisted Plasma CLI verb over WinRM.
3. A response probe returns a Plasma **dry-run plan id**; nothing is applied.
4. The operator reviews the plan and runs `orchestrate.py apply <id>`.
5. `orchestrate.py undo <id>` reverses it.

The model cannot widen its scopes, run an arbitrary command, or hide a request
from the ledger. Protected paths, accounts, services and processes are refused
by Plasma before the plan is minted.

## Example

```bash
neuralosd ask --instance-dir ~/neuralos-instances/plasma-estate \
  "is the estate healthy"

neuralosd ask --instance-dir ~/neuralos-instances/plasma-estate \
  "propose a block plan for 192.0.2.2 on WS1"

python orchestrate.py apply <plan>
python orchestrate.py undo <plan>
```

## Verification

The 1.15.9 drill ran the instance against WS1 and WS2:

- health, coverage, chain, attack map, PowerShell logs, canary, FIM, deep
  persistence, DTrace selftest, ETW tap selftest, identity pull, eval, evidence,
  SBOM, policy, approvals, kill switch, tenants, drift, store stats and fleet;
- response plans for block, disable, quarantine, remove-admin, task, service,
  Run key and snapshot were applied and reversed;
- protected targets were refused;
- both hosts parse 100% of the event store.

See `DEEP_TEST_1.15.9.md` in the instance directory for the full matrix.

## Requirements

- A Python desk with `neuralosd` installed and the instance directory.
- WinRM reachable on the estate (5985 with `allow_insecure_winrm` in a lab, or
  5986 HTTPS in production).
- Host credentials in the bridge, or a secret store; never in the model menu.
