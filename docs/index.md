# Plasma

**The lake-less Windows EDR.** Sensors keep everything on the endpoint, a
small on-device model answers questions about it, and every response is
human-gated, journaled and reversible. **No log lake. No cloud. No blind
trust.**

## Quick start

```powershell
# 1. download the current release binary
#    https://github.com/DrOlu/plasma/releases/latest

# 2. install (intelligent mode choice: FULL or MINIMAL)
.\plasma-<version>-windows-x64.exe install

# 3. verify
plasma health
plasma identity pull --events C:\ProgramData\Plasma\data\events.jsonl --since 60
plasma watch once
```

Every command prints JSON and uses meaningful exit codes, so it composes
with Task Scheduler, cron or another agent.

## Why it's different

Commercial EDR ships every event to a central lake and asks you to trust the
vendor's console. SIEM does the same one layer up. Plasma starts from the
opposite question: **what can one machine answer about itself, honestly,
without sending its diary anywhere?**

| Every other EDR / SIEM | Plasma |
|---|---|
| Streams events to a vendor cloud | Normalizes them **on the box** into one local JSONL contract |
| Central lake required for correlation | A desk pulls bounded tails and correlates **only when asked** |
| Model in the cloud decides | A 121M **on-device** model picks from a **closed menu of probes** |
| Response is a vendor API call | Response is a **named, allowlisted, dry-run-first** action with undo |
| "Trust us" | Manifest digests, SHA256SUMS, pinned signer thumbprints, and a refusal gate |

## The three layers

```text
SENSORS            Sysmon · WHIDS gene rules · Security-log identity ·
                   ETW tap · deep persistence probe
        │
        ▼  one strict event contract (events.jsonl, on the box)
ON-DEVICE BRAIN    frozen neuralOS instance — 10 probes, refuse-if-unknown
        │
        ▼  pull-based answers over WinRM/SSM, never a standing server
DESK               status · ask · drift · chains · coverage · fleet ·
                   watch + alerts · plan-gated response (actuate)
```

## What you get in 1.4.0

- **Story detection** — deterministic chain rules (phish spawn, brute-force
  success, persistence-after-privilege) that fire on sequences, not single
  events, and run inside every `watch` sweep.
- **Honest ATT&CK coverage** — 91.7% with parent rollup, 83.3%
  fidelity-weighted, and the three remaining blind spots named out loud.
- **Deep persistence probe** — every auto-start location with Authenticode
  status and a surfaced `suspect` heuristic; no driver, no service.
- **Signed updates** — `update apply` refuses any binary whose Authenticode
  signer does not match thumbprints pinned inside the installed exe.
- **Playbooks** — `contain-user`, `isolate-box`: fixed sequences applied as
  one plan-gated unit, aborting on the first failure, reversible last-first.
- **Store hygiene** — `store rotate|compact|stats` keeps the diary bounded.
- **Canary files** — decoy documents whose deletion/modification is a
  score-10 impact finding, verified on every `watch` sweep.
- **MSI + GPO** — an enterprise package that provisions a node silently
  through Group Policy.
- **DTrace, on demand** — reviewed, bounded kernel/syscall tracing where
  the host supports it, normalized into the same event contract.

## Doctrine

1. **Read-only first.** Nothing changes on a host unless a human passes
   `--apply --plan <id>`.
2. **Deterministic.** Detection is written rules and written chains. The
   model selects probes; it never decides guilt and never runs commands.
3. **Bounded.** Every collector has a time window, a row cap and a size cap.
4. **Local.** Events never leave the host by default. The desk pulls what it
   needs.
5. **Reversible.** Every applied action carries a journal entry and an undo
   payload — where an action cannot be undone, the CLI says so up front.

## Where to go next

- New here? [Getting started](getting-started.md).
- Want the mental model? [Concepts](concepts.md).
- Operating an estate? [Operations](operations.md) and [Fleet](fleet.md).
- About to respond to an incident? [Response](response.md).
- Judging it for a regulated environment? [Security model](security-model.md).
