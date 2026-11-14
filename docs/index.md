<div class="raft-hero" markdown="0">
<p class="raft-eyebrow">Windows EDR &middot; v1.8.0</p>
<h1>No log lake.<br>No cloud.<br>No blind trust.</h1>
<p class="raft-lede">Plasma keeps the telemetry on the box, answers questions with a
121M on-device model, and makes every response named, journaled, and reversible.
The endpoint can explain itself &mdash; without shipping its diary anywhere.</p>
<div class="raft-actions">
<a class="raft-btn primary" href="getting-started/">Get started</a>
<a class="raft-btn" href="https://github.com/DrOlu/plasma/releases/latest">Download v1.8.0</a>
<a class="raft-btn" href="agent-native/">Agent-native operation</a>
</div>
<div class="raft-badges">
<span class="raft-badge">91.7% rollup coverage</span>
<span class="raft-badge">13 reversible actions</span>
<span class="raft-badge">440 tests</span>
<span class="raft-badge">Signed MSI + SHA256SUMS</span>
</div>
</div>

<div class="raft-grid">
<div class="raft-card"><div class="swatch yellow">SENSORS</div><div class="body">
<h3>Everything stays on the box</h3>
<p>Sysmon, WHIDS gene rules, identity Event Log API, an ETW tap, persistence probes, canaries and DTrace &mdash; normalised into one strict JSONL contract.</p>
</div></div>
<div class="raft-card"><div class="swatch cyan">ON-DEVICE</div><div class="body">
<h3>A 121M model that refuses</h3>
<p>Frozen neuralOS instance picks from a closed menu of probes and says <em>unknown</em> when it is &mdash; no cloud round-trip, no hallucinated answer.</p>
</div></div>
<div class="raft-card"><div class="swatch pink">RESPONSE</div><div class="body">
<h3>Reversible by construction</h3>
<p>Plan-gated actions with single-use approvals, a hash-chained provenance ledger, a kill switch and undo for every change.</p>
</div></div>
</div>

<div class="raft-strip">Ask one machine what happened. Get an answer it can prove.</div>

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

## What's new in 1.8.0

This is the production-hardening release, driven by a full re-test on the
Windows estate.

- **WHIDS init hang, root-caused** — an oversized `Dumps` tree inside the
  install directory made WHIDS' startup ACL reset exceed the SCM timeout.
  Detect-only nodes now ship with dump hooks off; `whids prune` and the
  watchdog move legacy trees out of the install path, not delete them file
  by file.
- **Watch surfaces lone critical alerts** — a criticality-8+ WHIDS alert is
  reported on the next sweep, with per-file offsets that survive log
  rotation. Previously only the 25-row growth counter was visible.
- **Fleet false positives cut** — lateral movement now requires network
  logons (`type=3/10`) and reports `linked` only when the source address is
  another host in the case; shared domains/IPs need at least one scored row.
- **Chain user binding** — a brute-force burst must end in a success for the
  same user; another user's success no longer completes the story.
- **Response safety** — the kill switch now blocks CLI and playbook applies,
  rotated credentials are redacted from the journal, quarantine is
  hash-pinned and refuses protected paths, WMI undo restores bindings by
  name, isolation verifies management allows before blocking, and the
  journal is locked, fsynced and id-safe.
- **Collector edge cases** — empty stores are no longer "ok", deep
  persistence no longer flags unsigned Windows binaries, and identity drops
  malformed domains/timestamps.

440 tests pass (21 skipped).

## What's new in 1.7.2

- **Implicit state machines formalised** — update phases, approvals,
  actuate plans, playbook plans, undo, tenant ownership, rings, canaries
  and the service lifecycle now have explicit states and single-use
  transitions.
- **No plan or approval reuse** — reusing an actuate/playbook plan or an
  approval is refused; undo requires its own dry-run.
- **Atomic writes** — binary rotation recovers from an interrupted rename;
  canary manifests are written atomically and deduped.
- **Exclusive tenant ownership** — a host belongs to one tenant.

See [State machines](state-machines.md).

## What's new in 1.7.0

Plasma is now **agent-native**, not just agent-adjacent:

- **Capability contract** — 11 typed tools with scopes, risk tiers,
  preconditions and JSON schemas. Unknown tools and extra arguments are
  refused before anything runs.
- **Deterministic policy engine** — assist / supervised / autonomous tiers,
  deny lists, blast-radius and rate limits. The model never authorises.
- **Provenance ledger** — every decision and action is appended to a
  hash-chained log with harness, model, prompt digest, arguments, policy
  digest, approval and outcome. `plasma control audit verify`.
- **Approval queue** — high/critical actions return an approval id; a human
  approves or denies, and the approval is single-use.
- **Kill switch** — global and per-host, blocks actions but not reads.
- **MCP server** — `plasma mcp serve` exposes the typed tools over stdio to
  any harness.
- **Compliance evidence** — CBN, NDPA, PCI DSS and ISO 27001 control
  matrices generated from real state.
- **Assurance** — CycloneDX SBOM, safety case and redacted support bundle.
- **Deployment rings** — canary/broad assignment and one-command rollback.
- **Safety evals** — `plasma eval run` covers tier behaviour, injections,
  blast radius, rate limits and refusals.

Read [Agent-native operation](agent-native.md) and the
[Control plane](control-plane.md).

## What's new in 1.6.x

- **Self-healing WHIDS** — `plasma whids ensure` force-stops a hung
  `StartPending` and restarts the sensor. The installer registers
  **PlasmaWhidsWatchdog** as a SYSTEM task that runs it every two minutes;
  every action is logged. Crashes are already covered by SCM failure
  actions; this covers the hang.
- **DTrace provisioning without winget** — `trace provision` downloads the
  official Microsoft package directly (winget is absent on Server 2022 by
  default), enables `bcdedit /set dtrace on`, and is idempotent. Readiness
  is capability-based: installed + enabled is ready.
- **Trace rows are estate-consistent** — the reviewed scripts emit `tid`,
  which works across the DTrace builds on Windows Server; `pid` is not
  portable between them.
- **Installer convergence** — updates re-stage the WHIDS config, rules,
  binary and Sysmon config from the bundle, and roll back the config once
  if a new one cannot start.
- **Gene alerts keep their technique** — WHIDS 1.7 omits the ATTACK block;
  Plasma maps the rule name to its technique on ingest.

Prefer a visual tour? **[Open the one-page overview](https://drolu.github.io/plasma/onepager.html)**.

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
