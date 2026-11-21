<div class="raft-hero" markdown="0">
<p class="raft-eyebrow">Windows EDR &middot; v1.26.2</p>
<h1>No log lake.<br>No cloud.<br>No blind trust.</h1>
<p class="raft-lede">Plasma keeps the telemetry on the box, answers questions with a
121M on-device model, and makes every response named, journaled, and reversible.
The endpoint can explain itself &mdash; without shipping its diary anywhere.</p>
<div class="raft-actions">
<a class="raft-btn primary" href="getting-started/">Get started</a>
<a class="raft-btn" href="https://github.com/DrOlu/plasma/releases/latest">Download v1.26.2</a>
<a class="raft-btn" href="agent-native/">Agent-native operation</a>
</div>
<div class="raft-badges">
<span class="raft-badge">94.6% rollup coverage</span>
<span class="raft-badge">13 reversible actions</span>
<span class="raft-badge">949 tests</span>
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
<div class="raft-card"><div class="swatch cyan">ORCHESTRATION</div><div class="body">
<h3>neuralOSd in front</h3>
<p>An optional local orchestrator with 20 typed probes, a refusal gate and a signed envelope. The model proposes; the operator applies. <a href="neuralosd/">Read the guide</a>.</p>
</div></div>
<div class="raft-card"><div class="swatch pink">RESPONSE</div><div class="body">
<h3>Reversible by construction</h3>
<p>Plan-gated actions with single-use approvals, a hash-chained provenance ledger, a kill switch and undo for every change.</p>
</div></div>
<div class="raft-card"><div class="swatch yellow">PREVENTION</div><div class="body">
<h3>Off until you arm it</h3>
<p><code>enforce</code> contains in seconds; <code>prevent</code> configures AppLocker, firewall egress, ASR, LSA, CFA, Network Protection and the driver blocklist. Dry-run first, journaled, rollbackable &mdash; no Plasma kernel driver.</p>
</div></div>
</div>

<div class="raft-strip">Detects always. Contains only when armed. Blocks only through Microsoft's own enforcement points.</div>

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

# 4. optional: see what prevention would do (nothing is applied)
plasma enforce run
plasma prevent status
plasma prevent posture
plasma query --kind alert --min-score 0.7 --since 24h
```

Every command prints JSON and uses meaningful exit codes, so it composes
with Task Scheduler, cron or another agent.

## Enterprise deployment

Planning an AD-domain rollout? Start with [Enterprise deployment](enterprise-deployment.md):
prerequisites, GPO/SCCM/Intune install, configuration, fleet desk, canary shield,
validation, operations and troubleshooting.

## PDF guides

The same material as printable, offline documents:

- [Plasma Product Guide (PDF, 23 pages)](Plasma_Product_Guide.pdf) — architecture,
  detection, coverage, prevention, response, neuralOSd orchestration and the honest limits.
- [Plasma Operations Guide (PDF, 20 pages)](Plasma_Operations_Guide.pdf) —
  install, configuration, daily operations, prevention runbook, fleet,
  neuralOSd orchestration, troubleshooting and cheat sheet.

Both are built for the current release and published in the site root.

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
| Response is a vendor API call | Response is **named, allowlisted and dry-run first**; containment is policy-gated; prevention uses Windows enforcement points |
| "Trust us" | Manifest digests, SHA256SUMS, pinned signer thumbprints, and a refusal gate |

## The layers

```text
SENSORS            Sysmon · WHIDS gene rules · Security-log identity ·
                   ETW tap · deep persistence probe · canary tokens · memory scan
        │
        ▼  one strict event contract (events.jsonl, on the box)
ON-DEVICE BRAIN    frozen neuralOS instance — 10 probes, refuse-if-unknown
        │
        ▼  optional: local model + refusal gate + 20-probe menu
ORCHESTRATOR       neuralOSd — plan/apply/undo over the same typed tools
        │
        ▼  pull-based answers over WinRM/SSM, never a standing server
DESK               status · ask · query · tree · summarize · case ·
                   drift · chains · coverage · fleet ·
                   watch + alerts · plan-gated response (actuate)
        │
        ▼  measured, policy-gated, journaled
PROTECTION         enforce (snapshot + kill at 9+, approval for the rest) ·
                   prevent (AppLocker, egress, ASR, LSA, CFA, Network Protection) ·
                   intercept (NTFS ACL, firewall, agent gateway)
```

## What's new in 1.26.2

- **Boot-time enforcement.** `PlasmaWatch`, `PlasmaWhidsWatchdog` and `PlasmaCanaryShield` now carry both an `AtStartup` trigger and `StartWhenAvailable`. A reboot or missed timer run no longer waits for the next interval.
- **Bounded task runs.** Restart-on-failure, non-overlapping execution and execution time limits stop a hung sweep from wedging the schedule.
- **Health drift detection.** `plasma health` reports present Plasma tasks that lack an `AtStartup` trigger.

## What's new in 1.26.1

- **Architecture diagram polish.** Removed overlapping labels and rerouted the WinRM, optional API and SIEM links in the enterprise illustration; PDFs regenerated. No runtime behavior change.

## What's new in 1.26.0

- **Named-pipe canaries.** `canary pipe deploy|list|remove|serve|install|uninstall`
  adds decoy pipes. The SYSTEM listener gets the connecting client PID with
  `GetNamedPipeClientProcessId`, verifies it, refuses protected/trusted
  processes, and kills. Enumeration alone is not a connection.
- **Proper architecture diagram.** The enterprise deployment page now uses a
  real SVG illustration instead of ASCII art.
- **Enterprise guide expanded** with pipe-canary rollout, scanner caveats and
  disarm steps.
- **943 tests**, full suite and `-W error` pass.

## What's new in 1.25.0

- **Active canary shield.** File and registry canaries can now kill the
  process that writes or deletes them. A narrow Sysmon include feeds a
  one-minute SYSTEM sweep; the sweep verifies the live PID and image, refuses
  protected/trusted processes, then kills and journals.
- **No read false positives.** Merely opening or reading a canary does not
  trigger. Explorer, Plasma, Defender and common backup/system processes are
  skipped; the boundary is explicit.
- **Registry canaries.** `canary registry deploy|list|remove` adds decoy
  registry keys watched by the same narrow RegistryEvent include.
- **Enterprise deployment guide.** A new AD-domain installation,
  configuration, GPO/SCCM/Intune, fleet, canary-shield and operations guide.
- **933 tests**, full suite and `-W error` pass.

## What's new in 1.24.1

- **Structured refusal for ACL intercept.** `intercept apply` on an ACL rule
  with no matching canary now returns a JSON refusal instead of a traceback.
- **Structured refusal for bad summaries.** `summarize --since` with an
  invalid duration returns a JSON query error instead of a traceback.
- **921 tests**, full suite and `-W error` pass.

## What's new in 1.24.0

- **Opt-in Defender controls.** `prevent cfa`, `prevent network` and
  `prevent driver-blocklist` now preview, apply, verify and roll back with
  the same plan gate as AppLocker and ASR. WDAC stays read-only.
- **Rollback that proves itself.** The previous value is captured at apply
  time and rollback verifies the restored value, not just the command exit.
- **Detection regression suite.** `plasma detect test` runs deterministic
  hit/miss cases for phishing, brute force, Kerberos spray, privilege to
  persistence, account creation and injection.
- **Hardened network fetches.** Every download is HTTPS-only, with no
  embedded credentials or control characters.
- **True read-only MCP reads.** `get_case` renders in memory and no longer
  writes a report file.
- **919 tests**, full suite and `-W error` pass.

## What's new in 1.23.0

- **Typed investigation.** `plasma query` is a closed local query language;
  `plasma tree` follows explicit PID lineage; `plasma summarize` produces a
  bounded digest for agent context.
- **Case workspace.** `plasma case` collects selected events and findings,
  records operator notes, renders a report and seals the artifacts with a
  hash manifest. `case verify` detects later changes.
- **Triggered memory triage.** `plasma memory triage` scans only PIDs
  selected by injection- or credential-shaped alerts.
- **Identity coverage.** Account creation/enable/reset, group membership,
  explicit credentials, special privileges and directory access now
  normalize into the event contract, with parent PID retained on 4688.
- **Detection harness.** `plasma detect validate|diff|replay` compiles
  rule regexes, compares rule sets and replays chains over a capture.
- **Honest posture.** `health` now accounts for blind spots and canary
  tamper; `prevent posture` reads WDAC, Controlled Folder Access, Network
  Protection and the vulnerable driver blocklist.
- **Agent surface.** Eight new typed MCP tools, including `query_events`,
  `get_process_tree`, `get_summary`, `get_case` and `simulate_policy`.
- **900 tests**, full suite and `-W error` pass.

## What's new in 1.21.0

- **Interception phases 0-3.** `plasma intercept` adds shadow rule
  evaluation, NTFS canary protection, an MCP tool-call gateway and a native
  ACL/firewall policy broker.
- **Plan-gated and reversible.** Every apply is dry-run first, single-use,
  payload-bound, journaled and reversible. No kernel driver.
- **Estate-verified on WS1 and WS2:** canary write denial and rollback,
  firewall apply/rollback, shadow matches and an MCP `INTERCEPTED` response.
- **833 tests**, full suite and `-W error` pass.

## What's new in 1.20.1

- **Root help matches the feature set.** `plasma --help` now names canary
  files and native DNS/HTTP tokens in the intro, not just "canary decoys".
- No behavior change; this is a help/documentation patch on top of 1.20.0.

## What's new in 1.20.0

- **Native canary tokens.** File canaries now use randomized, believable
  documents; DNS tokens are observed through a narrow Sysmon EID 22 include;
  HTTP tokens use a loopback-first local collector. No Docker, no cloud.
- **One evidence path.** DNS/HTTP hits become `source="canary"` alerts,
  `watch` surfaces them, `fleet` correlates them, and enforcement maps them
  to approval-gated isolation.
- **Canary accounts are in the sweep.** Configure `canary.accounts` and
  every watch sweep checks 4624/4625/4771/4776 with deduplication.
- **Field-verified on WS1 and WS2:** file deploy/verify/tamper, a real
  Sysmon EID 22 query, an HTTP collector hit, watch findings, and a real
  4625 on a disabled canary account.
- **823 tests**, full suite and `-W error` pass, `ruff check` clean.

## What's new in 1.19.3

- **MSI upgrades converge the running node.** The package now runs
  `install --force --rotate`, which swaps `bin\plasma.exe` and restarts the
  registered tasks after staging the new version. Before this, an MSI
  upgrade updated the files and config but left the service on the old
  binary.
- **Rotation is all-or-nothing.** A failed canonical swap returns exit 4
  with the rotation detail instead of reporting a successful install.
- **Verified on WS2:** silent MSI install exits 0, `bin\plasma.exe
  --version` and `/healthz` both report 1.19.3.
- **788 tests**, full suite and `-W error` pass, `ruff check` clean.

## What's new in 1.19.2

- **The MSI is now Authenticode-signed** in the release workflow, using the
  same PFX and timestamp as the exe. `SHA256SUMS` covers the signed MSI.
- **The MSI is built with `-arch x64`**, so it installs under
  `C:\Program Files\Plasma` instead of `Program Files (x86)`.
- **Verified on WS2:** silent MSI install exits 0, the installed exe and
  `/healthz` report 1.19.2.
- **786 tests**, full suite and `-W error` pass, `ruff check` clean.

## What's new in 1.19.1

- **HTTP boundary hardened.** Parsed command paths replace text scanning,
  read-only covers every mutating command, the default key is loopback-only,
  TLS handshakes run in worker threads, request desync is blocked, output is
  read under a hard byte cap, and mutations fail closed when auditing fails.
- **Response and prevention hardened.** Kill switch covers undo and
  prevention, approvals re-check policy and are atomic, protected
  paths/processes/tasks are canonicalized, plans are identity- and
  time-bound, capture failure gates automatic kills, and prevention
  rollback is plan-gated and verified.
- **Collection and data hardened.** Tap/observatory redaction, identity
  failure reporting, malformed WHIDS/watch rows skipped, content-aware
  dedupe, trace/MSI validation, deep persistence parsing, BOM-safe stores,
  canary/fleet/health/Sigma/notify/FIM fixes.
- **Install/update hardened.** Dry-run is read-only, operator config is
  preserved, Sysmon and updates require valid signatures, ring/hold/promote
  logic is fixed, rotation/rollback/locking is robust, prerelease ordering
  is correct.
- **Agent trust hardened.** Policy type validation, fail-closed tenants,
  ledger truncation detection, terminal denials and single-use approvals.
- **785 tests**, full suite and `-W error` pass, `ruff check` clean.

## What's new in 1.19.0

- **Every command has a detailed help page.** `plasma <command> --help`
  includes a description, working examples, notes, safety, output and
  related commands. `-h` works everywhere.
- **`plasma help` is the discovery command.** No topic prints the grouped
  command map and the dry-run → plan → apply workflow; a topic prints one
  detailed page.
- **`plasma help --json` is the machine catalog.** Schema
  `plasma.help/1` lists every command path, usage, argument, default,
  choice, example, safety class and see-also. One topic narrows it.
- **The HTTP API carries the same metadata.** `/v1/commands` rows include
  summary, description, examples and safety; `help --json` is runnable
  through `/v1/exec`.

## What's new in 1.18.0

- **Measured self-update.** `plasma update auto` checks the latest release
  and applies it through the existing SHA256 + Authenticode + install +
  rotate path. Signed releases only.
- **`PlasmaUpdate` daily SYSTEM task** with a random minute inside the
  02:00–05:00 maintenance window. `--no-autoupdate` disables it.
- **Ring-aware:** `broad` waits 24 hours; `canary` updates immediately;
  `rollback` never auto-updates. The kill switch pauses updates.
- **Previous binary kept.** `plasma rollback` still restores it; the
  canonical `plasma.exe` is rotated and `PlasmaServe` is restarted after a
  successful update.
- **`update-journal.jsonl` and `update-state.json`** record every attempt.
- **731 tests**, full suite green, ruff clean.

## What's new in 1.17.1

- **Critical process-guard fix.** `_g_process` wrapped the
  `Get-CimInstance` assignment in parentheses, so PowerShell emitted the
  whole CIM object as a formatted table. The guard compared table text to
  `PROTECTED_PROCESSES`, and `kill_process` on LSASS, CSRSS, SERVICES,
  WINLOGON, WHIDS or Sysmon minted a dry-run plan instead of refusing.
  The assignment is now bare and the guard refuses as designed.
- **716 tests**, full suite green, ruff clean.

## What's new in 1.17.0

- **Measured protection is armed by default.** Automatic containment is
  limited to `snapshot` + `kill_process` at score 9+, with a 2-action
  per-run cap and a 30-minute cooldown. The snapshot is written before the
  kill.
- **Everything else stays human-approved.** Host isolation, quarantine,
  disabling users, removing admins, stopping services, credential rotation,
  task/Run-key/WMI removal and IP blocking require approval.
- **`PlasmaWatch` drives the sweep.** A SYSTEM task runs
  `watch once --enforce` every 5 minutes. `--no-autoprotect` installs the
  old dry-run posture and removes the task.
- **Protected components stay protected in code.** WinRM, RDP, WHIDS,
  Sysmon, LSASS, BFE, MpsSvc, Administrator, SYSTEM and service accounts
  are refused; isolation keeps RDP/WinRM open.
- **New `plasma protect` commands:** `status`, `arm`, `disarm`,
  `protected`.
- **715 tests**, full suite green, ruff clean.

## What's new in 1.16.3

- **Command-tree type metadata.** `/v1/commands` now reports `type` (`int`,
  `str`, or null) for every option and positional. The OpenAPI `Option` and
  `Positional` schemas require the field.
- **698 tests**, full suite green, ruff clean.

## What's new in 1.16.2

- **Serve hardening.** Serialized argparse validation, byte-safe API-key
  comparison, 411 for missing `Content-Length`, socket timeouts, broken-pipe
  handling, UTF-8 child I/O, `stdin=DEVNULL`, and process-tree kill on
  timeout.
- **Audit reliability and redaction.** Serialized audit appends, a 30 s
  lock timeout, failed-write logging, and redaction of `--prompt` values
  and credential-shaped argv items.
- **Command tree completeness.** `/v1/commands` returns a separate `root`
  and 127 commands, each with `positionals` as well as options. The
  OpenAPI schemas describe both.
- **Explicit lifecycles.** `plasma/lifecycle.py` names the serve request,
  plan, approval, enforcement, prevention, WHIDS, FIM, canary, drift,
  identity-schedule, capture, fleet, kill-switch, tenant and ring
  machines, with pure classifiers used by the modules.
- **698 tests**, full suite green, ruff clean.

## What's new in 1.16.1

- **OpenAPI 3.1 for `plasma serve`.** `GET /openapi.json` publishes the
  spec; `GET /docs` serves a self-contained HTML reference. Both are
  unauthenticated. The spec covers the four API routes, both auth schemes
  and the error envelopes.
- **674 tests**, full suite green, ruff clean.

## What's new in 1.16.0

- **`plasma serve` — the full CLI over HTTP.** `POST /v1/exec` takes an
  argv list and runs it through the real parser, so every command, flag and
  default is available exactly as it is on the command line. `GET
  /v1/commands` returns the full command tree.
- **API-key auth, read-only mode, TLS, audit and hard timeouts.** The
  default bind is loopback and non-loopback binds refuse the default key;
`--api-key-file` or
  `PLASMA_SERVE_API_KEY` overrides it. `--read-only` refuses every mutating
  command. Every call lands in `<root>/serve/audit.jsonl`.
- **667 tests**, full suite green, ruff clean.

## What's new in 1.15.9

- **`observe canary` filters server-side.** The collector pulled every
  4624/4625 for seven days and timed out at 240 s on a busy DC. It now uses
  a `FilterXPath` on `TargetUserName`, so only canary logons cross the wire.
- **639 tests**, full suite green, ruff clean.

## What's new in 1.15.8

- **Observatory collectors get 240 s.** `observe edges` and `observe canary`
  exceeded the 90 s limit on a busy domain controller.
- **Fleet pull ships in the frozen exe.** `pywinrm` is now collected by
  PyInstaller, so `plasma fleet scan` works from the single-file binary.
- **Terminal approvals leave the queue.** `control approvals list` hides
  `approval_invalid`, `denied` and `expired` rows; the ledger keeps history.
- **638 tests**, full suite green, ruff clean.

## What's new in 1.15.7

- **`remove_run_key` accepts the canonical registry spelling.** The
  allowlist regex was case-sensitive and expected `SOFTWARE`; the real key
  is `Software`, so every `HKCU:\Software\...\Run` target was refused.
  The regex is now case-insensitive.
- **637 tests**, full suite green, ruff clean.

## What's new in 1.15.6

- **WHIDS `storm_first_ts` alerts validate.** The strict contract carries the
  timestamp WHIDS writes on storm alerts. WS1 parses 24,965/24,965 events;
  WS2 90,724/90,724.
- **636 tests**, full suite green, ruff clean.

## What's new in 1.15.5

- **WHIDS `storm_count` alerts validate.** The strict contract carries the
  integer `storm_count` WHIDS writes on storm alerts. WS1 now parses
  24,874/24,874 events; WS2 89,603/89,603.
- **635 tests**, full suite green, ruff clean.

## What's new in 1.15.4

- **Long command lines validate.** Encoded PowerShell can exceed 8 KiB;
  `cmdline` now allows 32 KiB.
- **WHIDS `storm` alerts validate.** The strict contract carries the boolean
  `storm` field WHIDS writes on storm alerts.
- **634 tests**, full suite green, ruff clean.

## What's new in 1.15.3

- **WHIDS `suppressed` alerts validate.** The strict event contract now
  carries the `suppressed` reason WHIDS writes on suppressed alerts.
- **`dest_ip` accepts workstation names and IPv6 zone IDs.** 4776 NTLM
  events put the calling machine in `dest_ip`; IPv6 may carry `%zone`.
  A 10,000-event sample from each host now validates with zero failures.
- **633 tests**, full suite green, ruff clean.

## What's new in 1.15.2

- **DTrace events validate.** The strict event contract now accepts
  `source="dtrace"`, `kind="trace"`, `event_id=0` and `action="observed"`.
  The estate drill had been counting every DTrace row as a parse failure:
  1,419/22,818 events on WS1 and 765/77,950 on WS2.
- **Persistence chains read the command line.** `description` matchers now
  also search `cmdline`, so a real 4688 `net user /add` followed by
  `schtasks` fires `persistence_after_privilege`. Findings carry the matched
  command line as evidence.
- **Snapshot and remove-admin survive domain controllers.** The
  `Administrators` lookup uses `net localgroup Administrators` instead of
  `Get-LocalGroupMember -Group 'Administrators'`, which fails with “group not
  found” or Win32 error 1789 on some hosts. The same fix covers
  `observatory.sketch`.
- **631 tests**, full suite green, ruff clean.

## What's new in 1.15.1

- **Security and state-machine hardening** — failed actions are journaled
  as failed, locks cover the whole operation, the kill switch fails closed,
  MCP defaults to read-only scopes, update tag pinning works, and manifest
  verification rejects path traversal.
- **Section-injection predicate fixed** — `NtMapViewOfSection` takes
  `(SectionHandle, ProcessHandle, ...)`; the script filtered `arg0`, so it
  fired on every section map. It now filters `arg1`. Negative control on
  WS2: 12 rows/5 s before, 0 after.
- **Telemetry provenance** — coverage now derives a third axis from the
  shipped Sysmon config: `live`, `partial`, `dormant` or `unknown` per rule
  and technique. Weighted coverage counts only rules that can actually fire.
- **The dormant rules are live** — the config now enables DriverLoad (6),
  unsigned ImageLoad (7), LSASS ProcessAccess (10) and PipeEvent (17/18),
  so the LSASS, unsigned-driver and named-pipe rules are no longer
  inventory. `sysmon_config` is a health check.
- **Injection depth** — four new DTrace scripts (hijack, hollow, section,
  remote write) and four chains, covering the primitives that leave no RWX
  flip or no new thread on their own.
- **259-rule Sigma corpus** — the Windows/Sysmon SigmaHQ tree converted,
  curated and vendored (168 techniques, DRL 1.1, provenance pinned).
  Coverage moves to **94.6 rollup / 89.2 exact / 85.9 weighted**; the blind
  set is down to input capture (T1056, T1056.001).
- **Capture before containment** — `enforce` writes a host snapshot before
  the first automatic kill, so the response does not delete the evidence
  the detection produced.
- **Prevention, two tiers** — `plasma enforce` turns watch findings into
  policy-gated, reversible containment (injection → kill the accessing
  process, canary → isolation for approval). `plasma prevent` configures
  the Windows enforcement points: AppLocker, firewall egress default-deny,
  Defender ASR and LSA protection. Off by default, dry-run first, journaled
  and rollbackable.
- **Full identity plane** — 4624/4625 logons, 4768/4769/4770/4771 Kerberos,
  4776 NTLM and 4688 process lineage with creator, parent and command line.
- **Coverage provenance** — evidence class derived from rule shape, so
  substr-only techniques are labelled keyword-only. 94.6 rollup /
  89.2 exact / 85.9 weighted; blind spots T1056, T1056.001.
- **Sigma, FIM, Sysmon gaps** — Sigma→gene conversion, critical-file
  integrity, and LSASS access / unsigned driver / named-pipe rules.
- **PyYAML is a feature dependency** — only `sigma convert` asks for it.
- 605 tests pass (21 skipped).

## What's new in 1.9.5

- **One handle test, both scripts** — `inject-rwx` now uses the same
  low-word comparison as `inject-remote-thread`, so self-RWX can never be
  misclassified by a 64-bit literal quirk.
- **APC chain** — cross-process RWX followed by an APC from the same image
  inside 30 s forms `injection_apc_chain` at score 9. `inject-apc` itself is
  documented as high-volume.
- **README corrected** — WHIDS is detect-only (`report`); containment is the
  separate, plan-gated response plane.
- 492 tests pass (21 skipped).

## What's new in 1.9.4

- **Injection precision** — `inject-rwx` now matches RWX with modifier bits
  and records whether the caller targeted itself or another process.
  Self-RWX (JIT) scores 5; cross-process RWX scores 8, and only that can
  satisfy `injection_chain`.
- **APC coverage** — `inject-apc` witnesses `NtQueueApcThread`,
  `NtQueueApcThreadEx` and `NtQueueApcThreadEx2`.
- Positive controls on WS1 and WS2 for self/cross-process RWX, remote
  threads and APC queueing. 488 tests pass (21 skipped).

## What's new in 1.9.3

- **Kernel-boundary injection evidence (T1055)** — two reviewed DTrace
  scripts witness the RWX permission flip (`inject-rwx`) and thread creation
  in another process (`inject-remote-thread`); `injection_chain` binds both
  to the same image at score 9.
- Field-verified on WS1 and WS2 (DTrace Sun D 1.13.1). Coverage stays
  91.7% rollup / 75.0% exact / 83.3% weighted; blind spots T1056,
  T1056.001, T1112.

484 tests pass (21 skipped).

## What's new in 1.9.2

- **DTrace descriptions redacted** — trace rows can carry command-line
  detail; the normalized description now passes through the same credential
  redactor as WHIDS alerts.

475 tests pass (21 skipped).

## What's new in 1.9.1

- **ACL hardening fixed for existing installs** — 1.9.0 applied an
  inheritable `(OI)(CI)` ACE recursively with `/T`, which left existing
  files with an inherit-only ACE (empty effective DACL) and Windows refused
  to execute them. The installer now adds explicit Full Control to every
  existing child after setting the root inheritance. This also restores
  nodes upgraded to 1.9.0.
- 475 tests pass (21 skipped).

## What's new in 1.9.0 — security review

A focused secure-code review of the agent and desk surfaces.

- **MCP context is server-authoritative** — `_meta` tenant/scopes were a
  self-asserted claim. Tenant and scopes now come from `PLASMA_TENANT` /
  `PLASMA_SCOPES`; trusting client `_meta` requires an explicit
  `PLASMA_TRUST_CLIENT_META=1`. Read tools are tenant-filtered, the health
  tool checks local-host ownership, and `isolate_host` is local-only.
- **Approval/allow-list fixes** — an explicit allow list can no longer
  bypass assist/supervised approval. Non-integer approval ids and
  oversized/malformed JSON-RPC requests are refused without crashing the
  server.
- **DTrace MSI verification** — the downloaded Microsoft MSI must carry a
  valid Microsoft Authenticode signature before `msiexec` runs.
- **Notification secrets** — webhooks must be HTTPS; Telegram tokens are
  redacted from error strings.
- **Filesystem** — the installer restricts `%ProgramData%\Plasma` to
  SYSTEM + Administrators (well-known SIDs), protecting policy, kill-switch,
  approvals, ledger and events from inherited ProgramData permissions.
- **Fleet transport** — WinRM endpoints must be HTTPS unless
  `allow_insecure_winrm: true` is set for a controlled lab.
- **Response hardening** — isolation also allows outbound RDP/WinRM
  responses, loopback/broadcast block targets are refused, the current user
  is protected from disable/rotate, and gene-rule domains are escaped and
  validated against rule injection.

474 tests pass (21 skipped).

## What's new in 1.8.7

- **PowerShell policy-test scratch files are suppressed** — every
  PowerShell start deletes a `__PSScriptPolicyTest_*.ps1` file in Temp.
  That produced fleet `shared_hash` findings on every host pair (identical
  content) and a stream of low-value File-Delete alerts. Both are now
  recognised as PowerShell housekeeping.

454 tests pass (21 skipped).

## What's new in 1.8.6

- **Fleet reads a bounded tail over WinRM** — the previous base64 read
  returned the whole events store; a large store exceeded the WinRM
  envelope and the host answered HTTP 400. The pull now reads only the
  last ~1 MB (enough for the 200-row cap), then falls back to line mode.

452 tests pass (21 skipped).

## What's new in 1.8.5

- **Pull clears the watch backlog counter** — after `whids pull`, the next
  `watch` sweep no longer reports the same alert rows as "unpulled".
- **Legacy storm summaries are covered** — inverted first/last timestamps
  from 1.8.3 are normalised before coverage checks, so old storms do not
  spawn duplicates.

452 tests pass (21 skipped).

## What's new in 1.8.4

- **Storm windows are time-ordered** — alert files are scanned by path, so
  a storm spanning rotated logs could record `first_ts` after `last_ts`.
  Groups are sorted before sampling and summarising.

451 tests pass (21 skipped).

## What's new in 1.8.3

- **Alert-storm coalescing** — a process repeating the same Tcpip service
  key write 17k times no longer stores 17k rows. `whids pull` keeps a few
  samples plus one summary (count, first/last timestamp, max score), and
  re-pulling is idempotent. `watch` collapses identical findings into one
  line with an occurrence count.
- **Why it matters** — the signal (one agent looping on a privileged key)
  stays visible; the diary and the alert budget do not drown in it.

450 tests pass (21 skipped).

## What's new in 1.8.2

- **Windows service-path suppression widened** — ADFS and Microsoft.NET
  service binaries also update their service keys during normal operation.
  They are now suppressed alongside System32/SysWOW64; `C:\Windows\Temp`,
  `Tasks` and `Debug` are explicitly excluded, and LOLBins keep full score.

448 tests pass (21 skipped).

## What's new in 1.8.1

A short follow-up from the live estate run of 1.8.0.

- **Service-registry false-positive storm fixed** — Windows' own service
  binaries (`dns.exe`, `lsass.exe`, `DFSRs.exe`, AD WebServices) produced
  401 criticality-8 alerts on one server during normal servicing. They are
  now suppressed by System32/SysWOW64 path evidence; `reg.exe`, `sc.exe`
  and PowerShell keep the full score.
- **Fleet shared-hash noise fixed** — `cmd.exe`/`powershell.exe` hashes are
  identical on every Windows host and no longer become score-8 cross-host
  findings. User-path hashes still do.
- **Watch first sweep no longer floods** — a fresh install/upgrade starts
  at the current end of the alert log; only new criticality-8+ alerts are
  surfaced. Compressed/archived logs are excluded from counts.
- **Run-key suppression narrowed** — a Microsoft-signed LOLBin writing a
  Run key is the technique, not a benign installer.

447 tests pass (21 skipped).

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

- **Capability contract** — 20 typed tools with scopes, risk tiers,
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
- **Honest ATT&CK coverage** — 91.9% with parent rollup, 64.7%
  fidelity-weighted (keyword-only evidence derived and discounted), and the
  blind spots named out loud.
- **Deep persistence probe** — every auto-start location with Authenticode
  status and a surfaced `suspect` heuristic; no driver, no service.
- **Signed updates** — `update apply` refuses any binary whose Authenticode
  signer does not match thumbprints pinned inside the installed exe.
- **Playbooks** — `contain-user`, `isolate-box`: fixed sequences applied as
  one plan-gated unit, aborting on the first failure, reversible last-first.
- **Store hygiene** — `store rotate|compact|stats` keeps the diary bounded.
- **Interception** — typed rules compiled into NTFS ACLs, Windows
  Firewall rules and the MCP tool-call gateway; plan-gated and reversible.
- **Canaries and tokens** — randomized, believable decoy documents
  (score 10 on modification/deletion), DNS hostname tokens observed through
  a narrow Sysmon EID 22 include (score 8), HTTP `.url` tokens served by a
  loopback-first local collector (score 8), and configured canary accounts
  (score 10). All hits land in the same `source="canary"` event path.
- **MSI + GPO** — an enterprise package that provisions a node silently
  through Group Policy.
- **DTrace, on demand** — reviewed, bounded kernel/syscall tracing where
  the host supports it, normalized into the same event contract.

## Doctrine

1. **Read-only by default.** Collectors read. Manual actions require
   `--apply --plan <id>` from a seen dry-run.
2. **Containment is armed but narrow; prevention is audit-first.**
   `enforce` is limited to `snapshot` + `kill_process` at score 9+, with
   isolation and every other action behind approval. `prevent` does
   nothing until you apply a plan. Both are policy-gated and journaled.
3. **Deterministic.** Detection is written rules and written chains. The
   model selects probes; it never decides guilt and never runs commands.
4. **Bounded.** Every collector has a time window, a row cap and a size cap.
5. **Local.** Events never leave the host by default. The desk pulls what it
   needs.
6. **Reversible.** Every applied action or prevention control carries a
   journal entry and an undo recipe — where something cannot be undone, the
   CLI says so up front.

## Where to go next

- New here? [Getting started](getting-started.md).
- Want the mental model? [Concepts](concepts.md).
- Operating an estate? [Operations](operations.md) and [Fleet](fleet.md).
- About to respond to an incident? [Response](response.md).
- Judging it for a regulated environment? [Security model](security-model.md).
