# Changelog

The canonical history lives in
[CHANGELOG.md](https://github.com/DrOlu/plasma/blob/main/CHANGELOG.md).
Highlights by release:

## 1.19.2 — 2026-11-18

Enterprise MSI packaging.

- **The MSI is Authenticode-signed** in the release workflow, using the same
  PFX and timestamp as the exe; `SHA256SUMS` covers the signed MSI.
- **The MSI is built with `-arch x64`**, so it installs under
  `C:\Program Files\Plasma` instead of `Program Files (x86)`.
- Verified on WS2: silent MSI install exits 0, installed exe and `/healthz`
  report 1.19.2.
- 786 tests collected; full suite and `-W error` pass; `ruff check` clean.

## 1.19.1 — 2026-11-18

Holistic security and correctness review.

- **HTTP boundary:** canonical parsed command paths, complete read-only
  coverage, loopback-only default key, TLS handshake in the worker thread,
  request-smuggling defenses, incremental output caps, audit redaction and
  fail-closed auditing for mutations.
- **Response/prevention:** kill switch covers undo and prevention, approval
  queue re-checks policy and is atomic, protected paths/processes/tasks are
  hardened, plans are identity- and time-bound, capture failure gates
  automatic kills, prevention rollback is plan-gated and verified.
- **Collection/data:** tap/observatory/drift redaction, identity failure
  reporting, malformed WHIDS/watch rows skipped, content-aware dedupe,
  trace validation/MSI hardening, deep persistence parsing, BOM-safe store,
  canary/fleet/health/Sigma/notify/FIM fixes.
- **Install/update:** dry-run is read-only, operator config is preserved,
  Sysmon and updates require valid signatures, ring/hold/promote logic
  fixed, rotation/rollback/locking hardened, prerelease ordering fixed.
- **Agent trust:** policy type validation, fail-closed tenants, ledger
  truncation checkpoint, terminal denials and single-use approvals.
- 785 tests collected; full suite and `-W error` pass; `ruff check` clean.

## 1.19.0 — 2026-11-18

Agent-oriented help for every command.

- **Every command has a detailed help page.** Description, examples,
  notes, safety, output and see-also, not just flags. `-h` works
  everywhere.
- **`plasma help` is the discovery command.** Grouped command map and the
  dry-run → plan → apply workflow; `plasma help <path>` for one command.
- **`plasma help --json` is the machine catalog.** Schema
  `plasma.help/1` with every path, argument, example and safety class.
- **The HTTP API carries the same metadata.** `/v1/commands` rows include
  summary, description, examples and safety; `help --json` is executable
  through `/v1/exec`.
- 755 tests collected; full suite passes; ruff error-level checks clean.

## 1.18.6 — 2026-11-18

Manual administrator updates can clear SYSTEM-owned stale processes.

- **Escalate the cleanup to SYSTEM when needed.** A remote Administrator
  token often cannot terminate SYSTEM-owned `serve` processes
  (`Access is denied`), which left the old API image on port 9999 after a
  manual `update auto`. If any plasma process survives the direct kill and
  the updater is not already SYSTEM, it registers a one-shot SYSTEM task to
  finish the cleanup, waits, and removes the task. The normal
  `PlasmaUpdate` path is already SYSTEM and skips the escalation.
- 743 tests collected; full suite passes; ruff error-level checks clean.

## 1.18.5 — 2026-11-18

Serve-process cleanup that works on hardened hosts.

- **Identify lingering plasma processes by image name.** WS1 hides
  `CommandLine` and `ExecutablePath` from WMI, so the command-line match
  used in 1.18.4 found nothing and the old serve process kept port 9999.
  The updater now walks its own ancestor chain and stops every other
  `plasma*` process before rotation. All of them are restarted by
  `_start_tasks` (or by their normal schedule), and the update process
  cannot kill itself.
- 742 tests collected; full suite passes; ruff error-level checks clean.

## 1.18.4 — 2026-11-18

Ring selection and serve restart fixes found on the live estate.

- **An explicit host ring now wins.** A host assigned to `canary` was still
  compared against the configured default (`broad`) and skipped by the
  `PlasmaUpdate` task. `update auto` now derives the ring from the host's
  assignment, falling back to `config.json` only when the host is unassigned.
- **Restarting `PlasmaServe` actually restarts the API.** PyInstaller's
  one-file bootloader re-execs itself as a child; `schtasks /end` killed the
  parent but left the child holding port 9999, so `/healthz` kept reporting
  the old version. The updater now stops lingering `serve` processes before
  rotation so the restarted task binds and serves the new binary.
- 742 tests collected; full suite passes; ruff error-level checks clean.

## 1.18.3 — 2026-11-18

Manual `update apply` shares the hardened rotation path.

- **`update apply` now quiesces and restarts the scheduled tasks** with the
  same `rotate_running` helper as `update auto`, so the manual path cannot
  hit the in-use-image failure that prompted 1.18.2.
- 738 tests collected; full suite passes; ruff error-level checks clean.

## 1.18.2 — 2026-11-18

Self-update rotation reliability on Windows.

- **The tasks holding the binary are quiesced around the swap.**
  `PlasmaServe`, `PlasmaWatch`, `PlasmaWhidsWatchdog` and
  `PlasmaIdentityPull` stop before rotation and restart afterwards; a
  serve-launched update skips `PlasmaServe` so it cannot kill itself.
- **Retries and stale-backup recovery.** A locked image is retried five
  times, a stale `.old` backup is preserved under a unique name, a
  read-only attribute is cleared first, and a failed swap restores the
  previous binary. `PlasmaServe` restarts after the update, so `/healthz`
  reports the new version.
- 737 tests collected; full suite passes; ruff error-level checks clean.

## 1.18.1 — 2026-11-18

Self-update install robustness.

- **A locked staged exe no longer aborts the install.** The installer
  skips the `sys.executable` copy when the bytes already match and
  tolerates a locked destination; the updater's rotation is authoritative.
- 731 tests collected; full suite passes; ruff clean.

## 1.18.0 — 2026-11-18

Measured self-update.

- **`plasma update auto`** checks the latest release and applies it through
  the existing SHA256 + Authenticode + install + rotate path. Signed
  releases only.
- **`PlasmaUpdate` daily SYSTEM task** with a random minute inside the
  02:00–05:00 maintenance window. `--no-autoupdate` disables it.
- **Ring-aware:** `broad` waits 24 hours; `canary` updates immediately;
  `rollback` never auto-updates.
- **Kill-switch aware; one update at a time; previous binary kept.**
- **Canonical `plasma.exe` rotated** and `PlasmaServe` restarted after a
  successful update.
- **`update-journal.jsonl` and `update-state.json`** record every attempt.
- 731 tests collected; full suite passes; ruff clean.

## 1.17.1 — 2026-11-17

Critical process-guard fix.

- **Protected process names were not matched.** `_g_process` wrapped the
  `Get-CimInstance` assignment in parentheses, so PowerShell emitted the
  whole CIM object as a formatted table. The guard compared table text to
  `PROTECTED_PROCESSES`, and `kill_process` on LSASS, CSRSS, SERVICES,
  WINLOGON, WHIDS or Sysmon minted a dry-run plan instead of refusing.
  The assignment is now bare and the guard refuses as designed.
- 716 tests collected; full suite passes; ruff clean.

## 1.17.0 — 2026-11-17

Measured protection is armed by default.

- **Automatic containment is on, but narrow.** Default policy:
  `enabled: true`, `mode: "enforce"`, `min_score: 9`,
  `allowed_actions: ["snapshot", "kill_process"]`, 2 actions per run,
  30-minute cooldown. Snapshot is written before the kill.
- **Everything else stays human-approved.** Isolation, quarantine,
  disabling users, removing admins, stopping services, credential
  rotation, task/Run-key/WMI removal and IP blocking require approval.
- **`PlasmaWatch` drives the sweep.** A SYSTEM task runs
  `watch once --enforce` every 5 minutes. `--no-autoprotect` installs the
  old dry-run posture and removes the task.
- **Protected components stay protected in code.** WinRM, RDP, WHIDS,
  Sysmon, LSASS, BFE, MpsSvc, Administrator, SYSTEM and service accounts
  are refused. Isolation keeps RDP/WinRM open.
- **Upgrades migrate the old default; custom blocks are preserved.**
- **New `plasma protect` commands:** `status`, `arm`, `disarm`,
  `protected`.
- 715 tests collected; full suite passes; ruff clean.

## 1.16.3 — 2026-11-17

Command-tree type metadata.

- **Options and positionals carry their argparse type.** `/v1/commands` now
  reports `type` (`int`, `str`, or null) for every option and positional.
  The OpenAPI `Option` and `Positional` schemas require the field.
- 698 tests collected; full suite passes; ruff clean.

## 1.16.2 — 2026-11-17

Serve hardening, command-tree completeness and explicit lifecycles.

- **Serve concurrency and edge cases.** Argparse validation is serialized;
  API keys are compared as bytes; a missing `Content-Length` returns 411;
  the handler has a socket timeout; broken pipes are ignored; child
  processes get UTF-8 I/O, `stdin=DEVNULL`, and a process-tree kill on
  timeout.
- **Audit reliability and redaction.** Audit appends are serialized and
  use a 30 s lock timeout; failed writes are logged. `--prompt` values and
  credential-shaped argv items are redacted.
- **Command tree completeness.** `/v1/commands` returns a separate `root`
  and 127 commands, each with `positionals` as well as options. The
  OpenAPI schemas describe both.
- **Explicit lifecycles.** `plasma/lifecycle.py` names the serve request,
  plan, approval, enforcement, prevention, WHIDS, FIM, canary, drift,
  identity-schedule, capture, fleet, kill-switch, tenant and ring
  machines, with pure classifiers used by the modules.
- 698 tests collected; full suite passes; ruff clean.

## 1.16.1 — 2026-11-17

OpenAPI 3.1 for `plasma serve`.

- **`GET /openapi.json`** publishes an OpenAPI 3.1 document covering the
  four API routes, both auth schemes, the request/response envelopes and
  the error responses. No auth required.
- **`GET /docs`** serves a self-contained HTML reference that renders the
  spec; no CDN, no external dependency.
- **`plasma/openapi.py`** is the single source of truth; `info.version`
  tracks the package version, and a unit test asserts the spec paths and
  the server routes do not drift apart.
- 674 tests collected; full suite passes; ruff clean.

## 1.16.0 — 2026-11-17

`plasma serve`: the full CLI over an authenticated HTTP API.

- **One endpoint, the whole CLI.** `POST /v1/exec` takes an argv list and
  runs it through the real parser, so every command, flag and default is
  available exactly as it is on the command line. `GET /v1/commands`
  returns the full command tree with options, mutating flags and
  long-running markers.
- **API-key auth.** Bearer token or `X-API-Key`; the default is
  `plasmaplasma` for lab use, and `--api-key-file` or
  `PLASMA_SERVE_API_KEY` overrides it.
- **Read-only mode.** `--read-only` refuses every command that changes host
  or Plasma state, including any `--apply`.
- **Bounded execution.** Each call runs in a child process with a hard
  timeout, a 1 MiB request cap and an 8 MiB output cap.
- **Audit.** Every call is appended to `<root>/serve/audit.jsonl`.
- **TLS.** `--tls-cert` and `--tls-key` wrap the listener in HTTPS.
- 667 tests collected; full suite passes; ruff clean.

## 1.15.9 — 2026-11-17

Canary collector performance.

- **`observe canary` filters server-side.** The collector pulled every
  4624/4625 for seven days and timed out at 240 s on a busy DC. It now uses
  a `FilterXPath` on `TargetUserName`, so only canary logons cross the wire.
- 639 tests collected; full suite passes; ruff clean.

## 1.15.8 — 2026-11-17

Operational gaps from the deep drill.

- **Observatory collectors get 240 s.** `observe edges` and `observe canary`
  exceeded the 90 s limit on a busy domain controller. The default is now
  240 s; the dedicated `canary status` and `fim verify` paths are unchanged.
- **Fleet pull ships in the frozen exe.** `pywinrm` is now a build
  dependency and is collected by PyInstaller, so `plasma fleet scan` works
  from the single-file binary, not only from a Python desk install.
- **Terminal approvals leave the queue.** `control approvals list` no longer
  shows rows whose outcome is `approval_invalid`, `denied` or `expired`;
  the audit ledger still keeps the history.
- 638 tests collected; full suite passes; ruff clean.

## 1.15.7 — 2026-11-17

Run-key allowlist fix from the deep drill.

- **`remove_run_key` accepts the canonical registry spelling.** The
  allowlist regex was case-sensitive and expected `SOFTWARE`; the real key
  is `Software`, so every `HKCU:\Software\...\Run` target was refused.
  The regex is now case-insensitive.
- 637 tests collected; full suite passes; ruff clean.

## 1.15.6 — 2026-11-17

Final WHIDS storm field.

- **WHIDS `storm_first_ts` alerts validate.** The strict contract carries the
  timestamp WHIDS writes on storm alerts. WS1 parses 24,965/24,965 events;
  WS2 90,724/90,724.
- 636 tests collected; full suite passes; ruff clean.

## 1.15.5 — 2026-11-17

Last contract field from the 1.15.4 estate audit.

- **WHIDS `storm_count` alerts validate.** The strict contract carries the
  integer `storm_count` WHIDS writes on storm alerts. WS1 now parses
  24,874/24,874 events; WS2 89,603/89,603.
- 635 tests collected; full suite passes; ruff clean.

## 1.15.4 — 2026-11-17

Final contract edges from the 1.15.3 estate audit.

- **Long command lines validate.** Encoded PowerShell can exceed 8 KiB;
  `cmdline` now allows 32 KiB.
- **WHIDS `storm` alerts validate.** The strict contract carries the boolean
  `storm` field WHIDS writes on storm alerts.
- 634 tests collected; full suite passes; ruff clean.

## 1.15.3 — 2026-11-17

Deeper contract audit from the same estate drill.

- **WHIDS `suppressed` alerts validate.** The strict `PlasmaEvent` contract
  now carries the `suppressed` reason WHIDS writes on suppressed alerts.
- **`dest_ip` accepts workstation names and IPv6 zone IDs.** 4776 NTLM
  events put the calling machine in `dest_ip`; IPv6 may carry `%zone`.
  A 10,000-event sample from each host now validates with zero failures.
- 633 tests collected; full suite passes; ruff clean.

## 1.15.2 — 2026-11-16

Field-found fixes from the neuralOSd-orchestrated estate drill.

- **DTrace events now validate.** The strict `PlasmaEvent` contract accepts
  `source="dtrace"`, `kind="trace"`, `event_id=0` and `action="observed"`.
  Before this, every DTrace row was counted as a parse failure: 1,419/22,818
  events on WS1 and 765/77,950 on WS2.
- **Persistence chains read the command line.** `description` matchers now
  also search `cmdline`, so a real 4688 `net user /add` followed by
  `schtasks` fires `persistence_after_privilege` instead of being invisible.
  Findings now carry the matched `cmdline` as evidence.
- **Snapshot and remove-admin survive domain controllers.** The
  `Administrators` lookup uses `net localgroup Administrators` instead of
  `Get-LocalGroupMember -Group 'Administrators'`, which fails with “group not
  found” or Win32 error 1789 on some hosts. The same fix covers
  `observatory.sketch`.
- 631 tests collected; full suite passes; ruff clean.

## 1.15.1 — 2026-11-15

Two field-found follow-ups to the review.

- **Non-terminating PowerShell errors now fail the action.** `Disable-LocalUser`
  on a missing account writes an error but leaves `$LASTEXITCODE` at 0, so
  the action was journaled as applied. `actuate` now runs payloads with
  `$ErrorActionPreference='Stop'`; the estate drill now records
  `mode: failed`.
- **PowerShell BOM state files are readable.** `Set-Content -Encoding UTF8`
  writes a BOM; `agentstate.read_json` and the kill-switch reader now use
  `utf-8-sig`. The kill-switch restore drill had left the switch engaged.
- 605 passed / 21 skipped.

## 1.15.0 — 2026-11-15

Holistic security and state-machine review.

- **Failed actions are no longer reported as applied.** `actuate` now checks
  the payload exit code, journals `mode: failed` with a `failure` reason,
  and still allows undo of a partially applied action. Playbook undo marks
  the whole reversal failed instead of claiming success.
- **Locks cover the whole operation.** A shared `agentstate.lock` uses a PID
  token and a 300 s stale window; the old 30 s window let a second process
  steal the actuate journal lock during a 60 s apply. State machines,
  ledger, prevention, enforcement, rings, killswitch and policy writes use
  it.
- **Kill switch fails closed.** A corrupt `killswitch.json` now reports the
  switch engaged instead of silently disabling containment.
- **MCP is least-privilege by default.** A harness that does not declare
  `PLASMA_SCOPES` gets read-only scopes, not `*`. Policy evaluation with no
  scopes denies instead of inheriting a wildcard.
- **Update pinning works.** `download_and_verify` honours the requested tag
  (it silently installed latest before), matches the SHA256SUMS line to the
  actual exe asset, and `update apply --tag` exposes it.
- **Path and quoting hardening.** Manifest verification rejects `..` paths;
  the WHIDS watchdog task escapes single quotes; DTrace validation catches
  whitespace-separated `system (`; AppLocker allow paths reject control
  characters; WMI capture and removal use the same bounded set.
- **Enforcement approvals are single-use and policy-checked.** Pending
  requests are deduplicated, consumed on approval, and re-checked against
  the current allowlist.
- 602 passed / 21 skipped.

## 1.14.3 — 2026-11-15

Fix the section-injection predicate.

- `NtMapViewOfSection` takes `(SectionHandle, ProcessHandle, ...)`. The
  script filtered `arg0` (the section handle) against the process
  pseudo-handle, so the predicate was always true and fired on every
  section map. It now filters `arg1`.
- Negative control on WS2: the old predicate produced 12 rows in 5 s
  (including Sysmon mapping its own sections); the fixed predicate produced
  0. The chain still requires a remote thread from the same image.
- Removed the constant `remote` / `remote_thread` fields the scripts emitted
  after the predicate had already established the distinction.
- The handle test is split per script instead of looping over three
  different syscall signatures.
- 583 passed / 21 skipped.

## 1.14.2 — 2026-11-15

Enable both halves of the named-pipe rule.

- The Sysmon `PipeEvent` include filter named only `CreatePipe`, so EID 18
  (ConnectPipe) never fired. A live pipe-connect test on WS1/WS2 returned
  zero EID 18 events. The config now includes both types.
- The telemetry parser honours the `EventType` filter instead of assuming
  the element enables 17 and 18 together.
- 583 passed / 21 skipped.

## 1.14.1 — 2026-11-15

Ship the config the telemetry axis reads.

- `sysmon-config.xml` is now part of the embedded sensor payload. Without
  it, an installed node could not derive `live`/`dormant` and reported 17
  techniques as `unknown` (weighted 82.7 instead of 85.9). The field check
  caught it on both hosts.
- 581 passed / 21 skipped.

## 1.14.0 — 2026-11-15

Telemetry provenance, and the injection primitives that leave no RWX flip.

- **Third provenance axis** — coverage derives `live` / `partial` / `dormant`
  / `unknown` per rule and technique from the shipped Sysmon config. Weighted
  coverage counts only rules that can fire; `weighted_all_pct` keeps the
  unfiltered number for comparison, and `dormant_techniques` names what is
  inventory rather than coverage.
- **Dormant rules made live** — the config now enables DriverLoad (6),
  unsigned ImageLoad (7), LSASS ProcessAccess (10) and PipeEvent (17/18).
  The LSASS, unsigned-driver and named-pipe rules from 1.10.0 are no longer
  inventory. `sysmon_config` is a health check that names missing event IDs.
- **Config drift fixed** — `sensors/sysmon-config.xml` and the installed
  config are now the same document; the FileDelete include filter the docs
  promised is present, and FileCreate is documented.
- **Injection depth** — four new reviewed DTrace scripts: thread hijack
  (`NtSetContextThread`), hollowing (`NtUnmapViewOfSection`), section map
  (`NtMapViewOfSection`) and remote write (`NtWriteVirtualMemory`). Four
  chains bind them to a remote thread from the same image; the write chain
  covers the case with no RWX flip and no new thread of its own.
- 580 passed / 21 skipped.

## 1.13.0 — 2026-11-15

Detection breadth, finally. The pipeline existed; the corpus did not.

- **259-rule SigmaHQ corpus** (`sensors/plasma-sigma.gen`) converted from
  the Windows/Sysmon tree at commit `54967d64`, curated to 168 techniques.
  Provenance in `sigma-sources.json`; the data ships under DRL 1.1 with the
  licence text, not MIT. Rebuild with `tools/sync_sigma_corpus.py`.
- **Coverage** moves to **94.6% rollup (35/37), 89.2% exact (33/37), 85.9%
  fidelity-weighted**. Blind set is down to input capture: T1056,
  T1056.001.
- **Converter correctness** — gene conditions now translate Sigma `not` to
  the gene `!` grammar. The first field load proved WHIDS rejects `not`
  outright; 278 rules (19 baseline/IOC + 259 Sigma) now compile and load
  with no errors. Unsupported modifiers (`windash`, `cidr`, `base64offset`,
  `fieldref`) are refused rather than mistranslated. `|all` is implemented
  as an AND of per-value match variables; upstream author and source file
  are preserved for DRL attribution.
- **Containment auto-path** now includes credential access (T1003 family)
  and token manipulation (T1134 family), still behind the score-9 floor and
  the capture-first snapshot.
- **Prevention safety** surfaces `capture_ok` at run level.
- 572 passed / 21 skipped.

## 1.12.2 — 2026-11-15

Response review fixes: capture the evidence before deleting it.

- **Capture before containment.** `enforce` now writes one host-state
  snapshot (read-only export, through the dry-run + plan gate) before the
  first automatic `kill_process` in a run. Killing the injecting process
  destroys the in-memory artifact the detection exists to surface; the
  journal records `capture: applied|failed|skipped`. Default
  `allowed_actions` is now `["snapshot", "kill_process"]`. Operators can
  drop snapshot for speed or move kill into `require_approval` for
  forensics first.
- **Egress DNS warning.** `prevent egress` warns when no port-53 destination
  is in the allowlist, instead of leaving the documentation to promise a
  guard the code did not enforce. It still refuses an empty allowlist.
- **Security-model anchors committed** — enforcement and prevention
  journals/backups are recorded in the published threat model (the edit
  landed after the 1.12.1 tag).
- Website response copy no longer implies all action is manual.
- 563 passed / 21 skipped.

## 1.12.1 — 2026-11-15

Field fixes from the first prevention drill on the estate.

- **AppLocker verification** now reads the local policy object. `-Effective`
  lagged the local write and reported zero rules immediately after a
  successful apply; the field drill showed `applied: true, rules: 0`.
  Verified on WS2: apply → 4 rules, audit mode; rollback → 0 rules.
- **AppLocker rollback** applies an empty policy when there was no prior
  policy. Removing the registry key did not clear a locally-applied policy;
  the empty-policy path does (verified on WS2).
- **Prevention status** no longer reports a phantom `null` ASR rule when
  Defender returns empty arrays.
- 558 passed / 21 skipped.

## 1.12.0 — 2026-11-15

Prevention, in two honest tiers.

- **Tier 0 — `plasma enforce`**: watch findings become policy-gated,
  reversible containment. Injection findings and chain detections kill the
  accessing process; a tripped canary queues host isolation for approval.
  Off by default and dry-run unless `enabled` + `mode: enforce` are set.
  Score floor, per-run cap, cooldown, action allowlist, approval queue,
  kill switch and a decision journal. `watch once --enforce` wires it to a
  sweep.
- **Tier 1 — `plasma prevent`**: AppLocker (audit by default), firewall
  egress default-deny with a mandatory allowlist, Defender ASR rules and LSA
  protection. Every control is dry-run first, plan-gated, verified, journaled
  and rollbackable by id.
- **Still no kernel driver.** Inline blocking at the file/process/network
  boundary is delegated to Microsoft's signed enforcement points; Plasma owns
  the policy, evidence and rollback. This is a deliberate limit, documented
  in `docs/prevention.md`.
- Findings now carry structured entities (pid, user, path, technique) so
  enforcement acts on data instead of re-parsing text.
- 555 passed / 21 skipped.

## 1.11.0 — 2026-11-15

Identity coverage beyond logons, and the lineage edge that was missing.

- **Kerberos and NTLM** — `identity pull` now reads 4768 (TGT), 4769
  (service ticket), 4770 (renewal), 4771 (pre-auth failure) and 4776 (NTLM
  credential validation) in addition to 4624/4625. Kerberos IDs are
  KDC-generated: a domain controller reports them, a member server reports
  zero, and the result says so rather than erroring.
- **4688 process lineage** — process-creation records are normalized as
  `kind="process"` with creator subject, parent image, full image path and
  command line (redacted). This is the creator→child edge the store did not
  have; Sysmon EID 1 remains the richer source where installed.
- **`kerberos_brute_force` chain** (score 9) — five 4771 pre-auth failures
  followed by a 4768 TGT success for the same account within 30 minutes.
- **Bounded and allowlisted** — `--max-events` (default 2000) caps every
  pull; `--ids` accepts only the supported set, rejecting anything else
  before PowerShell runs. Machine accounts and realm-qualified UPNs are
  normalized correctly.
- Field-verified on the estate: WS1 (DC) produced 4768/4769/4771/4776 and
  4688 rows with zero normalization failures; WS2 (member) produced 4688
  lineage and zero Kerberos, as expected.
- 529 passed / 21 skipped.

## 1.10.1 — 2026-11-15

Two claims made honest, one release after the features landed.

- **Evidence class is derived, not declared.** A tap rule whose only match
  key is `substr` is keyword evidence; anything structured is behavioural.
  The label is computed from the rule at coverage time, so it cannot drift
  from the rules. Result: 15 keyword-only techniques (was reported as 2),
  and `weighted_pct` falls to the honest **64.7%** (was 80.3%). It climbs
  back as behavioural rules land.
- **PyYAML is no longer a startup dependency.** `import yaml` moved into the
  Sigma parser; `plasma sigma convert` gives a clean message if PyYAML is
  absent, and every other command (watch, canary, coverage, `--version`)
  starts without it.
- 513 passed / 21 skipped.

## 1.10.0 — 2026-11-15

Detection breadth, standing authentication, and coverage honesty.

- **Sigma -> gene converter** (`plasma sigma convert`): Windows/Sysmon
  categories, field modifiers and boolean conditions map mechanically; every
  refused rule is reported with its reason.
- **Three Sysmon gaps closed** — EventID 10 (LSASS access, T1003.001),
  EventID 6 (unsigned driver from a user-writable path, T1014), EventID
  17/18 (PsExec/Cobalt-shaped named pipes, T1021/T1090).
- **FIM** (`plasma fim baseline|verify|status`): configurable critical paths,
  hash/size diff, and watch findings at 8 (modified/removed) and 6 (added).
  This is the PCI DSS 11.5.1 control, separate from canaries.
- **Standing identity pull** — `install`/`update` registers the SYSTEM task
  `PlasmaIdentityPull` (15 minutes), so 4624/4625 reach the store between
  operator sweeps. `plasma identity schedule|schedule-status|unschedule`.
- **Coverage provenance** — T1055/T1055.001 are labelled `keyword-only` and
  discounted in `weighted_pct`. T1021 is now in the core matrix and covered
  by the named-pipe rule. Coverage: 91.9 rollup (34/37), 75.7 exact (28/37),
  80.3 weighted; blind T1056, T1056.001, T1112.
- 509 passed / 21 skipped.

## 1.9.5 — 2026-11-15

Consistency and claim corrections.

- `inject-rwx` now tests the target handle with the same low-word form as
  `inject-remote-thread` (`(arg0 & 0xffffffff) == 0xffffffff`). Both scripts
  make one platform assumption; a build that truncates 64-bit literals can
  no longer turn self-RWX into a high-severity event.
- `injection_apc_chain` (score 9, 30 s) escalates a cross-process RWX flip
  followed by an APC from the same image. `inject-apc` is documented as
  high-volume and is not chained on its own.
- README no longer claims WHIDS kills or contains: the shipped config is
  detect-only (`report`), and containment lives in the plan-gated response
  plane.
- 492 passed / 21 skipped.

## 1.9.4 — 2026-11-14

Injection evidence precision, with positive controls on both hosts.

- `inject-rwx` matches RWX with modifier bits (`arg3 & 0xff == 0x40`) and
  records whether the caller targeted itself or another process. Self-RWX
  scores 5 (JIT warm-up); cross-process RWX scores 8.
- `injection_chain` requires a cross-process RWX row (`"self": 0`), so a
  process warming up its own JIT pages can never satisfy the first step.
- `inject-remote-thread` compares only the low 32 bits of the target handle,
  avoiding an untyped 64-bit literal; `inject-apc` covers the
  `NtQueueApcThread` family, including `NtQueueApcThreadEx2`.
- Positive controls on WS1 and WS2: local RWX produced `self=1` score 5;
  `VirtualProtectEx` on a scratch notepad produced `self=0` score 8;
  `CreateRemoteThread` produced a remote-thread row; `QueueUserAPC`
  produced an `NtQueueApcThreadEx2` row. All three scripts compile and pass
  `trace selftest` on both hosts.
- 488 passed / 21 skipped.

## 1.9.3 — 2026-11-14

Kernel-boundary process-injection evidence (T1055).

- New reviewed DTrace scripts: `inject-rwx` (`NtProtectVirtualMemory` with
  PAGE_EXECUTE_READWRITE) and `inject-remote-thread` (`NtCreateThreadEx`
  into another process). Both use the stable syscall provider and compile
  plus pass `trace selftest` on WS1 and WS2; firing was positively
  controlled in 1.9.4.
- `injection_chain` (score 9, 120 s) binds both halves to the same image,
  so ordinary system thread creation cannot collide with a JIT RWX page.
- DTrace remains on-demand and is excluded from always-on coverage:
  91.7 / 75.0 / 83.3, blind T1056, T1056.001, T1112.
- 484 passed / 21 skipped.

## 1.6.2 — 2026-11-13

- **DTrace readiness is capability-based** — the "2.0" package still calls
  itself 1.1.0 / Sun D 1.13.1, so `trace check`/`provision` no longer chase
  a version string; installed + enabled means ready.

## 1.6.1 — 2026-11-13

- **DTrace version probe** — `trace check` runs the resolved `dtrace.exe`.
- **Trace rows use `tid`** — `pid` is not portable across the DTrace builds
  on the estate; `tid` works on both hosts.

## 1.9.2 — 2026-11-14

- DTrace normalized descriptions pass through the credential redactor.
- 475 passed / 21 skipped.

## 1.9.1 — 2026-11-14

- Fix ACL hardening on existing installs: recursive inheritable ACEs left
  files with an empty effective DACL and blocked execution. Add explicit
  Full Control to existing children after the root inheritance change.
- 475 passed / 21 skipped.

## 1.9.0 — 2026-11-14

Secure-code review release.

- MCP tenant/scopes are server-authoritative; client `_meta` claims are
  ignored unless PLASMA_TRUST_CLIENT_META=1. Tenant-filtered reads, local
  health ownership, local-only isolate_host.
- Allow lists cannot bypass assist/supervised approvals. Malformed params
  and approval ids are refused; oversized JSON-RPC lines are bounded.
- DTrace MSI requires a valid Microsoft Authenticode signature.
- Webhook URLs must be HTTPS; Telegram tokens redacted from errors.
- Plasma root ACL restricted to SYSTEM/Administrators at install.
- WinRM fleet transport requires HTTPS unless explicitly opted out.
- Isolation adds outbound management allows; loopback/broadcast block
  targets refused; current user protected; gene domains escaped.
- 474 passed / 21 skipped.

## 1.8.7 — 2026-11-14

- Suppress PowerShell's `__PSScriptPolicyTest_*.ps1` scratch-file deletes
  in whids and exclude their identical hashes from fleet shared_hash.
- 454 passed / 21 skipped.

## 1.8.6 — 2026-11-14

- fleet WinRM pull reads a bounded tail instead of the whole store; large
  stores no longer exceed the WinRM envelope (HTTP 400).
- 452 passed / 21 skipped.

## 1.8.5 — 2026-11-14

- whids.pull updates watch-alerts-state so a pull is not immediately
  reported as an unpulled backlog.
- Legacy inverted storm summaries are normalised for coverage.
- 452 passed / 21 skipped.

## 1.8.4 — 2026-11-14

- Storm groups are sorted by timestamp before sampling/summary; rotated
  logs are scanned by path, so the window could otherwise be inverted.
- 451 passed / 21 skipped.

## 1.8.3 — 2026-11-14

- whids.pull coalesces repeated identical alerts into samples + a storm
  summary (count, first/last, max score). Re-pulling is idempotent.
- watch collapses identical high-criticality findings with an occurrence
  count, so one loop cannot consume the ten-item budget.
- 450 passed / 21 skipped.

## 1.8.2 — 2026-11-14

- Service-registry suppression now covers Windows service binaries under
  ADFS and Microsoft.NET as well as System32/SysWOW64. Temp/Tasks/Debug are
  excluded; reg.exe/sc.exe/powershell.exe keep full severity.
- 448 passed / 21 skipped.

## 1.8.1 — 2026-11-14

Follow-up from the live 1.8.0 estate run.

- Service-registry alerts from Windows' own service binaries (dns.exe,
  lsass.exe, DFSRs.exe, AD WebServices) are suppressed by System32 path
  evidence; reg.exe/sc.exe/powershell.exe keep full severity.
- Fleet no longer treats shared cmd.exe/powershell.exe hashes as cross-host
  indicators; user-path hashes still produce shared_hash.
- watch initializes new alert files at end-of-file (no history flood) and
  ignores .gz/.old-* logs in counts.
- Run-key suppression no longer covers Microsoft-signed LOLBins.
- 447 passed / 21 skipped.

## 1.8.0 — 2026-11-14

Production-hardening release from a full Windows-estate re-test.

- WHIDS startup hang root-caused: 145k dump files / 2.3 GB inside the
  install directory made the startup ACL reset exceed the SCM timeout.
  Dump hooks are off in detect-only mode; `plasma whids prune` and the
  watchdog move oversized/legacy trees out of the install path.
- watch: a single criticality-8+ WHIDS alert is surfaced immediately;
  per-file offsets handle append, truncation and rotation.
- fleet: lateral movement requires network auth logons and reports a
  source-address link; shared domains/IPs require at least one scored row.
- chain: brute-force success must belong to the same user as the burst.
- actuate: kill switch enforced on CLI/playbook applies; rotate_credential
  passwords redacted from the journal; quarantine hash-pinned with protected
  paths; WMI undo by name; isolation fail-closed; journal lock/fsync/id-safety.
- MCP: rate limit counts actions, not reads; approvals are tenant-scoped.
- identity/deep/health/store edge cases fixed.
- 440 passed / 21 skipped.

## 1.7.2 — 2026-11-13

- **Explicit state machines** — update phases, single-use plans and
  approvals, undo gates, exclusive tenant ownership, atomic bin/manifest
  writes. See [State machines](state-machines.md).

## 1.7.1 — 2026-11-13

- **Ring gate wired** — `update apply --ring` refuses a host outside the
  ring before downloading.

## 1.7.0 — 2026-11-13

- **Agent-native trust layer** — typed capability contract, deterministic
  policy engine (assist/supervised/autonomous), approval queue, hash-chained
  provenance, kill switch, tenants and an MCP server.
- **Evidence and assurance** — CBN/NDPA/PCI/ISO control matrices, SBOM,
  safety case, support bundle and a safety eval suite.
- **Rings and rollback** — canary/broad assignment and one-command rollback.

## 1.6.0 — 2026-11-13

- **WHIDS watchdog** — `plasma whids ensure` heals a hung StartPending or a
  stopped sensor; the installer registers `PlasmaWhidsWatchdog` (SYSTEM,
  every 2 minutes).
- **DTrace 2.0 provisioning** — `trace provision` downloads the official
  MSI when winget is absent and upgrades 1.x in place; scripts emit
  `pid` + `tid`.

## 1.5.10 — 2026-11-13

- **Gene alerts keep their technique** — WHIDS 1.7 omits the ATTACK block,
  so `normalize_alert()` maps the rule name to its technique. FileDelete
  drills now land as `T1070.004` in the store.

## 1.5.9 — 2026-11-13

- **Coverage resolves the bundled sensors** — `plasma coverage` works on
  installed nodes, not just in a repo checkout.

## 1.5.8 — 2026-11-13

- **D scripts run on Windows DTrace** — `/* */` comments, a terminated
  predicate, `tid` instead of the unreadable `pid`, and no tracer
  self-noise. Verified live on WS1.

## 1.5.7 — 2026-11-13

- **DTrace enabled state parsed correctly** — `bcdedit` prints
  `dtrace Yes`; `trace check` now recognises it instead of advising another
  `trace provision`.

## 1.5.6 — 2026-11-13

- **Config file lookup matches the bundle layout** — `sensors/whids.toml`
  is now found one level above the WHIDS payload, so upgrades rewrite a
  stale `config.toml` as well as the rules.

## 1.5.5 — 2026-11-13

- **Baseline rules actually reach the engine** — rule lookup accepts both
  `sensors/whids/` and `sensors/`; stale `*.bak.gen` files count as drift
  and are cleaned on install.

## 1.5.4 — 2026-11-13

- **Sysmon config convergence** — `install --force` re-applies the baseline
  Sysmon config (hot reload), so old nodes gain FileDelete and the other
  telemetry added since v1.3.

## 1.5.3 — 2026-11-13

- **DTrace payload actually ships** — the frozen bundle now carries
  `sensors/dtrace/*.d`; installed nodes can `trace list|selftest|run`.
- **DTrace outside PATH** — `trace check` finds
  `%ProgramFiles%\DTrace\dtrace.exe` (the MSI does not touch PATH).
- Installer convergence fix from 1.5.2: existing WHIDS installs are
  re-staged from the bundle; stale configs no longer survive upgrades.

## 1.5.2 — 2026-11-13

- **WHIDS convergence** — `install --force` rewrites `config.toml`, rules
  and the binary from the bundle, restarts only on drift, and rolls back the
  config once if the new one cannot start.

## 1.5.0 — 2026-11-13

- **DTrace integration** — `plasma trace list|check|selftest|run|provision`:
  reviewed D scripts (syscall errors, process creation, ETW kernel-process),
  bounded runs (window + row cap), normalized `kind: "trace"` rows in the
  same store. Explicit provisioning (Microsoft.DTrace via winget +
  `bcdedit /set dtrace on`) — never installed silently.
- Docs: new DTrace page; detection/troubleshooting updated.

## 1.4.0 — 2026-11-13

- **WHIDS init-hang handling** — explicit channel list, supervised start
  with bounded wait, force-stop + degraded recording, `plasma whids diagnose`.
- **Canary files** — `canary deploy|verify|status`; watch verifies decoys and
  reports score-10 impact findings. Coverage now attributes T1486 to
  `canary:verify`.
- **MSI + GPO packaging** — release adds `plasma-<version>-windows-x64.msi`;
  silent install, `PLASMA_ROOT` property, GPO instructions, upgrade in place.
- Coverage: 91.7% rollup / 75.0% exact / 83.3% weighted; blind spots are
  T1056, T1056.001 and T1112.

## 1.3.0 — 2026-11-13

- **ATT&CK parent rollup** — coverage now reports both the exact count
  (72.2%) and the rollup count (88.9%).
- **Fidelity-aware coverage** — every tap and gene rule carries a fidelity
  (high/medium/low); `weighted_pct` (80.6%) discounts weak rules.
- **Five new gene rules** — File Delete by LOLBin (T1070.004), Run Key
  Persistence (T1547.001), Service Registry Persistence (T1543.003),
  Privileged Group Add (T1098), Execution From User Paths (T1204.002).
- **Sysmon baseline** — bounded FileDelete include filter so the deletion
  rule has real telemetry; existing nodes apply it with `Sysmon64.exe -c`.
- Remaining blind spots are explicit: T1056/T1056.001, T1112, T1486.

## 1.2.0 — 2026-11-12

- **Pinned-signer update verification** — `update apply` refuses any binary
  whose Authenticode signer is not in the pinned set; override via
  `PLASMA_SIGNER_THUMBPRINTS`.
- **Anonymous updates** — public repository, no token required.
- **Release signing in CI** — signtool + DigiCert timestamp before hashing,
  when the signing secrets exist.
- **SignPath Foundation application** prepared (`docs/SIGNPATH_APPLICATION.md`).
- **Reproducible engine fetch** — pinned upstream revision
  (`tools/fetch_engine.py`) after the engine bundles disappeared upstream.

## 1.1.0 — 2026-11-05

- **Chain detection** — phish spawn, brute-force success,
  persistence-after-privilege; runs inside `watch`.
- **ATT&CK coverage** — `plasma coverage` (58.3% of the curated core, blind
  spots named).
- **Deep persistence probe** — every auto-start location + signature status.
- **Store hygiene** — `store rotate|compact|stats`.
- **Playbooks** — `contain-user`, `isolate-box` (one plan gates the sequence).
- **New actions** — `disable_task`, `remove_run_key`.
- **Watch throttling**, `sensor_heartbeat`, `rdp_hardening_drift`.

## 1.0.0 — 2026-10-19

First stable release after a full audit: 24 defects fixed (dead detection
rule, WHIDS confidence-scale bug that could wipe the IOC file, UTC
timestamp corruption, update downgrade bug, plan-gated actuate, journal
robustness, and more). 202 tests at release.

## 0.11.x

Auto-update, alerting, health/watch, deeper detection rules.

## 0.10.x

Intelligent installer (FULL/MINIMAL decision, Sysmon auto-download, repair
semantics), BOM-tolerant config reads.

## 0.9.x

Identity plane (Event Log API) and fleet correlation scoring.

## 0.8.x

`plasma fleet`: desk-side cross-host pull/correlate/report.

## 0.7.0

krabsetw ETW tap (`plasma-tap.exe`), manifest-verified rules, matches-only.
