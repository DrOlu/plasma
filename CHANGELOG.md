# Changelog

## 1.27.7 — 2026-11-22

- **TTPForge-driven coverage.** Four new baseline rules close the gaps the ForgeArmory run exposed: masqueraded system binaries (T1036.005), PowerShell download via 4104 (`WebClient`/`DownloadFile`/`Invoke-WebRequest`, T1105), WMI reconnaissance via 4104 (`Get-WmiObject`/`Get-CimInstance` over Win32_ classes, T1047/T1082) and `wmic` query reconnaissance (T1047/T1082). Rule count 21 → 25.
- **Query self-match fixed.** `plasma query --contains X` no longer returns the query process's own command line; the current PID is excluded when the image name matches and the row is under five minutes old.
- **Docs corrected** to the real baseline count.
- 995 tests collected; full suite, ruff and bandit (0 medium/high) pass.

## 1.27.6 — 2026-11-22

- **Defender and ngen parents damped.** A final estate pass showed `mpcmdrun.exe` (Defender) and `ngentask.exe` scoring at the top for genuinely rare but routine shapes. They join the benign service-parent set.
- 990 tests collected; full suite, ruff and bandit (0 medium/high) pass.

## 1.27.5 — 2026-11-22

- **Estate scoring ignores incomplete pairs.** An authentication row has a user but no image; the estate component built `user>` and scored it as first-seen, so 4624 rows topped the ranking at 10.0. Estate components now require a complete image edge or identity pair.
- 989 tests collected; full suite, ruff and bandit (0 medium/high) pass.

## 1.27.4 — 2026-11-22

- **Staged installer recognised.** The second estate pass showed the release downloaded as `plasma-1.27.3.exe` in Temp still topping WS2's ranking. The self-filter now also matches `plasma-<semver>[-suffix].exe`, while look-alike payload names remain scorable.
- 988 tests collected; full suite, ruff and bandit (0 medium/high) pass.

## 1.27.3 — 2026-11-22

- **Self-detection tightened.** Only the shipped `plasma.exe`, `plasma-<version>-windows-x64.exe` and the updater are treated as Plasma's own; a payload called `plasma-anything.exe` is scored like any other image. Children of Plasma's process tree are damped like other service parents.
- Second estate pass also confirmed that the injection markers must not be named `plasma-*` to be visible; that was a test-harness artefact, not a detector rule.
- 988 tests collected; full suite, ruff and bandit (0 medium/high) pass.

## 1.27.2 — 2026-11-22

- **Operational self-noise removed.** Rows and traces rooted in a `plasma*.exe` binary are skipped by default, so an upgrade cannot dominate its own anomaly ranking. `--include-self` restores them.
- **Critical band at 9.0.** With service parents damped, genuine first-seen binaries land at 9.1-9.7 again; the band now starts at 9.0 (high 7.5, medium 6.0).
- 986 tests collected; full suite, ruff and bandit (0 medium/high) pass.

## 1.27.1 — 2026-11-22

- **Estate calibration.** First-run scoring on WS1/WS2 ranked routine servicing (`devicecensus.exe`, `upfc.exe`, `usoclient.exe` and friends) as critical novelty. Children of a small signed service-parent set are now damped by 0.55, and the critical band starts at 9.5 instead of 9.0. Novelty from `svchost.exe` still surfaces, at triage level rather than red.
- No raw-data or profile-format change.
- 984 tests collected; full suite, ruff and bandit (0 medium/high) pass.

## 1.27.0 — 2026-11-22

- **Behavioural profiles.** `plasma profile build` reduces the bounded local store to counts — images, parent→child edges, identity pairs, destination/registry/file families, command-line shapes and robust hourly volume. Tens of kilobytes, no event rows, no raw command lines, SHA-256 integrity.
- **Explainable anomaly scores.** `plasma anomaly score|explain` fuse categorical rarity, first-seen keys, robust daily volume and optional estate rarity into a 0–10 score with per-component counts. Cold profiles return no score.
- **Causal traces.** `plasma anomaly trace` joins process spans by PID/PPID within one host, handles PID reuse, and scores traces by edge rarity. Traces never cross hosts.
- **Estate tier.** `plasma fleet profiles` builds each host's profile where the data lives and returns only the profile, then merges an estate baseline for cross-host rarity.
- **Credential-safe shapes.** `net user <name> <password>`, `--password=...` and similar values collapse to `<cred>` before counting.
- 982 tests collected; full suite, ruff and bandit (0 medium/high) pass.

## 1.26.6 — 2026-11-21

- **Two more chain false positives closed.** `persistence_after_privilege` matched any `schtasks` invocation, so a cleanup `schtasks /delete` completed the chain; it now requires `/create`. It also matched Plasma's own scheduled-task registration; events whose parent is a `plasma*.exe` binary are excluded from that step. Both have regression cases.
- 957 tests collected; full suite and `-W error` pass.

## 1.26.5 — 2026-11-21

- **Chain false positive fixed.** `persistence_after_privilege` matched the bare substring `sched`, so a read-only `Get-ScheduledTask` query completed the chain after an unrelated account change and scored 9 — the automatic-containment band. The step now requires `schtasks`, and a regression case pins the miss.
- 957 tests collected; full suite and `-W error` pass.

## 1.26.4 — 2026-11-21

- **Estate-caught fix.** `Plasma Sensitive File Delete`, `Plasma Hidden File Attribute` and `Plasma Registry Evasion` were first cut at criticality 4-5. WHIDS loaded them (281 genes) and then silently dropped every alert, because `sensors/whids.toml` forwards only criticality > 5. All three now sit at 6.
- `plasma detect validate` warns when a gene's criticality is at or below the WHIDS forwarding threshold, so a rule that can never reach the alert log is visible before deployment.
- Added regression tests for the threshold and the rule set; 957 tests collected.

## 1.26.3 — 2026-11-21

- `Plasma Encoded Cmd` now matches `powershell -e <base64>` as well as `-enc`, `-ec` and `-encodedcommand`, with a base64-length guard.
- Added `Plasma Sensitive File Delete` (T1070.004), `Plasma Hidden File Attribute` (T1564.001) and `Plasma Registry Evasion` (T1112/T1564.001). Their criticality was raised to 6 in 1.26.4 after estate testing showed WHIDS drops anything at or below its forwarding threshold of 5.
- Suppressed PowerShell `__PSScriptPolicyTest` temp artifacts at info/0.2; they were triggering public-folder and SharePoint Sigma rules on both estate hosts.
- Extended `persistence_after_privilege` to recognise `sc.exe create` and `reg add ...\Run`, with sequenced regression cases.
- Added a six-case Atomic Red Team smoke suite: `sensors/atomic-smoke.json`, `tests/test_atomic_fixes.py`, `docs/atomic-smoke.md`.
- 955 tests collected; full suite and `-W error` pass.

## 1.26.2 — 2026-11-21

- `PlasmaWatch`, `PlasmaWhidsWatchdog` and `PlasmaCanaryShield` now register both an `AtStartup` trigger and `StartWhenAvailable`, so enforcement resumes immediately after a reboot or a missed timer run.
- Added restart-on-failure, `MultipleInstances IgnoreNew` and execution time limits to the scheduled tasks; a hung sweep can no longer wedge the schedule.
- `PlasmaUpdate` remains a daily maintenance-window task; it gains overlap protection and a bounded runtime, not a boot trigger.
- `plasma health` now reports present Plasma tasks that lack an `AtStartup` trigger.
- 949 tests collected; full suite and `-W error` pass.

## 1.26.1 — 2026-11-21

- Fixed overlapping labels and link paths in the enterprise architecture SVG/PNG; regenerated the product and operations PDFs.
- No runtime behavior change from 1.26.0.
- 943 tests collected; full suite and `-W error` pass.

## 1.26.0 — 2026-11-21

- **Named-pipe canaries.** `canary pipe deploy|list|remove|serve|install|uninstall`
  creates decoy pipes and a SYSTEM listener. A client that connects is
  identified with `GetNamedPipeClientProcessId`, verified, and killed unless
  protected/trusted. Enumeration alone does not trigger.
- **Proper architecture diagram.** The enterprise AD page now uses a real SVG
  illustration instead of ASCII art, with a PNG companion for the PDF.
- **Enterprise guide expanded** with pipe-canary rollout, scanner caveats and
  disarm steps.
- **Shield hardening from estate drills:** scheduled-task argument quoting,
  fresh-root Sysmon backup, case-preserving Sysmon conditions, journal ids,
  DTD/entity refusal.
- 943 tests collected; full suite and `-W error` pass.

## 1.25.0 — 2026-11-21

- **Active canary shield.** New `plasma canary shield` previews/installs a
  narrow Sysmon FileCreate/FileDelete/RegistryEvent include and a
  one-minute SYSTEM task. When a process creates, deletes or registry-writes
  a canary, the sweep verifies the live PID/image, refuses protected/trusted
  processes and kills the process.
- **Registry canaries.** `canary registry deploy|list|remove` adds decoy
  keys under `Software\PlasmaDecoy` in HKCU or HKLM.
- **False-positive boundary.** Reads do not trigger; Explorer, Plasma,
  Defender, backup and system processes are skipped; protected processes are
  refused. A pure in-place overwrite is still caught by `canary verify` as a
  hash change, without process attribution.
- **Enterprise AD deployment guide.** Detailed installation, configuration,
  GPO/SCCM/Intune rollout, fleet, canary shield, SIEM, operations, rollback
  and troubleshooting for a domain network.
- 933 tests collected; full suite and `-W error` pass.

## 1.24.1 — 2026-11-20

- **ACL intercept refuses without a canary.** `plasma intercept apply` on an
  ACL rule with no matching canary paths now returns a structured JSON
  refusal (`code: REFUSED`) instead of a Python traceback.
- **Invalid summary duration is structured.** `plasma summarize --since
  yesterday` now returns a JSON query error instead of a traceback.
- 921 tests collected; full suite and `-W error` pass; bandit 0 high/medium;
  pip-audit 0 known vulnerabilities.

## 1.24.0 — 2026-11-20

- **Opt-in Defender enforcement.** New `prevent cfa`, `prevent network` and
  `prevent driver-blocklist` controls: preview, plan-gated apply, positive
  verification and rollback by journal id. WDAC remains read-only.
- **Rollback proves the restored value.** CFA/Network Protection and the
  driver-blocklist rollback compare the resulting value with the captured
  previous value, not just the PowerShell exit code.
- **Actionable posture.** `prevent posture` now says which controls Plasma
  can apply, gives the preview command and emits a recommendation per gap.
- **Detection regression suite.** `plasma detect test` runs deterministic
  positive and negative chain cases; a broken expectation exits 2.
- **Security hardening.** All outbound downloads are HTTPS-only with no
  embedded credentials; Sysmon XML refuses DTD/entity input; query regex and
  detection case files are bounded; MCP `get_case` no longer writes.
- **Agent surface.** MCP adds `get_enforcement_posture` (20 tools total).
- 919 tests collected; full suite and `-W error` pass.

## 1.23.0 — 2026-11-20

- **Typed investigation.** `plasma query` adds a closed local query language
  with exact, glob, time, score and aggregate filters. Unknown fields are
  refused. `plasma tree` builds lineage only from explicit `pid`/`ppid`
  edges, and `plasma summarize` reduces a bounded tail to a compact digest.
- **Case workspace.** `plasma case` collects selected events and findings,
  records notes, renders a timeline and Markdown report, and seals every
  artifact with a SHA-256 manifest. `case verify` detects changes.
- **Triggered memory triage.** `plasma memory triage` scans only PIDs
  selected by injection- or credential-shaped alerts, deduplicated across
  runs.
- **Identity coverage.** 4720/4722/4724/4728/4732/4756/4648/4672-class
  account, group and privilege events normalize into the event contract.
  4662/4672 are supported but excluded from the default high-volume pull.
  4688 now retains parent PID for lineage.
- **Detection harness.** `plasma detect validate|diff|replay` compiles rule
  regexes, compares rule sets by name and hash, and replays chains over a
  captured store.
- **Tamper and blind-spot accounting.** `health` verifies canary integrity,
  names blind spots, and includes them in the verdict. `prevent posture`
  reads WDAC, Controlled Folder Access, Network Protection and the
  vulnerable driver blocklist without changing them.
- **Agent surface.** MCP adds `query_events`, `get_process_tree`,
  `get_summary`, `get_coverage`, `get_blind_spots`, `get_case`,
  `scan_memory` and `simulate_policy`. `control policy simulate` explains a
  decision without creating an action, approval or ledger row.
- 900 tests collected; full suite passes.

## 1.22.0 — 2026-11-20

- **Memory scanning.** New `plasma memory scan` binds HollowsHunter/PE-sieve
  as a pinned, on-demand probe for hollowing, implanted PEs, shellcode,
  code patches and IAT hooks. Reports are archived under `<root>/memory/`;
  findings become `source="memory"` alerts.
- **No dumps by default.** `--dump` is explicit and refused with `--all`;
  the scanner is SHA-256 verified before execution.
- **JIT noise control.** Managed .NET shellcode false positives are
  suppressed from the alert stream and reported as a count.
- **Bundled and bounded.** 64-bit and 32-bit scanners are fetched into the
  Windows payload; targeted PID/name scans are the default, `--all` is
  explicit.
- Estate-tested on WS1 with a real `powershell.exe` scan (3.4s deep scan;
  managed JIT suppressed). 846 tests collected; full suite and `-W error`
  pass.

## 1.21.0 — 2026-11-19

- **Intercept phases 0-3.** New `plasma intercept` surface: shadow rule
  evaluation over the event store, NTFS deny/audit protection for canary
  files, a synchronous MCP tool-call gateway, and a native policy broker
  for ACL and firewall rules.
- **Plan-gated and reversible.** Every intercept apply is dry-run first,
  payload-bound, journaled with an undo recipe, verified, and reversible.
- **No kernel driver.** The broker uses gates Windows already owns: NTFS
  ACLs, Windows Firewall, and the MCP boundary.
- **Estate-verified on WS1 and WS2:** shadow matches, canary write denial,
  ACL rollback, firewall rule apply/rollback, and an MCP `INTERCEPTED`
  response.
- 833 tests collected; full suite and `-W error` pass.

## 1.20.1 — 2026-11-19

- **Root help names the token model.** `plasma --help` now says canary files
  and native DNS/HTTP tokens are normalized into the event store, matching
  the command help and the 1.20.0 feature set.
- No behavior change; this is a documentation/help patch on top of 1.20.0.

## 1.20.0 — 2026-11-19

- **Believable file canaries.** Random subdirectories and document names by
  default, valid xlsx/docx/pdf/csv bodies, and no self-identifying marker in
  the file. `--no-randomize` preserves a pinned layout.
- **DNS tokens.** `canary token create --kind dns` allocates a unique
  hostname; `canary sysmon --apply` writes a narrow Sysmon EID 22 include
  and hot-reloads it. Matches become score-8 `canary_dns_tripped` findings.
- **HTTP tokens.** `canary token create --kind http` writes a plausible
  Windows `.url` shortcut; `canary serve` is a loopback-first local
  collector that refuses non-loopback binds without an explicit flag.
- **One evidence path.** DNS/HTTP hits are appended as `source="canary"`
  alert rows, deduplicated across sweeps; `watch` surfaces them, `fleet`
  adds `canary_token_hit` (score 9), and enforcement maps them to
  approval-gated isolation.
- **Canary accounts are in the sweep.** `config.json` `canary.accounts` (or
  `watch --canary-account`) queries 4624/4625/4771/4776; repeated logons are
  deduplicated.
- **Offset fix.** Short append-only logs no longer look replaced when they
  grow, so the first hit is not re-ingested on every sweep.
- Field-tested on WS1 and WS2: file deploy/verify/tamper, real Sysmon EID 22
  query, HTTP collector hit, watch findings, and a real 4625 on a disabled
  canary account. 823 tests collected; full suite and `-W error` pass;
  `ruff check` clean on the changed modules.

## 1.19.3 — 2026-11-18

MSI upgrades now converge the running node.

- **`install --rotate`.** The MSI custom action passes `--rotate`, so after
  staging the new version the installer swaps `bin\plasma.exe` and restarts
  the registered tasks. Previously the package copied a versioned sibling
  and updated `config.json`, but the running node kept executing the old
  canonical binary — an MSI upgrade from 1.19.1 to 1.19.2 left `/healthz`
  reporting 1.19.1.
- **Rotation is all-or-nothing.** A failed canonical swap returns exit 4
  with the rotation detail instead of reporting a successful install.
- Verified on WS2: silent MSI install exits 0, `bin\plasma.exe --version`
  and `/healthz` both report 1.19.3.
- 788 tests collected; full suite and `-W error` pass; `ruff check` clean.

## 1.19.2 — 2026-11-18

Enterprise MSI packaging.

- **The MSI is now Authenticode-signed** in the release workflow, using the
  same PFX and timestamp as the exe. `SHA256SUMS` covers the signed MSI.
- **The MSI is built with `-arch x64`**, so it installs under
  `C:\Program Files\Plasma` instead of `Program Files (x86)`.
- Verified on WS2: `msiexec /i ... /qn` exits 0, the installed exe reports
  1.19.2, and `/healthz` reports 1.19.2.
- 786 tests collected; full suite and `-W error` pass; `ruff check` clean.

## 1.19.1 — 2026-11-18

Holistic security and correctness review.

### HTTP API

- **Canonical command path from the parsed namespace.** The read-only,
  long-running and mutating gates no longer trust a text scan of argv.
  A leading `--` is rejected, and `manifest --dir D create` is correctly
  classified as a write.
- **Read-only coverage completed.** `update auto` (without
  `--check-only`), `protect arm/disarm`, `sigma convert` (without
  `--dry-run`) and `deep persistence --json-out` are now mutations.
- **Default key is loopback-only.** The default bind is `127.0.0.1`; a
  non-loopback bind refuses the known `plasmaplasma` key unless
  `--allow-insecure-default-key` is explicit.
- **TLS handshake moved to the connection thread.** A client that connects
  and sends nothing can no longer freeze the accept loop.
- **Request-smuggling defenses.** Responses close the connection, and
  duplicate `Content-Length` or any `Transfer-Encoding` is rejected.
- **Output is read incrementally** under `--max-output`; a runaway command
  can no longer exhaust memory before truncation.
- **Audit redaction covers `--prompt=VALUE` and abbreviations.** Mutating
  calls that cannot write an audit row now refuse to run.
- **`PLASMA_ROOT` is propagated to child commands**, so the API and the
  commands it runs agree on the state root.
- **OpenAPI** now documents `408`/`411`, and the root command row carries
  `mutating`/`long_running`.

### Response and prevention

- **Kill switch covers undo and prevention.** `actuate undo`, playbook undo,
  every prevention apply and prevention rollback now refuse while engaged,
  with a re-check under the plan lock.
- **Approval queue cannot bypass policy.** Ineligible findings are `denied`,
  not queued. Approval re-checks enabled/mode, score, deny/allow techniques
  and cooldown, and is atomically claimed before execution.
- **Protected paths are canonicalized.** Trailing dots/spaces, 8.3 names,
  reparse points and final-path aliases are refused.
- **Protected processes/tasks/accounts expanded.** System, Defender,
  svchost, Plasma tasks and Microsoft tasks are protected; built-in account
  SIDs and the last-enabled-admin check are enforced on Windows.
- **Plans are identity- and time-bound.** PID plans bind creation time and
  image name; plans expire after 60 minutes.
- **Evidence capture gates automatic kills.** If the snapshot fails, a kill
  becomes a human approval instead of destroying memory evidence.
- **`remove_admin`/`disable_user`/`stop_service`/`disable_task` are
  no-op-aware**, and no-op actions no longer get an undo that would change
  unrelated state.
- **Prevention plans are claimed atomically; rollback is plan-gated.**
  AppLocker rollback refuses to clear all rules without a backup, ASR
  rollback validates and quotes every recipe, and LSA captures the prior
  value.
- **Credential rotation uses a CSPRNG.**

### Collection and data

- **Tap events redact script blocks and command lines.**
- **Identity collector reports failure instead of “0 events”.**
- **WHIDS and watch skip malformed rows** without aborting the pull/sweep;
  watch offsets still advance.
- **WHIDS dedupe includes content**, so distinct registry/file/network
  writes in the same second survive.
- **Trace scripts reject comment-hidden `system()` and `copyout`, and no
  longer load from the current directory.** MSI downloads use unique files
  and a re-hash; provisioning fails when `bcdedit` fails.
- **Deep persistence extracts the executable from command-line paths.**
- **Store rewrite/compact are BOM-safe and refuse to follow a planted
  output path.** Append collectors repair a torn final line.
- **Canary paths are absolute and symlink-aware.**
- **Fleet inventory rejects string booleans and inline secrets; WinRM pull
  fails on remote error instead of reporting an empty host.**
- **Health survives unreadable config; coverage survives malformed
  criticality; Sigma `|re` rejects quote/newline injection; notify refuses
  redirects and non-HTTPS webhooks; FIM has a hard size bound; observatory
  redacts command lines and validates canary names.**

### Install and update

- **`install --dry-run` no longer creates the root, rewrites ACLs, downloads
  Sysmon or starts services.** Self-update preserves operator
  `events_path`, retention and response settings.
- **Sysmon is Authenticode-verified as Microsoft-signed before execution.**
- **Update signature status must be valid**; `HashMismatch` is refused even
  with the pinned certificate.
- **Ring logic fixed:** broad means “unassigned hosts”, `promote` affects
  the default, and the canary hold uses the effective ring. Unknown
  `published_at` fails closed for broad.
- **Canonical rotation failure fails the update** and restores the running
  binary. Rollback picks the newest usable backup and never leaves the host
  without `plasma.exe`.
- **Manual apply shares the self-update lock.** String booleans are parsed
  safely; task state is locale-independent; pre-release tags order correctly.
- **Install staging is a sibling swap**, so a failed copy does not leave a
  partial version and `--force` does not keep stale files.
- **`packaging/install.ps1` works on Windows PowerShell 5.1**, and junction
  paths are quote-escaped.
- **Update failures emit JSON** and use the documented exit codes.

### Agent trust

- **Policy types are validated** (string deny becomes a list, malformed
  approval maps fall back safe, malformed rate limits default to 30).
- **Tenant lookup is case-insensitive and fails closed on a corrupt
  registry**, with locked read-modify-write.
- **Ledger head checkpoint detects suffix truncation**; denied approvals are
  terminal; approvals are atomic and single-use.
- **MCP only honors client `_meta.host` when explicitly trusted**, and an
  ordinary call cannot burn another tenant's approval.

785 tests collected; full suite and `-W error` pass; `ruff check` clean.

## 1.19.0 — 2026-11-18

Agent-oriented help for every command.

- **Every command has a detailed help page.** `plasma <command> --help`
  now includes a full description, working examples, notes, a safety
  classification, output contract and related commands, not just flags.
  `-h` works everywhere.
- **`plasma help` is the discovery command.** No topic prints a grouped
  command map, the dry-run → plan → apply workflow and exit codes. A topic
  prints the same detailed page (`plasma help control approvals approve`).
- **`plasma help --json` is the machine catalog.** Schema
  `plasma.help/1` returns every command path, summary, description, usage,
  arguments (required/default/choices), examples, safety, output and
  see-also. One topic narrows it to one command.
- **The HTTP API carries the same metadata.** `GET /v1/commands` rows now
  include summary, description, examples, safety and see-also;
  `POST /v1/exec {"argv":["help","--json"]}` returns the full catalog.
- **Registry completeness is tested.** A test walks the real argparse tree
  and fails if a command is added without a help entry; another asserts
  every entry has examples.
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
  compared against the configured default (`broad`) and skipped by
  `PlasmaUpdate`. `update auto` now derives the ring from the host's
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

- **Rotation now quiesces the tasks that hold the binary.** `PlasmaServe`,
  `PlasmaWatch`, `PlasmaWhidsWatchdog` and `PlasmaIdentityPull` are stopped
  before the rename and restarted afterwards, so an in-use image cannot
  turn a valid update into `WinError 5`. `PlasmaUpdate` is never stopped —
  it is the process doing the update — and a serve-launched update skips
  `PlasmaServe` so it cannot kill its own process tree.
- **Retries and stale-backup recovery.** A locked image is retried five
  times. A leftover `.old` backup that cannot be replaced is preserved
  under a unique name instead of failing the swap, a read-only attribute is
  cleared before the rename, and a failed second rename restores the
  previous binary so the host is never left without a launchable exe.
- **`PlasmaServe` now restarts after an update**, so `/healthz` reports the
  new version rather than the pre-update process.
- 737 tests collected; full suite passes; ruff error-level checks clean.

## 1.18.1 — 2026-11-18

Self-update install robustness.

- **A locked staged exe no longer aborts the install.** `cmd_install`
  copied `sys.executable` over `bin\<same name>` unconditionally; during
  an update the staged exe (or a stale copy of it) could be locked, and
  the whole install failed before the updater's authoritative rotation.
  The copy is now skipped when the bytes already match and tolerated when
  the destination is locked.
- 731 tests collected; full suite passes; ruff clean.

## 1.18.0 — 2026-11-18

Measured self-update.

- **`plasma update auto`** checks the latest release and applies it through
  the existing download → SHA256 → Authenticode → install → rotate path.
  Signed releases only; `--allow-unsigned` remains a development escape.
- **The installer registers `PlasmaUpdate`**, a daily SYSTEM task with a
  random minute inside the 02:00–05:00 local maintenance window, so the
  fleet does not wake at the same moment. `--no-autoupdate` removes the
  task and disables the feature.
- **Ring-aware and canary-held.** `broad` hosts wait 24 hours after a
  release; `canary` hosts update immediately; `rollback` hosts never
  auto-update. No ring file means `broad` is the default.
- **Kill-switch aware.** An engaged kill switch pauses automatic updates.
  A cross-process lock allows one update at a time.
- **Previous binary kept.** `plasma rollback` still restores the prior
  binary. The canonical `plasma.exe` is rotated too, so the serve/watch
  tasks pick up the new build, and `PlasmaServe` is restarted after a
  successful update.
- **Journal and state.** `update-journal.jsonl` records every attempt;
  `update-state.json` records the last check, result and version. Optional
  notification uses the existing channels.
- Scheduled tasks now point at the stable `plasma.exe`, not the transient
  `plasma-update-staged.exe` used during an update.
- 731 tests collected; full suite passes; ruff clean.

## 1.17.1 — 2026-11-17

Critical process-guard fix.

- **Protected process names were not matched.** `_g_process` wrapped the
  `Get-CimInstance` assignment in parentheses, which makes PowerShell emit
  the whole CIM object as a formatted table. The guard compared that table
  text to `PROTECTED_PROCESSES`, so `kill_process` on **LSASS, CSRSS,
  SERVICES, WINLOGON, WHIDS and Sysmon** minted a dry-run plan instead of
  refusing. The assignment is now bare, the output is the process name,
  and the guard refuses as designed.
- A regression test asserts the guard payload does not emit the CIM
  object.
- 716 tests collected; full suite passes; ruff clean.

## 1.17.0 — 2026-11-17

Measured protection is armed by default.

- **Automatic containment is on, but narrow.** The default enforcement
  policy is `enabled: true`, `mode: "enforce"`, `min_score: 9`,
  `allowed_actions: ["snapshot", "kill_process"]`, a 2-action per-run cap
  and a 30-minute cooldown. The snapshot is written before the kill.
- **Everything else stays human-approved.** `isolate_host`,
  `quarantine_file`, `disable_user`, `remove_admin`, `stop_service`,
  `rotate_credential`, task/Run-key/WMI removal and `block_ip` are in
  `require_approval`.
- **A SYSTEM task drives the sweep.** The installer registers
  `PlasmaWatch`, which runs `watch once --enforce` every 5 minutes, so
  automatic containment is live out of the box. `--no-autoprotect` installs
  the old dry-run posture and removes the task.
- **Protected components stay protected in code.** WinRM, RDP, WHIDS,
  Sysmon, LSASS, BFE, MpsSvc, Administrator, SYSTEM and service accounts
  are refused by the response layer. Isolation keeps RDP/WinRM open.
  AppLocker keeps the Administrators path rule.
- **Upgrades migrate the old default.** Exactly the pre-1.17
  `enabled: false` block is replaced with the measured policy; a custom
  operator block is preserved.
- **New `plasma protect` control surface.** `status`, `arm`, `disarm` and
  `protected` make the posture inspectable and reversible.
- 715 tests collected; full suite passes; ruff clean.

## 1.16.3 — 2026-11-17

Command-tree type metadata.

- **Options and positionals carry their argparse type.** `/v1/commands` now
  reports `type` (`int`, `str`, or null) for every option and positional,
  so a generated client can render the right input control. The OpenAPI
  `Option` and `Positional` schemas require the field.
- 698 tests collected; full suite passes; ruff clean.

## 1.16.2 — 2026-11-17

Serve hardening, command-tree completeness and explicit lifecycles.

- **Serve concurrency and edge cases.** Argparse validation is serialized
  (it redirects process-global stdout/stderr); API keys are compared as
  bytes so non-ASCII keys work; a missing `Content-Length` returns 411;
  the handler has a socket timeout; broken pipes are ignored; child
  processes get `PYTHONIOENCODING=utf-8`, `stdin=DEVNULL`, and a
  process-tree kill on timeout.
- **Audit reliability and redaction.** Audit appends are serialized
  in-process and use a 30 s file-lock timeout; a failed write is logged.
  `--prompt` values and credential-shaped argv items are redacted before
  they reach the audit log.
- **Command tree completeness.** `/v1/commands` now returns a separate
  `root` object and 127 commands (the root is no longer counted as a
  command). Each command includes `positionals` (name, required, nargs,
  choices, help) as well as options. The OpenAPI `Command` and
  `CommandTree` schemas describe both.
- **Explicit lifecycles.** New `plasma/lifecycle.py` names the serve
  request, plan, approval, enforcement, prevention, WHIDS, FIM, canary,
  drift, identity-schedule, capture, fleet, kill-switch, tenant and ring
  machines, with pure classifiers. `actuate`, `ledger`, `enforce`,
  `prevent` and `whids` now use the classifiers instead of ad-hoc status
  comparisons.
- 698 tests collected; full suite passes; ruff clean.

## 1.16.1 — 2026-11-17

OpenAPI 3.1 for `plasma serve`.

- **`GET /openapi.json`** publishes an OpenAPI 3.1 document covering the
  four API routes, both auth schemes (`bearerAuth`, `apiKeyAuth`), the
  request/response envelopes and the error responses. No auth required.
- **`GET /docs`** serves a self-contained HTML reference that renders the
  spec; no CDN, no external dependency.
- **`plasma/openapi.py`** is the single source of truth; `info.version`
  tracks the package version, and a unit test asserts the spec paths and
  the server routes do not drift apart.
- `POST /v1/exec` remains generic by design; the full command surface is
  discoverable at `GET /v1/commands`.
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
  `PLASMA_SERVE_API_KEY` overrides it. Keys are compared in constant time
  and never written to the audit log.
- **Read-only mode.** `--read-only` refuses every command that changes host
  or Plasma state, including any `--apply`.
- **Bounded execution.** Each call runs in a child process with a hard
  timeout (default 300 s), a 1 MiB request cap and an 8 MiB output cap.
- **Audit.** Every call is appended to `<root>/serve/audit.jsonl` with the
  remote address, key id, argv, exit code and duration.
- **TLS.** `--tls-cert` and `--tls-key` wrap the listener in HTTPS.
- Default bind is `0.0.0.0:9999`; the server warns when the default key is
  used on a non-loopback address.
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
  Without it, every suppressed alert was a parse failure.
- **`dest_ip` accepts workstation names and IPv6 zone IDs.** 4776 NTLM
  events put the calling machine in `dest_ip`; IPv6 may carry `%zone`.
  The old IP-only pattern rejected both. A 10,000-event sample from each
  host now validates with zero failures.
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

Production hardening after a full Windows-estate re-test.

- **WHIDS hang root-caused**: 145k dump files / 2.3 GB inside the install
  directory made WHIDS' startup ACL reset exceed the SCM timeout. Detect-only
  config now ships with `en-hooks = false`; `plasma whids prune` and the
  watchdog move oversized/legacy trees out of the install path.
- **watch**: surfaces a single criticality-8+ alert immediately, using
  per-file offsets that handle append, truncation and rotation.
- **fleet**: lateral movement requires network logons and a same-user
  pattern; `linked` is true only with a source-address link to another host.
  Shared domains/IPs need at least one scored row.
- **chain**: brute-force success must belong to the same user as the burst.
- **actuate**: kill switch enforced on CLI/playbook applies; rotated
  credentials redacted from the journal; quarantine hash-pinned with
  protected paths; WMI undo restores bindings by name; isolation verifies
  management allows before blocking; journal is locked, fsynced, id-safe.
- **MCP**: rate limit counts actions, not reads; approvals are tenant-scoped.
- **collectors**: empty stores are degraded; deep persistence no longer
  flags unsigned Windows binaries; identity drops malformed domains and
  timestamps; store rotation failures are data.
- 440 passed / 21 skipped.

## 1.7.2 — 2026-11-13

### Fixed — implicit state machines

- **Update lifecycle** — persisted phases (`idle → staged → verified →
  installing → installed → rotated`, `failed`) with history; `update check`
  reports the phase; a new run resets a stale phase.
- **Plan reuse** — actuate and playbook plans are single-use; a second
  apply of the same plan is refused.
- **Undo gate** — actuate and playbook undo require a prior undo dry-run
  (or its `--plan`) and cannot be applied twice.
- **Approval race** — approval consumption is atomic under the ledger lock
  and writes an `approval_use` row; a reused approval returns
  `APPROVAL_INVALID`.
- **Tenant ownership** — a host belongs to at most one tenant; adding it
  to another tenant moves it.
- **Atomic bin rotation** — write-temp then rename, with recovery when a
  previous run died between renames.
- **Canary manifest** — atomic write and path dedupe.

### Tests
- 398 passed / 21 skipped.

## 1.7.1 — 2026-11-13

### Fixed — `update apply --ring` was documented but not wired
- The ring gate now runs before download: a host outside the requested
  ring is refused with exit 2 and a hint to assign it. This makes canary
  rollout a local fact rather than an agent suggestion.

### Tests
- 384 passed / 21 skipped.

## 1.7.0 — 2026-11-13

Agent-native trust layer: autonomy with a leash.

### New — capability contract
- Eleven typed tools with scopes, risk tiers, JSON schemas, preconditions
  and postconditions. Unknown tools and extra arguments are refused.
- Mutating tools are dry-run-only in the MCP surface; execution stays
  behind the CLI plan/approval gate.

### New — deterministic policy engine
- `assist` / `supervised` / `autonomous` tiers, deny/allow lists, scope
  checks, blast-radius and rate limits. The model never authorises.

### New — approvals and provenance
- `plasma control approvals` queue; approvals are single-use and bound to
  the tool and argument hash.
- Hash-chained ledger records harness, model, prompt digest, arguments,
  policy digest, approval and outcome. `plasma control audit verify`.

### New — kill switch and tenants
- Global and per-host kill switch; reads stay available.
- Tenant registry scopes hosts and tags ledger rows for MSSP isolation.

### New — MCP server
- `plasma mcp serve` exposes the typed tools over stdio (initialize,
  tools/list, tools/call) to any harness.

### New — evidence and assurance
- `plasma evidence export` for CBN, NDPA, PCI DSS and ISO 27001.
- CycloneDX SBOM, safety case and redacted support bundle.
- `plasma eval run` safety suite covering tiers, refusals, injection
  strings, blast radius and rate limits.

### New — deployment rings and rollback
- `plasma ring status|assign|promote`; `plasma rollback` restores the
  previous canonical binary.

### Tests
- 384 passed / 21 skipped.

## 1.6.2 — 2026-11-13

### Fixed — the "upgrade to 2.0" hint never went away
- Microsoft's download page labels the current package "2.0", but the MSI
  reports ProductVersion 1.1.0 and the tool reports `Sun D 1.13.1`.
  Version strings cannot distinguish new from old, so `trace check` kept
  telling an up-to-date host to provision and `provision` would reinstall
  forever. Readiness is now capability-based: installed + enabled is ready;
  only a missing or disabled install triggers action.

### Tests
- 350 passed / 21 skipped.

## 1.6.1 — 2026-11-13

Field follow-up from the DTrace 2.0 rollout.

### Fixed — `trace check` ran bare `dtrace -V`
- The MSI does not add DTrace to PATH, so the version probe returned empty
  on WS2 and the version read as unknown. It now runs the resolved path.

### Changed — scripts emit `tid` only
- The same DTrace package reads `pid` on WS2 but rejects it with "invalid
  user access" on WS1, so `pid` is not portable across the estate. The
  reviewed scripts emit `tid` (carried in the event description), which
  works on both hosts and keeps the event contract consistent.

### Tests
- 350 passed / 21 skipped.

## 1.6.0 — 2026-11-13

Self-healing WHIDS and DTrace 2.0 everywhere.

### New — WHIDS watchdog (permanent init-hang recovery)
- `plasma whids ensure`: Running is a no-op; a hung `StartPending` is
  force-stopped and restarted (Start-Service alone cannot recover it);
  a stopped service is started. Every action is appended to
  `logs/whids-watchdog.log`.
- The installer registers **PlasmaWhidsWatchdog**, a SYSTEM scheduled task
  that runs `whids ensure` every two minutes. SCM failure actions only
  cover crashes, not hangs.
- `whids diagnose` reports whether the task is present.

### New — DTrace 2.0 provisioning
- `trace provision` now downloads the official Microsoft DTrace 2.0 MSI
  directly when winget is absent (the default on Server 2022), and
  upgrades an older Sun D 1.13.1 preview in place.
- `trace check` flags a 1.x install and points at `provision`.
- The reviewed scripts emit both `pid` and `tid`; DTrace 2.0 can read
  `pid` in probe context (the 1.x preview could not).

### Tests
- 349 passed / 21 skipped.

## 1.5.10 — 2026-11-13

Tenth field fix: gene alerts lost their ATT&CK technique on the way in.

### Fixed — WHIDS 1.7 alerts carry no ATTACK block
- `GeneInfo` contains only `Criticality` and `Signature`; the rule's Tags
  (and its technique) are not propagated. Every gene alert therefore
  landed in the store with `technique: null`, so coverage, chains and
  fleet could not see it. `normalize_alert()` now falls back to a
  rule-name → technique map built from the shipped baseline rules.
- Verified live on WS2: a FileDelete drill produced a Sysmon 23 event and
  a `Plasma File Delete by LOLBin` alert; after this fix the pulled row
  carries `T1070.004`.

### Tests
- 341 passed / 21 skipped.

## 1.5.9 — 2026-11-13

Ninth field fix: `plasma coverage` failed on every installed node.

### Fixed — coverage could not find the bundled sensor payload
- `coverage._repo_sensors()` only looked at repo-relative paths, so the
  frozen bundle's `<_MEIPASS>/embedded/sensors` was invisible and the
  command returned "plasma-tap-rules.json not found (repo or embedded)"
  (WS2, live). It now resolves the frozen bundle, an explicit sensors
  directory, and the repo.

### Tests
- 340 passed / 21 skipped.

## 1.5.8 — 2026-11-13

Eighth field fix: the D scripts did not actually run on Windows DTrace.

### Fixed — scripts rejected or silently empty on a live host
- `//` line comments are a syntax error for the Windows DTrace compiler
  ("syntax error near /"); metadata and prose now use `/* ... */`.
- `process-create.d` was missing the closing `/` on its predicate.
- `pid` raises "invalid user access in action" in probe context on this
  build (Sun D 1.13.1); the scripts emit `tid` instead, which is readable
  and is carried in the normalized event description.
- All three scripts exclude `dtrace.exe` itself, so the tracer no longer
  fills the store with its own syscalls.
- Verified live on WS1: 4 process-create, 236 syscall-error and 57
  ETW kernel-process rows in a 6-second window.

### Tests
- 339 passed / 21 skipped.

## 1.5.7 — 2026-11-13

Seventh field fix: DTrace looked disabled right after provisioning it.

### Fixed — `bcdedit` reports `dtrace Yes`, not `dtrace on`
- `trace check` only matched the literal "on", so a host with
  `bcdedit /set dtrace on` applied kept reporting `enabled: false` and
  advised running `trace provision` again. It now parses the actual
  `dtrace Yes` / `dtrace No` output.

### Tests
- 336 passed / 21 skipped.

## 1.5.6 — 2026-11-13

Sixth field fix: the config file shares the rule files' staging layout.

### Fixed — stale `config.toml` still survived (WS2 measured at 1512 bytes)
- `whids.toml` is staged at `sensors/`, not `sensors/whids/`, so the
  converged-install map had no `config.toml` entry to compare or copy. WS2
  kept its pre-1.4 config (`channels = ["all"]`) through the 1.5.5 upgrade
  while the rules correctly reached 16.
- Config lookup now accepts both layouts and writes the bundled file to
  both `whids.toml` and `config.toml`.

### Tests
- 334 passed / 21 skipped.

## 1.5.5 — 2026-11-13

Fifth field fix: the baseline rule file was staged a directory away from
where the installer looked.

### Fixed — `plasma-baseline.gen` still never reached the engine
- The builder stages shared rule files at `sensors/` and the WHIDS payload
  at `sensors/whids/`; `deploy_rules(".../sensors/whids", ...)` therefore
  found only `plasma-iocs.gen` (2 rules on WS1, 1 on WS2 — measured live).
- Rule lookup now accepts both `sensors/whids/` and `sensors/`, in both
  `whids.deploy_rules()` and the installer's convergence map.
- Obsolete `*.bak.gen` files count as drift, so a node that otherwise looks
  converged still gets a cleanup pass (WS1 kept loading a stale backup).

### Tests
- 333 passed / 21 skipped.

## 1.5.4 — 2026-11-13

Fourth field fix: Sysmon telemetry was frozen at install time.

### Fixed — Sysmon config was never refreshed on upgrade
- Sysmon applies the config it was installed with and keeps it. Detection
  content added since (FileDelete for T1070.004, registry run-key/service
  events, privileged-group and user-path execution) was therefore silent
  on nodes installed before v1.3.
- `install --force` (also what `update apply` runs) now re-applies
  `SYSMON_BASELINE_CONFIG` through `Sysmon64.exe -c` — a hot reload, no
  service bounce — and records `sensors.sysmon.config_applied` (or
  `config_error`) in `config.json`.

### Tests
- 331 passed / 21 skipped.

## 1.5.3 — 2026-11-13

Third field fix: the DTrace feature could not run on an installed node.

### Fixed — reviewed D scripts were missing from the bundle
- `build_embedded_windows.py` staged `sensors/whids` and `sensors/tap` but
  never `sensors/dtrace`, so `trace list|selftest|run` failed with
  "sensors/dtrace not found (repo or embedded)" on every installed host.
  The builder now stages every `*.d` script and the manifest covers them.
- `trace._scripts_dir()` also resolves the frozen bundle
  (`<_MEIPASS>/embedded/sensors/dtrace`), an explicit root, and the repo.

### Fixed — DTrace installed outside PATH was reported missing
- Microsoft.DTrace's MSI does not add `dtrace.exe` to PATH. `trace check`
  now falls back to `%ProgramFiles%\DTrace\dtrace.exe` (and ProgramFiles
  (x86) / ProgramW6432) before declaring DTrace unavailable.

### Tests
- 328 passed / 21 skipped.

## 1.5.2 — 2026-11-13

Second field fix from the v1.5.0 estate run: an existing WHIDS install must
be **converged**, not assumed.

### Fixed — stale `config.toml` survived every install
- `whids_install_decision()` returned `already_present` when the service
  existed, and the installer skipped the whole provisioning block. So
  `install --force` refreshed the Plasma instance but left whatever
  `C:\Program Files\Whids\config.toml` was on disk:
  - WS1 had Whids' 6.7 KB default config → the service crash-looped every
    5 s (SCM 7031 ×57) and never reached "Boot sequence completed".
  - WS2 had a pre-1.4 Plasma config (`channels = ["all"]`, no explicit
    channel list) and kept running it.
- `install`/`install --force` now stages WHIDS from the bundle on every run:
  `_whids_files_to_stage()` builds a bundle-driven target map (binary,
  `whids.toml`, `config.toml`, IOC + baseline rules), computes drift, and
  only restarts when something differs.
- A healthy, already-converged sensor is left running untouched.
- If the new config cannot start the service, the installer restores
  `config.toml.plasma-prev` and retries once before marking the sensor
  skipped — an upgrade never knowingly leaves a working node down.
- Obsolete `*.bak.gen` rule backups are removed when rules are deployed
  (Gene loads every `*.gen`, including backups).
- `C:\Sysmon` (the configured archive directory) is created before first
  start.

### Tests
- 325 passed / 21 skipped.

## 1.5.1 — 2026-11-13

Field fixes found during the first live estate validation of 1.5.0.

### Fixed — baseline gene rules were never deployed to WHIDS
- The installer copied only `plasma-iocs.gen` into
  `Database\Rules`; live nodes were loading **1–2 rules instead of 16**.
  `whids.deploy_rules()` now copies the baseline and IOC rule files
  together. (Detected from WHIDS's own log line "Number of rules loaded in
  engine: 1".)

### Fixed — misleading DTrace availability hint
- `trace check` on a host with DTrace installed but the boot setting absent
  said "admin required". It now distinguishes an absent setting (normal)
  from an unreadable one and points at `plasma trace provision`.

### Tests
- 321 passed / 21 skipped.

## 1.5.0 — 2026-11-13

DTrace as Plasma's third sensor — the on-demand kernel microscope.

### New — DTrace integration
- `plasma trace list|check|selftest|run|provision`.
- Reviewed script library (`sensors/dtrace/*.d`) with `//` metadata
  (name/technique/score/kind); the loader refuses `system()` and other
  destructive constructs, requires an allowlisted provider and the
  `plasma|{json}` row marker.
- Three shipped scripts: **syscall-errors** (T1106, non-success NT
  statuses), **process-create** (T1059, NtCreateUserProcess/ThreadEx),
  **etw-kernel-process** (T1057, Microsoft-Windows-Kernel-Process header
  fields; `etw:<guid>:<level>_<keyword>:generic_event` syntax).
- Bounded runs: wall-clock window (1s–5m, process killed), row cap
  (default 2000), optional raw capture, content-hash dedupe into the store.
- Rows normalize to `kind: "trace"`, `source: "dtrace"` with technique and
  score — chains, watch, fleet and drift consume them unchanged.
- Explicit provisioning: Server 2025 is built-in; older Windows installs
  Microsoft.DTrace v2.0 (winget) and sets `bcdedit /set dtrace on`,
  reporting `reboot_required`. Never installed silently by the EDR
  installer; install records `sensors.trace.status`
  (available / installed_not_enabled / unavailable / unknown).
- `-w` (destructive mode) is never used.

### Tests
- 318 passed / 21 skipped (up from 295): script validation (destructive
  constructs, marker, providers, score), parsing and normalization,
  bounded-run kill/dedupe paths, check/status, provisioning (already-ready,
  enable-only, winget, no-winget manual hint).

## 1.4.0 — 2026-11-13

Prime-time gaps closed: supervised WHIDS, honest impact detection, and an
enterprise deployment package.

### Fixed — WHIDS init hang
- **Explicit channel list** in `whids.toml` (Sysmon, PowerShell, Security,
  System) instead of `"all"` — subscribing to every channel is the known
  trigger for the 1.7.0 init hang.
- **Supervised start**: the installer waits up to `PLASMA_WHIDS_START_TIMEOUT`
  (60s default) for `Running`; a service stuck in `StartPending` is
  force-stopped and the node records a documented MINIMAL posture instead
  of leaving a hung service.
- **`plasma whids diagnose`**: service state/mode/path, channel
  readability, recent SCM errors, `whids.log` tail, and the likely cause —
  as data.
- Health names `StartPending` explicitly ("hung at init").

### New — canary files (impact detection, T1486)
- `plasma canary deploy|verify|status`: six decoy documents with a SHA-256
  manifest. `watch` verifies them every sweep; missing/modified = score-10
  `canary_tripped`. Coverage attributes T1486 to `canary:verify` (no noisy
  "encryption burst" heuristic).

### New — MSI + GPO packaging
- Releases now include `plasma-<version>-windows-x64.msi`, built with WiX
  from the signed exe: silent install, deferred elevated provisioning
  action, `PLASMA_ROOT` public property, in-place upgrades.
- `docs/deployment.md`: silent install, GPO Software Installation steps,
  transforms, uninstall semantics, rollout rings, signing note.

### Coverage
- 91.7% rollup (33/36), 75.0% exact (27/36), 83.3% fidelity-weighted.
- Blind spots now exactly three: T1056, T1056.001, T1112.

### Tests
- 295 passed / 21 skipped (up from 277): canary lifecycle (deploy/verify/
  delete/modify/watch), WHIDS diagnosis, MSI WiX generation, updated
  coverage semantics.

## 1.3.0 — 2026-11-13

Depth without checkbox-padding: the coverage report now separates breadth
from evidence quality, and five telemetry-backed rules close real gaps.

### New — coverage semantics
- **Parent rollup.** A core technique counts as covered when any of its
  sub-techniques is covered. Both numbers are reported: **exact 72.2%**,
  **rollup 88.9%**.
- **Fidelity per rule.** Every tap rule carries a `fidelity`
  (high/medium/low); gene-rule fidelity is mapped in `coverage.py`.
  `weighted_pct` (**80.6%**) discounts low/medium evidence, so 100% breadth
  cannot mask a weak rule.
- Blind spots are now precisely four and named: T1056 / T1056.001 (input
  capture, needs kernel hooks), T1112 (generic registry edits), T1486
  (impact; canary files are the honest detector).

### New — five gene rules (Sysmon)
- File Delete by LOLBin (T1070.004) — Sysmon 23/26, executable/archive
  artifacts deleted by cmd/powershell/certutil/bitsadmin/wmic/reg.
- Run Key Persistence (T1547.001) — registry Run/RunOnce writes.
- Service Registry Persistence (T1543.003) — Services key writes.
- Privileged Group Add (T1098) — `net localgroup administrators … /add`.
- Execution From User Paths (T1204.002) — processes running from
  Downloads / Temp / Users\Public.

### Improved — Sysmon baseline
- FileDelete is opt-in in Sysmon; the shipped baseline now includes a
  bounded `FileDelete` include filter (executable/archive extensions) so
  T1070.004 has real telemetry. Existing nodes apply it with
  `Sysmon64.exe -c C:\ProgramData\Plasma\tools\sysmon-baseline.xml`.

### Tests
- 277 passed / 21 skipped (up from 264): positive/negative behavior for
  every new rule, rollup semantics, fidelity weighting, honest-blind-spot
  assertions, and XML validation of the Sysmon baseline config.

## 1.2.0 — 2026-11-12

Signed-update trust chain and tokenless updates (repo is now public).

### New — signer pinning on updates
- `plasma update apply` now verifies the **Authenticode signer** of the
  downloaded exe before executing it, against thumbprints pinned inside the
  installed binary (`DEFAULT_SIGNER_THUMBPRINTS`; override with
  `PLASMA_SIGNER_THUMBPRINTS`, e.g. while rotating from the self-signed
  Hyperspace cert to SignPath). A mismatch or unsigned binary aborts the
  update (exit 2) and the staged installer is never run. SHA256SUMS and the
  exe share one origin; the pinned thumbprint is a second, independent
  trust anchor. `--allow-unsigned` exists for development only.

### Improved — public-repo updates
- `update check` / `update apply` work **anonymously** now that the repo is
  public; `--token-env` remains optional for private forks. (This removes
  the token step from estate updates.)

### New — release signing in CI
- `release.yml` signs the Windows exe with Authenticode (signtool, DigiCert
  RFC3161 timestamp) when repo secrets `SIGNING_PFX_BASE64` /
  `SIGNING_PFX_PASSWORD` exist, **before** SHA256SUMS is computed. Without
  secrets the release proceeds unsigned, as before.
- `docs/SIGNPATH_APPLICATION.md`: complete application package for free,
  publicly trusted OSS signing via SignPath Foundation (eligibility
  checklist, form answers, post-approval GitHub Actions wiring).

### Fixed — reproducible engine fetch
- Upstream removed the neuralOS per-platform engine bundles from
  `Cactus-Compute/needle3` on 2026-11-05, breaking the CI/release engine
  fetch. `tools/fetch_engine.py` now fetches from the last revision that
  carries them (`d6c7d6a2e965…`), whose `needle3.cact` is byte-identical to
  the current head weights; CI and release use the pinned fetcher.

### Tests
- 264 passed / 21 skipped (up from 250): signer match/mismatch/unsigned/
  missing-PowerShell/pin-rotation, refusal path (installer never runs on a
  bad signer), dev override, anonymous API fetch without Authorization,
  pinned engine fetch (copy/exec-bit/unknown platform/missing folder).

## 1.1.0 — 2026-11-05

Deeper probes and findings — story-level detection, honest coverage
reporting, store hygiene, and a bigger (still plan-gated) response
vocabulary. Built and validated desk-side against fixtures and the golden
gates; live-fire validation on the estate follows when it boots.

### New — story-level detection
- `plasma chain score` (`plasma/chain.py`): deterministic chain rules over
  the events tail — ordered step matchers with gap windows, full
  backtracking, timestamp-ordered (file order is irrelevant). Three
  built-in stories: **phish_spawn_chain** (office → script host →
  encoded/egress, 9/10), **brute_force_success** (≥5 failed logons then a
  success for one user, 8/10), **persistence_after_privilege** (account
  creation → persistence-shaped command, 9/10). Integrated into
  `watch` sweeps as first-class findings.

### New — honest coverage reporting
- `plasma coverage` (`plasma/coverage.py`): diffs the shipped rule sets
  (tap rules + gene baseline + IOC feed) against a curated list of 36 core
  on-box ATT&CK techniques. Reports covered/blind with rule provenance.
  Current shipped rules: **58.3% core coverage (21/36)** — and the probe
  says out loud that ransomware staging (T1486) is unwatched instead of
  pretending.

### New — deep probe
- `plasma deep persistence` (`plasma/deep.py`): every auto-start location
  in one answer — run keys, services (+ service DLLs), scheduled task
  actions, IFEO debugger hijacks, Winlogon shell/userinit, WMI
  subscriptions — each with Authenticode signature status. Items are
  flagged `suspect` when unsigned AND outside `C:\Windows` (a surfaced
  heuristic, never an automatic action).

### New — store hygiene
- `plasma store rotate|compact|stats` (`plasma/store.py`): size-based
  rotation with numbered elders (bounded keep), atomic duplicate
  compaction (torn lines preserved, crash-safe via temp+replace), and
  span/kind statistics. The contract stays "a plain file".

### New — response vocabulary (same gates)
- `disable_task` — disable (not delete) with XML backup; enable to undo.
- `remove_run_key` — remove a string Run-key value; the value data is
  captured to a sidecar file and undo restores it (allowlisted keys only,
  pipe-separated `key|name` targets, strict value-name validation).
- `plasma playbook list|apply|undo` (`plasma/playbooks.py`): named
  sequences of allowlisted actions applied as ONE plan-gated unit —
  **contain-user** (disable_user + snapshot) and **isolate-box**
  (isolate_host + snapshot). Aborts on the first failing step, journals
  exactly how far it got, undoes succeeded steps last-first and skips
  non-undoable steps gracefully. No free-form shell — a bigger allowlist,
  not a wider door.

### Improved
- `watch`: scans chains on the events tail; alerts are **throttled by the
  loudest finding's type** (at-most-once per hour per finding-type; the
  throttle window only burns when a channel actually accepted the message).
- `health`: two new sensor-of-sensors checks — **sensor_heartbeat** (the
  events diary is still being written; newest row < 24h) and
  **rdp_hardening_drift** (fDenyTSConnections=0 + sane SecurityLayer — the
  lockout-incident checks, permanently on the meter).
- `coverage`, `chain`, `store`, `deep`, `playbook` all follow the JSON +
  exit-code CLI contract; failures are data, not tracebacks.

### Tests
- 250 passed / 21 skipped (up from 202): chain semantics (order, gaps,
  count bursts, store tail), coverage honesty, store rotation/compaction
  atomicity, playbook plan-gating/abort/reverse-undo, throttle windows,
  heartbeat parsing, deep-probe normalization.

## 1.0.0 — 2026-10-19

First stable release. Preceded by a full-repo audit (two independent
line-by-line reviews) that found and fixed 24 defects — every fix is pinned
by a regression test (`tests/test_regressions.py`, `tests/test_sensors.py`).

### Fixed — detection content (FP/FN)
- `net user add` gene rule was dead: `Image` match required trailing
  whitespace a bare path never has; also `/add` (canonical syntax) never
  matched — both fixed, functionally tested.
- `mshta` remote-content rule verified UNC/URL-scoped (local `.hta` paths do
  not match); Office-spawn child set now covers `mshta.exe`; encoded-command
  rule now covers the `-ec` short form.
- WHIDS default `--min-confidence` was 85 on a 0–10 scale, so a default
  `whids push --apply` extracted zero indicators and REPLACED the live IOC
  rule file with an empty one. Default is 8 (as the help text always said).

### Fixed — correctness
- `identity pull`: event timestamps were local time labeled `Z` (UTC) —
  cross-host lateral-hop correlation shifted by the host's UTC offset.
  Now `ToUniversalTime()` at the source; `process` is a real basename.
- `observatory`: three PowerShell regexes were over-escaped and silently
  disabled (standard-service filter flagged every LocalSystem service under
  `C:\Windows\`; device-path drivers were dropped from signature checks).
- `update check`: `v1.0.0-rc2` read as newer than `1.0.0` — the updater
  could downgrade a node to a release candidate. Pre-release suffixes are
  now ignored in comparisons.
- `fleet correlate`: one offset-less timestamp beside aware ones crashed
  the whole command with `TypeError`; naive timestamps now normalize to UTC.
- `fleet pull --cap 0` returned EVERY row (`[-0:]`); now returns none.
- `fleet`: explicitly-passed `--window`/`--canary` values now update an
  existing case instead of being silently ignored by `correlate`.
- `health`: Sysmon freshness parse was locale-sensitive (`12,3` on de-DE
  broke the check and reported healthy nodes down); now culture-invariant.
- `watch`: "unpulled WHIDS alerts" counted every alert line ever written and
  re-fired forever (pull never truncates rotated files); it now fires on
  growth since the last sweep only.
- `notify`: the `min_score` noise gate was computed and reported but never
  applied — every finding notified regardless. Score-gated now, documented.
- `actuate`: `--apply` now REQUIRES `--plan <id>` — the id of a prior
  dry-run entry for the same action+target with a matching payload digest
  (dry-run first is now enforced, not just documented).
- `actuate`: WMI-binding undo survived single-binding JSON unwrapping and
  journal truncation (bindings captured to a sidecar file); journal tolerates
  torn lines (crash mid-append no longer bricks every actuate command);
  apply failures (runner missing, non-zero rc, failed verification) exit
  non-zero instead of reporting success.
- `install`: the Sysmon-repair re-decision passed the updated
  `sysmon_present` and short-circuited to `already_present`, skipping the
  WHIDS start on exactly the broken boxes the repair path exists for.
- `install`: a dangling `current` junction defeated both guards and crashed
  with a traceback; handled with structured JSON errors.
- `update apply`: forwards `--root` to the inner install (custom-root nodes
  no longer split-brain); staged exe has a stable name.
- `update check` exit codes are scriptable: 0 = up to date, 2 = update
  available.
- CLI: `fleet pull` (bad inventory), `tap run --for`, `tap selftest/run`
  (bad rules), `notify show` (bad config) return JSON errors + rc 2 instead
  of raw tracebacks.
- All node-local subprocess calls decode explicitly as UTF-8 with
  replacement — non-ASCII PS output can no longer crash an apply mid-flight.
- `tap` rules loader: clean `ValueError` for missing provider; rule names
  validated against the pipe format; manifest excludes `.DS_Store` by name.

### Tests
- 202 passed / 21 skipped (Windows-only paths), up from 174: new
  detection-content suite (gene rules compile AND behave — positives and
  negatives), regression suite for every audit fix, plan-gate suite.

## 0.11.1 — 2026-10-18
- correct version string (the v0.11.0 tag built with 0.10.1).

## 0.11.0 — 2026-10-18
- auto-update (`update check|apply`, SHA256SUMS-verified, rename-while-running),
  alerting (`notify`, token_env-only), health + `watch once|loop`,
  detection depth (tap rules 29→31, baseline 10 gene rules).

## 0.10.x
- intelligent installer (FULL/MINIMAL decision, Sysmon auto-download + EULA,
  repair semantics), BOM-tolerant health config reads.

## 0.9.x
- identity plane (4624/4625 via Event Log API), fleet correlation scoring.

## 0.8.x
- `plasma fleet`: desk-side cross-host pull/correlate/report.

## 0.7.0
- krabsetw ETW tap (plasma-tap.exe, manifest-verified rules, matches-only).
