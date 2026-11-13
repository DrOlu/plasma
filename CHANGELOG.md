# Changelog

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
