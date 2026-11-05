# Changelog

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
