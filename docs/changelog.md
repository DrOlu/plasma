# Changelog

The canonical history lives in
[CHANGELOG.md](https://github.com/DrOlu/plasma/blob/main/CHANGELOG.md).
Highlights by release:

## 1.6.2 — 2026-11-13

- **DTrace readiness is capability-based** — the "2.0" package still calls
  itself 1.1.0 / Sun D 1.13.1, so `trace check`/`provision` no longer chase
  a version string; installed + enabled means ready.

## 1.6.1 — 2026-11-13

- **DTrace version probe** — `trace check` runs the resolved `dtrace.exe`.
- **Trace rows use `tid`** — `pid` is not portable across the DTrace builds
  on the estate; `tid` works on both hosts.

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
