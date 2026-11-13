# Changelog

The canonical history lives in
[CHANGELOG.md](https://github.com/DrOlu/plasma/blob/main/CHANGELOG.md).
Highlights by release:

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
