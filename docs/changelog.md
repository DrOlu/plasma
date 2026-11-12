# Changelog

The canonical history lives in
[CHANGELOG.md](https://github.com/DrOlu/plasma/blob/main/CHANGELOG.md).
Highlights by release:

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
