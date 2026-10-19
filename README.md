# Plasma

**An agent-based EDR bundle with a frozen neuralOS instance.**

Plasma packages three layers into one installable product:

```
WHIDS agent             detection (gene rules) + artifact collection + response
neuralOS engine         on-device 121M tool-calling model (selection only)
frozen instance         Pydantic contract + probe menu + bridge + graph layer
```

The result is an endpoint agent whose detection and containment stay
deterministic (WHIDS actionable rules), while operators can ask plain-English
questions about what happened: *"why did WHIDS kill PID 4832?"*,
*"which processes made outbound connections?"*, *"any persistence on WS2?"*

The model is **never** in the kill path. Situational awareness is the model's
job; response remains policy-driven and, for model recommendations, human-approved.

## Layout

```
instance/          frozen neuralOS artifact (menu, models, bridges, graph)
packaging/         installer + post-install verifier + config example
sensors/           pins + bundled WHIDS payload (AGPL-3.0) + IOC gene rule
plasma/            Python package: manifest, bundler, CLI (plasma ask/probe/status)
plasma_entry.py    entry point for the one-file executable
samples/           deterministic normalized-event corpus used for build + tests
tests/             pytest suite (models, bridge, menu, manifest, bundle, selection, PS)
.github/workflows/ CI (ubuntu + windows) and release packaging
```

## Quickstart

```bash
pip install -e .[dev]

# Build a bundle (add --engines <dir> to include platform engine binaries)
plasma bundle build --out dist --version 0.1.0

# Verify integrity
plasma manifest verify --dir dist/plasma-0.1.0

# Ask a question (needs an engine binary + weights)
plasma ask --bundle dist/plasma-0.1.0 --prompt "show me the critical alerts"

# Execute one probe directly
plasma probe --bundle dist/plasma-0.1.0 --tool plasma_overview
```

Windows install:

```powershell
.\packaging\install.ps1 -Bundle .\dist\plasma-0.1.0 -DryRun     # plan only
.\packaging\install.ps1 -Bundle .\dist\plasma-0.1.0             # install + flip current
.\packaging\verify.ps1 -Bundle C:\ProgramData\Plasma\current -EventsPath C:\ProgramData\Plasma\data\events.jsonl
```

## Frozen instance

Ten read-only probes: `plasma_overview`, `plasma_recent`, `plasma_alerts`,
`plasma_processes`, `plasma_network`, `plasma_dns`, `plasma_persistence`,
`plasma_search`, `plasma_graph_overview`, `plasma_graph_neighbors`.

* results are digests capped at 25 rows plus counts — never raw dumps;
* every record passes the strict `PlasmaEvent` model (Python) or generated
  shape checks (PowerShell);
* event source: `PLASMA_EVENTS`, port/instance-local store, then
  `C:\ProgramData\Plasma\data\events.jsonl`;
* build once, freeze, deploy identical artifacts fleet-wide; per-host values
  live in `config.json`, never in the instance.

## WHIDS integration (two-way)

```powershell
# Pull: WHIDS alerts -> normalized Plasma events
plasma whids pull --root "C:\Program Files\Whids" `
  --out C:\ProgramData\Plasma\data\events.jsonl

# Push: high-confidence Plasma indicators -> WHIDS gene rule (dry-run first)
plasma whids push --events C:\ProgramData\Plasma\data\events.jsonl --min-confidence 8
plasma whids push --events C:\ProgramData\Plasma\data\events.jsonl `
  --min-confidence 8 --apply --reason "IR-2026-042" --restart-service

# State
plasma whids status
```

**Pull** reads the WHIDS alert JSONL under `Logs\Alerts` (gene `EdrEvent`
records) and maps them to the Plasma schema: gene `Criticality` (0-10) →
severity/score, `ATTACK[].ID` → technique, `Actions` → killed/blocked/logged,
event fields → process/hash/network context.

**Push** writes `Database\Rules\plasma-iocs.gen` — a gene schema-2.0.0 rule
WHIDS compiles at start. SHA-256 indicators match `Hashes`/`ImageHashes`
(process, image load, file); domain indicators match `QueryName` (DNS);
IP indicators match `DestinationIp` (network). Matching events raise WHIDS
alerts carrying the Plasma signature.

Safety: dry-run by default; private/reserved IPs and benign domains excluded;
expressions merged and deduplicated; the previous rule file is backed up; every
apply is journaled. WHIDS owns response actions — Plasma never drives them.

## Observatory, drift and actuation (rmagent lineage)

Read-only host questions answered locally by fixed PowerShell payloads
(`plasma observe attest|sketch|edges|explain|pslogs|attackmap|regedges|flowstats|canary|sysmon_health`),
baselines + deterministic drift scoring
(`plasma drift record|score|list --question attest`), and scoped response:

```bash
plasma actuate actions                                              # the allowlist
plasma actuate apply isolate_host --reason "ransomware"             # dry-run (default)
plasma actuate apply isolate_host --reason "ransomware" --apply     # execute
plasma actuate undo --id 3 --apply
plasma actuate journal --last 10
```

Lockout-proof by construction: protected services/processes/accounts are
refused (WinRM, TermService, WHIDS, Sysmon, BFE, MpsSvc, lsass, ...);
`isolate_host` creates RDP-3389 + WinRM-5985 allow rules before any block
rule so management access survives isolation; `--reason` is mandatory;
every apply and undo is journaled (`actuate-journal.jsonl`) with its
verification result; nothing runs without an explicit `--apply`.

## ETW tap (krabsetw) — the gap providers

`plasma tap` streams the providers Sysmon/WHIDS do not own — PowerShell
(full ETW fidelity), WMI-Activity, DNS-Client, .NET Runtime (narrow
keywords), Schannel — through a small C++ sidecar (`tap/plasma-tap.cpp`,
built on Microsoft's MIT-licensed krabsetw, compiled by CI into the release
bundle). Lake-less by construction: events are scored **in memory**, only
matches are written (capped JSONL), no service, on-demand windows only.

```bash
plasma tap list                                    # providers + rules catalog
plasma tap selftest                                # validate sidecar + rules, no trace
sudo plasma tap run --providers powershell,wmi,dns --for 5m   # admin required
plasma tap run --providers dns --for 90s --events events.jsonl  # + auto-collect
plasma tap collect --matches matches.jsonl --events events.jsonl
```

Tap hits normalize into the same strict PlasmaEvent contract (source `tap`,
kind `alert`, action `logged`) and flow into the frozen instance like every
other sensor. Matching is deterministic (provider + event id +
case-insensitive substring on a named field) via the manifest-verified
`sensors/plasma-tap-rules.json` — never model judgment.

## Sensor policy

## Requirements

- Windows 10/11 x64
- **Sysmon** installed and logging `ProcessCreate`/`ProcessTerminate`
  (WHIDS makes the Sysmon service dependent on the WHIDS service at install)
- Administrator rights for `install`

## Single self-contained Windows x64 executable

The release artifact `plasma-<version>-windows-x64.exe` is the whole product
in one file:

* Python + Pydantic runtime (PyInstaller one-file)
* frozen instance (`models.py`, menu, bridges, graph)
* Windows neuralOS engine + `needle3.cact` weights
* WHIDS payload (AGPL-3.0 release bundle) + pin + IOC gene rule

Native executables are stored gzipped inside the binary (PyInstaller rewrites
Mach-O/PE payloads and would break the manifest); the CLI unpacks them to a
temporary runtime directory and executes them. `plasma status` verifies the
embedded SHA256 manifest; `plasma install` stages the instance, writes config,
installs WHIDS, and flips a `current` junction.

```powershell
.\plasma-0.3.0-windows-x64.exe status --events C:\ProgramData\Plasma\data\events.jsonl
.\plasma-0.3.0-windows-x64.exe ask --prompt "critical alerts"
.\plasma-0.3.0-windows-x64.exe install --dry-run
.\plasma-0.3.0-windows-x64.exe install
```

## CI

* `ci.yml` — tests on Ubuntu and Windows; engine selection job (fetches the
  Linux engine from the `neuralos` package); bundle build + verification.
* `release.yml` — tag `v*`: fetches Windows/Linux engines, builds the bundle,
  writes `SHA256SUMS`, publishes a GitHub release.

## Security

Read-only by construction; no secrets in the instance; signed release
artifacts recommended; test on non-production endpoints first. See
`docs/SECURITY.md`.

MIT licensed; third-party components retain their own licenses.
