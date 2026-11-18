# Plasma

**An agent-based EDR bundle with a frozen neuralOS instance.**

**Documentation:** https://drolu.github.io/plasma/
**One-page visual overview:** https://drolu.github.io/plasma/onepager.html

Plasma packages three detection/agent layers plus a measured prevention plane into one installable product:

```
WHIDS agent             detection (gene rules) + artifact collection + response
neuralOS engine         on-device 121M tool-calling model (selection only)
frozen instance         Pydantic contract + probe menu + bridge + graph layer
protection (measured)   enforce: snapshot + kill at score 9+, approval for the rest
                        prevent: AppLocker · egress · ASR · LSA protection
```

The result is an endpoint agent whose detection stays deterministic (WHIDS
gene rules), with containment kept in a separate, plan-gated response plane.
Operators can ask plain-English questions about what happened: *"why did
WHIDS report PID 4832?"*, *"which processes made outbound connections?"*,
*"any persistence on WS2?"*

**Detects always. Contains narrowly by default. Blocks only through
Microsoft's own enforcement points.**

The shipped WHIDS sensor config is detect-only (`report`): it reports, it
does not kill. Containment is a separate, measured layer — `plasma enforce`
ships armed but limited to snapshot + kill at score 9+, with isolation and
every other action behind approval. `plasma prevent` configures AppLocker,
firewall, Defender ASR and LSA controls, audit-first and rollbackable. The
model is **never** in the action path; containment runs through written
policy, an approval queue and a journal.

## Agent-native operation

Plasma can be driven by an agent harness without giving it arbitrary
execution. Eleven typed tools are exposed over MCP (`plasma mcp serve`);
mutating tools return a dry-run plan and an approval reference, never an
execution. A deterministic policy engine, a hash-chained provenance ledger,
a kill switch and a single-use approval queue sit between the model and the
host.

```powershell
plasma control policy show
plasma control policy set --autonomy supervised --deny kill_process
plasma mcp serve
plasma control audit verify
plasma eval run
```

See [Agent-native operation](https://drolu.github.io/plasma/agent-native/)
and the [Control plane](https://drolu.github.io/plasma/control-plane/).

### HTTP API

`plasma serve` exposes the same CLI over an authenticated HTTP API, as an
alternative to WinRM or SSH. `POST /v1/exec` takes an argv list and runs it
through the real parser; `GET /v1/commands` returns the command tree. The
default key is `plasmaplasma`; use `--api-key-file` or
`PLASMA_SERVE_API_KEY` in production. `--read-only` refuses every mutating
command, and every call is written to `<root>/serve/audit.jsonl`.

```powershell
plasma serve --port 9999 --api-key-file C:\ProgramData\Plasma\serve.key
```

See [HTTP API](https://drolu.github.io/plasma/serve/).

## Code signing

Windows release executables are Authenticode-signed (self-signed project
certificate today) and every release publishes a `SHA256SUMS`. Plasma is
applying to the [SignPath Foundation](https://signpath.org/) for publicly
trusted code signing, and will use SignPath Foundation-issued signing once
the application is approved. Updates verify the downloaded binary's signer
against pinned thumbprints before executing it.

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
severity/score, `ATTACK[].ID` → technique, `Actions` → reported/logged,
event fields → process/hash/network context.

**Push** writes `Database\Rules\plasma-iocs.gen` — a gene schema-2.0.0 rule
WHIDS compiles at start. SHA-256 indicators match `Hashes`/`ImageHashes`
(process, image load, file); domain indicators match `QueryName` (DNS);
IP indicators match `DestinationIp` (network). Matching events raise WHIDS
alerts carrying the Plasma signature.

Safety: dry-run by default; private/reserved IPs and benign domains excluded;
expressions merged and deduplicated; the previous rule file is backed up; every
apply is journaled. The shipped WHIDS config is detect-only (`report`); Plasma
never drives WHIDS response actions.

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

## Detection content

18 hand-written gene rules, 30 IOC indicators, 31 tap rules and a vendored
**259-rule SigmaHQ corpus** (`sensors/plasma-sigma.gen`, 168 techniques,
DRL 1.1, upstream commit pinned in `sensors/sigma-sources.json`). WHIDS
loads 278 rules on a converged node. Coverage is reported honestly:
94.6% rollup, 89.2% exact, 85.9% fidelity-weighted, with the two remaining
blind spots named. A third provenance axis derives `live` / `partial` /
`dormant` from the shipped Sysmon config, so a rule whose event IDs are not
enabled cannot inflate the weighted number.

## Protection (measured)

Containment is armed by default but narrow; prevention is audit-first.

**Containment** — findings become allowlisted, reversible actions:

```powershell
plasma protect status                    # armed? what is protected?
plasma protect protected
plasma protect disarm --reason "change window"
plasma protect arm
plasma enforce status
plasma enforce run                       # proposals only
plasma enforce run --apply               # policy still gates each action
plasma watch once --enforce              # the PlasmaWatch task does this every 5 min
plasma enforce pending                   # isolation etc. wait for a human
plasma enforce approve --id 4 --apply
```

The default policy allows only `snapshot` + `kill_process`, at score 9+,
2 actions per run, 30-minute cooldown. Injection findings write one host
snapshot and then kill the accessing process; a tripped canary queues host
isolation for approval. The snapshot is host state, not process memory —
remove it from `allowed_actions` for speed, or move `kill_process` into
`require_approval` for forensics first. WinRM, RDP, WHIDS, Sysmon, LSASS
and Administrator are refused in code. Every apply still passes actuate's
dry-run + plan gate.

**Enforcement points** — stop behaviour before it runs:

```powershell
plasma prevent status
plasma prevent applocker --mode audit                 # plan
plasma prevent applocker --mode audit --apply --plan 3 --reason "pilot"
plasma prevent egress --allow 10.0.0.0/8 --allow 1.2.3.4:443
plasma prevent asr --ids <rule-guid> --action Audit
plasma prevent lsa
plasma prevent rollback --id 7 --apply
```

AppLocker (audit by default), firewall egress default-deny with a mandatory
allowlist, Defender ASR and LSA protection. Plasma ships no kernel driver:
inline blocking is delegated to Microsoft's signed enforcement points, with
Plasma owning policy, evidence and rollback. Details and limits:
<https://drolu.github.io/plasma/prevention/>.

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

## Fleet — one desk, many computers (v0.8.0)

Desk-side cross-host correlation. Endpoints need nothing new: their
normalized `events.jsonl` stores are already small and schema-identical,
so the desk pulls a capped tail from each host into a case directory and
joins them with deterministic rules. No server, no standing collector,
no lake — pull small answers on demand, write a case dossier, close the case.

```bash
# fleet.json: [{name, transport: winrm|file, endpoint, username,
#               password_env, events_path}, ...]   (no inline passwords, ever)
export WS2PW=...
plasma fleet scan --inventory fleet.json --case incident-42 --window 3600
plasma fleet report --case incident-42          # one-page markdown dossier
```

Deterministic joins: canary_tripped (10), lateral_hop (9, same user on
2+ hosts inside the window), shared_hash (8), shared_domain (7),
shared_ip (7), blind_host (8, from attest answers in the case).
Verdicts: clean / investigate / act now. Credentials arrive via env vars
(`password_env`) and are never written to disk — enforced by test.

```bash
pip install 'plasma-edr[desk]'   # adds pywinrm for the winrm transport
```

## Operations: health, watch, notify, self-update

```bash
plasma health                                   # is the stack alive? (json verdict)
plasma watch once                               # sweep: health + drift + canary + alerts
plasma notify show | plasma notify test         # alert channels (telegram/webhook)
plasma update auto --check-only                 # exit 2 when an update is available
plasma update auto                              # measured signed self-update
plasma update check                             # compare against latest release
plasma update apply                             # download, verify sha, install, rotate bin
```

Alert channels live in `<root>/notify.json` (telegram needs `token_env` —
secrets never live in config files). `watch once` is cron/Task-Scheduler
friendly: quiet when clean, notifies on findings.

The installer registers `PlasmaUpdate`, a daily SYSTEM task with a random
minute inside the 02:00–05:00 maintenance window. It applies **signed**
releases only, through the same SHA256 + Authenticode + install + rotate
path as `update apply`. `broad` hosts wait 24 hours after publication;
`canary` hosts update first; `rollback` hosts never auto-update. The kill
switch pauses updates, the previous binary is kept for `plasma rollback`,
and `--no-autoupdate` disables the task. `update-journal.jsonl` and
`update-state.json` record every attempt.

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
