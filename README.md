# Plasma

**An agent-based EDR bundle with a frozen neuralOS instance.**

Plasma packages three layers into one installable product:

```
Sentinel service        detection + correlation + deterministic response (sensor layer)
neuralOS engine         on-device 121M tool-calling model (selection only)
frozen instance         Pydantic contract + probe menu + bridge + graph layer
```

The result is an endpoint agent whose detection and containment stay
deterministic (Sentinel Tier-1), while operators can ask plain-English
questions about what happened: *"why did Sentinel kill PID 4832?"*,
*"which processes made outbound connections?"*, *"any persistence on WS2?"*

The model is **never** in the kill path. Situational awareness is the model's
job; response remains policy-driven and, for model recommendations, human-approved.

## Layout

```
instance/          frozen neuralOS artifact (menu, models, bridges, graph)
packaging/         installer + post-install verifier + config example
sensors/           pins + bundled Sentinel payload (MIT, checksum-verified)
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

## Sentinel integration (two-way)

```powershell
# Pull: Sentinel detections -> normalized Plasma events
plasma sentinel pull --sentinel-root C:\ProgramData\Sentinel `
  --out C:\ProgramData\Plasma\data\events.jsonl

# Push: high-confidence Plasma indicators -> Sentinel's local IOC bundle (dry-run first)
plasma sentinel push --events C:\ProgramData\Plasma\data\events.jsonl `
  --min-confidence 85
plasma sentinel push --events C:\ProgramData\Plasma\data\events.jsonl `
  --min-confidence 85 --apply --reason "IR-2026-042" --restart-service

# State
plasma sentinel status
```

**Pull** reads `%ProgramData%\Sentinel\events.jsonl` (DetectionEvent records) and
maps them to the Plasma schema: Tier1→critical/high, `AuthorizedResponse`→
killed/quarantined/blocked/logged, metadata→IP/domain/hash/technique.

**Push** writes `%ProgramData%\Sentinel\threatfox-bundle.json.gz` — the
unsigned local IOC snapshot Sentinel loads at start. SHA-256 entries feed
`IoCScanner`; domain entries feed `DnsQueryMonitor`. Sentinel 3.3.1 exposes no
active IP query, so IP entries are stored for future/other consumers.

Safety: dry-run by default; private/reserved IPs and benign domains excluded;
existing bundle merged by highest confidence; backup written; every apply
journaled; **signed rule packs are never touched**. Requires administrator
rights (Sentinel's ProgramData ACL) and a service restart for Sentinel to load
the new bundle.

## Sensor policy

| Sensor | Required | Bundled | Why |
|---|---|---|---|
| Sentinel | yes | **yes — setup EXE + LICENSE + checksums** | the detection/response brain |
| Sysmon | no | installed from the official package | optional kernel-level baseline |
| Sealighter | no | on-demand only | deep ETW/WPP research, not an agent |

The bundled Sentinel setup is MIT-licensed (LICENSE travels with it) and is
SHA256-verified both by the bundle manifest and by `sensors/sentinel.pin.json`.
The installer runs it silently (`/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-`),
waits for the service, and fails closed if the service does not appear.

## Single self-contained Windows x64 executable

The release artifact `plasma-<version>-windows-x64.exe` is the whole product
in one file:

* Python + Pydantic runtime (PyInstaller one-file)
* frozen instance (`models.py`, menu, bridges, graph)
* Windows neuralOS engine + `needle3.cact` weights
* Sentinel setup payload (MIT, checksum-verified) + pin file

Native executables are stored gzipped inside the binary (PyInstaller rewrites
Mach-O/PE payloads and would break the manifest); the CLI unpacks them to a
temporary runtime directory and executes them. `plasma status` verifies the
embedded SHA256 manifest; `plasma install` stages the instance, writes config,
installs Sentinel silently, and flips a `current` junction.

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
