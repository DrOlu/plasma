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

## Standalone executable

`plasma` ships as a one-file executable per platform (PyInstaller), with
Python and Pydantic embedded — no interpreter required on the host. The frozen
binary re-enters itself through a hidden `_bridge` mode to execute the bundle's
`bridge.py`, so `ask`, `probe` and `status` work identically to the Python
install. Release assets: `plasma-<version>-linux-x86_64` and
`plasma-<version>-windows-x86_64.exe`; the same binaries also live inside the
bundle under `bin/`.

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
