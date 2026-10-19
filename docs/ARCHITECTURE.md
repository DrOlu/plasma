# Plasma architecture

```
┌─ SENSOR LAYER ──────────────────────────────────────────────┐
│ WHIDS agent (required)                                      │
│   - Sysmon/ETW telemetry, gene detection rules              │
│   - artifact collection driven by detection, ATT&CK mapping │
│   - response actions (kill/dump/quarantine) via its rules   │
│ Sysmon (required)     kernel telemetry WHIDS depends on     │
│ Sealighter (optional) on-demand ETW/WPP deep traces         │
└──────────────────────────┬──────────────────────────────────┘
                           ▼ normalize
┌─ LOCAL STORE ───────────────────────────────────────────────┐
│ events.jsonl (normalized schema, rolling retention)         │
└──────────────────────────┬──────────────────────────────────┘
                           ▼ read-only probes
┌─ FROZEN INSTANCE ───────────────────────────────────────────┐
│ models.py            strict Pydantic event contract         │
│ needle_menu.json     10 probes, triggers, caged arguments   │
│ bridge.py/.ps1       executors (Python or PowerShell-only)  │
│ graph_edges.json     relationship declaration               │
│ graph_bridge.py      overview / neighbors traversal         │
└──────────────────────────┬──────────────────────────────────┘
                           ▼ selection
┌─ ENGINE ────────────────────────────────────────────────────┐
│ neuralOS 121M tool-calling model (~35 MB, CPU, offline)     │
│ selects one probe + arguments; executes nothing             │
└──────────────────────────┬──────────────────────────────────┘
                           ▼ advisory output
┌─ RESPONSE BOUNDARY ─────────────────────────────────────────┐
│ Deterministic WHIDS rules may act (kill/dump/quarantine).   │
│ Model output is advisory; any model-suggested action is     │
│ human-approved. The model cannot kill, block or isolate.    │
└─────────────────────────────────────────────────────────────┘
```

## Build once, deploy many

Build phases run where Python exists: profile → model → generate → verify.
The bundle is versioned and immutable; `manifest.json` records SHA256 for
every file. Endpoints receive the same artifacts; the local event store is the
only per-host data.

## Bundle contents

```
instance/          frozen neuralOS artifact
packaging/         install.ps1, verify.ps1, config.example.json
sensors/           pins + whids payload + whids.toml + plasma-iocs.gen
engines/<platform>/  needle binary + needle3.cact + library/header
bin/               Plasma one-file executable (linux/windows/macos)
manifest.json      SHA256 of every file + sensor requirements
```

The WHIDS payload is AGPL-3.0-licensed, covered by the bundle manifest, and
installed by the installer as a service. Sysmon is installed from the official
package (never redistributed); Sealighter is on-demand only.

## Runtimes

| Endpoint | Selection | Execution |
|---|---|---|
| Windows + Python | `needle.exe` | `bridge.py` (Pydantic at runtime) |
| Windows, no Python | `needle.exe` | `bridge.ps1` (generated shape checks) |
| Linux | `needle` | `bridge.py` |
| macOS | `needle` | `bridge.py` |

## Verification contract

1. Coverage: ≥95% of local records parse (gate enforced by `verify.ps1`).
2. Selection: three phrasings select the intended probe.
3. Truth: one relayed count equals a direct count of the source.
4. Integrity: every bundle file matches its manifest hash.

Results are recorded in `instance/verification.txt` at build time and
re-checked at install time.
