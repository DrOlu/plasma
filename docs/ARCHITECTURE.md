# Plasma architecture

```
┌─ SENSOR LAYER ──────────────────────────────────────────────┐
│ Sentinel service (required)                                 │
│   - 10 ETW providers, behavioral rules, weighted correlation│
│   - offline ML scoring, ATT&CK mapping                      │
│   - deterministic Tier-1 response (process-tree kill)       │
│ Sysmon (optional)     kernel-level telemetry baseline       │
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
│ Deterministic policy (Sentinel Tier-1) may act.             │
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
sensors/           pins + SentinelSetup-3.3.1.exe + LICENSE + SHA256SUMS
engines/<platform>/  needle binary + needle3.cact + library/header
bin/               Plasma one-file executable (linux/windows/macos)
manifest.json      SHA256 of every file + sensor requirements
```

The Sentinel payload is MIT-licensed, checksum-verified at build and install
time, and executed silently by the installer. Sysmon is never redistributed;
Sealighter is on-demand only.

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
