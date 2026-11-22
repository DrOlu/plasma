# Plugins

Plasma plugins are **processes with a manifest**, not Python imports. Sysmon,
WHIDS, the ETW tap and DTrace already work this way: an external component
runs, emits a bounded record stream, and Plasma validates and normalises it.
The plugin ABI makes that pattern available to anything you write or buy.

A plugin may contribute one of four things:

| Kind | Emits | Runs |
|---|---|---|
| `sensor` | PlasmaEvents | `plasma plugin run <name>` on a cadence |
| `detector` | findings over a bounded event tail | `plasma plugin run <name>` |
| `responder` | named actions with preview/apply/rollback | `plasma plugin act` |
| `exporter` | nothing (outbound) | reserved for the export adapters |

They can be written in any language: a native binary, Python, or PowerShell.
The wire format is newline-delimited JSON.

## Install and run

```powershell
plasma plugin new acme-bridge --kind sensor --out C:\build
plasma plugin keygen --out keys
plasma plugin sign --plugin C:\build\acme-bridge --key keys\plugin-private.pem
plasma plugin install C:\build\acme-bridge `
  --pubkey keys\plugin-public.pem --enable
plasma plugin run acme-bridge --max-events 100
plasma plugin verify acme-bridge --pubkey keys\plugin-public.pem
```

Nothing is auto-enabled. `install` verifies the manifest, entrypoint, payload
digest and Ed25519 signature (unless `--allow-unsigned` is explicitly used),
copies the payload to `<root>\plugins\<name>` and records it in
`<root>\plugins\registry.json`.

## Manifest

`plugin.json` follows
[`schemas/plugin-manifest.schema.json`](schemas/plugin-manifest.schema.json):

```json
{
  "api_version": "1.0",
  "name": "acme-bridge",
  "version": "0.3.1",
  "kind": "sensor",
  "description": "Acme agent events",
  "entrypoint": "acme-bridge.exe",
  "runtime": "native",
  "protocol": "ndjson-stdio",
  "capabilities": ["event.process", "event.network"],
  "permissions": {
    "filesystem": ["C:\\ProgramData\\Acme\\**"],
    "network": ["https://acme.example/*"]
  },
  "limits": {
    "max_events": 1000,
    "max_line_bytes": 65536,
    "timeout_seconds": 60
  },
  "health": { "command": ["acme-bridge.exe", "--health"] },
  "min_core": "1.28.0"
}
```

`entrypoint` must stay inside the plugin directory. `limits` are enforced by
the host, not trusted from the plugin.

## Records

One JSON object per line:

```json
{"v":1,"type":"event","plugin":"acme-bridge","seq":1,"event":{
  "ts":"2026-11-22T15:00:00Z","kind":"process","process":"cmd.exe",
  "parent":"explorer.exe","pid":1234,"score":0.2
}}
{"v":1,"type":"finding","plugin":"acme-detector","finding":{
  "description":"encoded PowerShell","score":0.8,
  "technique":"T1059.001","evidence":["2026-11-22T15:00:00Z"]
}}
{"v":1,"type":"health","status":"ok"}
```

The core:

- rejects records over `max_line_bytes`, unknown envelope versions and
  unknown types;
- maps known fields onto the strict PlasmaEvent contract and puts unknown
  fields in a bounded `attributes` map;
- stamps `source=plugin:<name>`, `plugin=<name>@<version>` and the host;
- clamps scores to 0–1 and validates technique IDs;
- dedupes against the tail and appends only fresh records;
- quarantines invalid lines and stops a run after ten bad records.

Plugins never write `events.jsonl` directly. That is what stops a plugin from
forging another source or corrupting the diary.

## Detectors

A detector is a process invoked with:

```text
<entrypoint> --events <store> --max-rows <n> [--since <iso>]
```

It prints `finding` envelopes. Findings become `kind=alert` rows with
`alert_id=plugin:<name>`, the technique, a clamped score and bounded evidence.
The runner enforces a timeout and rejects over-scoring.

Rule packs can be validated with the existing harness:

```powershell
plasma detect validate --rules C:\plugins\acme\rules\pack.gen
```

## Responders

A responder declares actions in `actions.json`:

```json
{"actions":[{
  "name": "acme.restart_agent",
  "description": "restart the Acme agent",
  "args_schema": {"type":"object","properties":{"service":{"type":"string"}},"required":["service"]},
  "preview": ["acme-cli","restart","--dry-run","{{service}}"],
  "apply":   ["acme-cli","restart","{{service}}"],
  "verify":  ["acme-cli","status","{{service}}"],
  "rollback":["acme-cli","start","{{service}}"],
  "reversible": true
}]}
```

`plasma plugin act` without `--apply` renders the exact argv and returns a
plan id. Applying requires that id and a reason, checks the kill switch and
the plugin's enabled state, runs only the declared argv (no shell), verifies,
and journals the result with its rollback argv. `plasma plugin undo` replays
that rollback.

Path arguments are checked against `permissions.filesystem`. A plugin cannot
write outside the roots it declared.

## Ingest and export

Inbound adapters:

```powershell
plasma ingest jsonl .\events.jsonl --max-events 500
plasma ingest evtx --channel Microsoft-Windows-Sysmon/Operational --since 15
plasma ingest webhook --port 8787 --secret-env PLASMA_INGEST_SECRET --once
```

The webhook receiver requires `X-Plasma-Signature: sha256=<hmac>` when a
secret is configured, caps bodies at 2 MiB and validates every record.

Outbound:

```powershell
plasma export webhook --url https://siem.example/ingest --secret-env PLASMA_EXPORT_SECRET --since 1h
plasma export syslog --host 192.0.2.10 --port 514 --protocol udp --since 1h
```

Exports are batched and bounded. A failed sink spools the unsent tail under
`<root>\export-spool` with a hard line cap — never an unbounded queue.

## Security model

- Signed manifests and payloads; pin the publisher key with `--pubkey`.
- Install is explicit; enable is separate; `plugin disable` is the quick
  containment.
- Plugins cannot modify config, rules, baselines or services; the registry
  and store are core-owned.
- Responder actions are plan-gated, reason-bearing, kill-switch aware and
  reversible when declared.
- Runtime limits: line size, event cap, timeout, output cap; process
  isolation is a child process with its own working directory.
- Secrets are injected as environment variables at start and never written
  to the manifest or logs.

The remaining hardening step is stronger OS isolation (Job Objects and
AppContainer) for untrusted plugins; the current release enforces process
separation, limits and signature verification.

## Samples

`examples/plugins/` contains a sensor, a detector and a responder scaffolded
by `plasma plugin new`, used by the unit tests and the estate drill.

## Lifecycle

| State | Meaning | How it changes |
|---|---|---|
| installed | verified and copied, not enabled | `plugin install` |
| enabled | may run | `plugin enable` |
| disabled | `plugin run` refuses unless `--force` | `plugin disable` |
| running | a bounded run is in flight | `plugin run` |
| ok | last run completed inside its caps | registry `last_result` |
| quarantined | ten invalid records stopped the run | fix the emitter, then run again |
| timeout | the manifest deadline was reached | bound the plugin or raise the limit |
| broken | manifest or entrypoint no longer validates | reinstall or remove |
| removed | payload and registry entry deleted | `plugin remove` |

`plugin list` reports the state, signature, digest, last run and last result.
`plugin health` runs the manifest health command; a plugin without one reports
its registry state.

## Manifest reference

| Field | Required | Meaning |
|---|---|---|
| `api_version` | yes | `1.0`; unknown majors are refused |
| `name` | yes | lowercase id, 1–64 chars |
| `version` | yes | semver-like |
| `kind` | yes | `sensor`, `detector`, `responder`, `exporter` |
| `entrypoint` | yes | relative path inside the plugin directory |
| `runtime` | yes | `native`, `python`, `powershell` |
| `protocol` | yes | `ndjson-stdio` |
| `description` | no | shown by `plugin list` |
| `capabilities` | no | declared event families |
| `permissions` | no | `filesystem`, `registry`, `network` lists |
| `limits` | no | `max_events`, `max_line_bytes` (≤ 65536), `timeout_seconds`, `max_score` |
| `health` | no | `{ "command": [...] }` |
| `actions` | responders | path to `actions.json` |
| `rules` | detectors | path to a declarative pack |
| `min_core` | no | refuse an older core |

## Record reference

| Type | Required | Notes |
|---|---|---|
| `event` | `event` object with a timestamp or a usable signal | mapped onto the strict PlasmaEvent contract |
| `finding` | `description`, `score` (0–1) | becomes a plugin alert; `technique` and `evidence` optional |
| `health` | `status` | surfaced in the run summary |
| `log` | any | ignored; stderr is the log |

Every record needs `v: 1` and `type`. A record larger than `max_line_bytes`,
an unknown version or an unknown type is rejected and counted.

## Responder reference

Actions are argv arrays with `{{placeholder}}` substitution:

- `preview` — required; rendered and returned by a dry-run.
- `apply` — required; runs only after a matching plan id and reason.
- `verify` — optional; runs after apply and must exit 0.
- `rollback` — optional; required for `reversible: true`.
- `args_schema` — JSON Schema subset: object, string/integer/boolean, required,
  no unknown keys.
- `permissions.filesystem` — path arguments must resolve under one of these
  roots; `${root}` expands to the Plasma root.

`--args-file` is the reliable way to pass JSON on Windows. Plans expire after
24 hours. Every apply and undo is a JSONL journal entry with the argv, result,
verify result and rollback argv.

## Ingest and export reference

| Adapter | Direction | Caps |
|---|---|---|
| `ingest jsonl` | inbound file | `--max-events`, validation, dedupe |
| `ingest evtx` | inbound channel | `--since` minutes, `--max-events` |
| `ingest webhook` | inbound HTTP | 2 MiB body, HMAC, `--max-events`, `--seconds`/`--once` |
| `export webhook` | outbound | batches, retries, 5,000-line spool |
| `export syslog` | outbound UDP/TCP | `--max-events`, 8 KiB line cap |

Export URLs must be `http` or `https`; other schemes are refused before any
request.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `install: refusing unsigned` | no `SIGNATURE` or wrong key | sign it, or `--allow-unsigned` in a lab |
| `verify` exits 2 | payload changed after install | review, then `install --force` |
| `run: quarantined` | ten invalid records | read `<root>\logs\plugin-<name>.log` |
| `run: timeout` | manifest deadline | raise `limits.timeout_seconds` or bound the plugin |
| `act: outside permitted roots` | path escaped permissions | use a declared root |
| `act: kill switch is engaged` | switch on | `plasma control killswitch status` |
| webhook 401 | bad HMAC | sign the body with the configured secret |
| webhook 413 | body over 2 MiB | batch smaller |

## Versioning

`api_version` is a major.minor contract. The core supports the current major
and refuses unknown ones; `min_core` lets a plugin require a newer Plasma.
Record fields are additive: unknown event keys land in `attributes`, unknown
top-level record types are rejected. Plugin-defined `kind` values are not
consumed by chains or profiles until registered in core.

## Testing a plugin

```powershell
plasma plugin new acme-test --kind sensor --out C:\build
# implement, then:
plasma plugin sign --plugin C:\build\acme-test --key keys\plugin-private.pem
plasma plugin install C:\build\acme-test --pubkey keys\plugin-public.pem --enable
plasma plugin run acme-test --events C:\temp\events.jsonl --max-events 3
plasma query --events C:\temp\events.jsonl --source plugin:acme-test
```

For responders, preview first and inspect the exact argv; apply against a
disposable target; undo and confirm the journal. For detectors, seed a store
with a known row and check `alert_id=plugin:<name>`.

## Distribution

Ship the plugin directory, its `SIGNATURE`, and the publisher's public key.
Install with a pinned key from the same GPO/SCCM/Intune workflow that installs
Plasma. Keep the private key offline. Treat a plugin update as a new signed
artifact: verify, install, then enable.
