# Operations

## Health

```powershell
plasma health
```

| Check | Fails when | Verdict impact |
|---|---|---|
| `events_store` | store is not writable | degraded |
| `whids_service` | expected but not Running | **down** |
| `sysmon_feed` | no Sysmon event within 60 min | **down** |
| `sysmon_service` | Sysmon expected but stopped | **down** |
| `tap_sidecar` | tap binary missing | degraded |
| `sensor_heartbeat` | newest store row older than 24 h | degraded |
| `rdp_hardening_drift` | RDP disabled or security layer drifted | degraded |
| `install_mode` | never — it documents MINIMAL mode | informational |

MINIMAL-mode nodes are not penalized for lacking WHIDS: the sensor list comes
from the install decision recorded in `config.json`.

## Watch — the scheduled sweep

```powershell
plasma watch once                 # one sweep, JSON + exit code
plasma watch loop --every 3600    # long-running; or schedule `watch once`
```

A sweep gathers:

1. the health verdict,
2. drift against the `attest` baseline,
3. **new** WHIDS alert rows since the last sweep (growth-based, so pulled
   rows never re-fire),
4. chain matches over the events tail,
5. canary-file integrity (missing/modified = score 10).

Output: `findings[]`, `top_score`, and a verdict of **clean /
investigate / act now**. `watch-state.json` records each run;
`watch-alerts-state.json` tracks the alert-row watermark.

### Notifications

`<root>/notify.json`:

```json
{
  "channels": [
    {"type": "telegram", "token_env": "PLASMA_TG_TOKEN", "chat_id": "123456789"},
    {"type": "webhook",  "url": "https://hooks.example.com/plasma"}
  ],
  "min_score": 7
}
```

- Secrets are **only** via `token_env`; inline token fields are refused.
- Delivery is gated by `min_score` (default 7).
- Alerts are **throttled by the loudest finding's type**: at most one
  message per finding type per hour, and the throttle window only burns
  when a channel actually accepted the message. A broken webhook retries
  next sweep.
- `plasma notify show` validates the file; `plasma notify test` sends one.

## Store hygiene

```powershell
plasma store stats   --events C:\ProgramData\Plasma\data\events.jsonl
plasma store rotate  --events ... --max-mb 50 --keep 3
plasma store compact --events ...
```

- **rotate** renames the live file to `.1`, shifts `.k → .k+1`, and drops the
  oldest beyond `--keep`. Runs are no-ops below the size limit.
- **compact** drops exact duplicate rows (key-order-insensitive), preserves
  torn/noise lines, and swaps atomically via a temp file.
- **stats** reports row count, size, kind histogram and time span.

The store stays a plain JSONL file — rotation never changes the contract.

## Identity pulls

```powershell
plasma identity pull --events <store> --since 60 [--host NAME]
```

Reads 4624/4625 from the local Security channel, normalizes them, and
appends with dedupe. `--host` labels the rows when the store is shared.

## Drift baselines

```powershell
plasma drift record attest
plasma drift score  attest     # exit 0 clean / 2 drift / 1 collection error
plasma drift list
```

Baselines live under `<root>/drift/`. Score refuses to overwrite a good
baseline with a failed collection.

## Asking questions

```powershell
plasma ask --prompt "critical alerts" --events <store>
plasma ask --prompt "network connections to 203.0.113.9" --events <store>
plasma probe --tool plasma_persistence --events <store>
plasma status --events <store>
```

`status` shows the bundle identity and the probe menu; `probe` runs one
named probe; `ask` lets the on-device model choose the probe. Every answer
is JSON; refusals are structured (`GATE_VERSION 1`), never guesses.

## Observatory (self-knowledge)

```powershell
plasma observe attest
plasma observe sketch
plasma observe edges
plasma observe attackmap
plasma observe pslogs
```

These are read-only witness questions: can the box see its own logons, its
services, its network edges? `attest` includes a **blind check** — a box
that cannot see itself reports that honestly, and fleet correlation turns
it into a `blind_host` finding.

## Canary files

```powershell
plasma canary deploy --root C:\ProgramData\Plasma [--dir D:\Finance]
plasma canary verify --root C:\ProgramData\Plasma   # exit 2 when tripped
plasma canary status --root C:\ProgramData\Plasma
```

Deploy once per node (and on data shares with `--dir`); `watch` checks
them from then on. A tripped canary should be treated as impact — isolate
and snapshot before investigating.

## Scheduling

Task Scheduler (or cron on a desk) runs, at minimum:

```text
*/15 * * * *   plasma whids pull --root "C:\Program Files\Whids" --out <store>
0 * * * *      plasma identity pull --events <store> --since 70
0 */6 * * *    plasma watch once
```

After every `watch`, re-arm the alert watermark by pulling; otherwise the
watchman will (correctly) keep reporting growth.
