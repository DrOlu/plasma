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
| `canary_integrity` | a deployed canary is missing or modified | degraded |
| `blind_spot_accounting` | never — it names known gaps | informational |
| `install_mode` | never — it documents MINIMAL mode | informational |

MINIMAL-mode nodes are not penalized for lacking WHIDS: the sensor list comes
from the install decision recorded in `config.json`.

The verdict now includes a `blind_spots[]` list: skipped sensors, disabled
Sysmon event IDs, failed feeds, an undeployed canary, and the coverage
engine's named ATT&CK gaps. A blind spot is not a service failure, but it is
never silent either.

## Enforcement posture

```powershell
plasma prevent posture
```

Inventory of the signed Windows controls behind prevention: active WDAC
policy files, Controlled Folder Access, Network Protection, the vulnerable
driver blocklist, ASR rule counts, real-time protection and tamper
protection. Each row says whether Plasma can apply it and gives the preview
command. WDAC stays read-only; CFA, Network Protection and the driver
blocklist are opt-in and plan-gated with rollback.

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

## Enforcement and prevention

```powershell
plasma protect status                  # armed? containment + prevention + protected
plasma protect protected               # what the response layer refuses to touch
plasma protect disarm --reason "change window"
plasma protect arm
plasma enforce status                  # policy, journal counts, kill switch
plasma enforce run                     # dry-run proposals
plasma enforce run --apply             # policy still gates every action
plasma enforce pending
plasma enforce approve --id 4 --apply
plasma prevent status                  # read-only posture
plasma prevent rollback --id 7 --apply # undo an applied prevention control
```

Containment ships armed but narrow: `snapshot` + `kill_process` at score
9+, 2 actions per run, 30-minute cooldown. Isolation and every other action
require approval. The installer registers `PlasmaWatch`, which runs
`watch once --enforce` at boot and every 5 minutes; `--no-autoprotect`
removes it and installs the old dry-run posture. `PlasmaWatch`,
`PlasmaWhidsWatchdog` and `PlasmaCanaryShield` carry both an `AtStartup`
trigger and `StartWhenAvailable`, so a reboot or a missed timer run is
picked up immediately. `PlasmaUpdate` deliberately keeps its daily
maintenance-window trigger and does not run at boot.

`enforce-journal.jsonl` records every decision (including refusals and
cooldowns); `prevent-journal.jsonl` records every control change with its
undo recipe. Prevention backups live in `prevent-backups/`. Neither file is
rotated automatically — they are audit records.

## Plugins

Plugins are installed once, verified, enabled explicitly and then run on a
cadence or on demand.

```powershell
plasma plugin list
plasma plugin verify acme --pubkey acme.pem
plasma plugin health acme
plasma plugin run acme --max-events 100
plasma plugin run acme-detector --since 1h
plasma plugin disable acme
```

`install` verifies the manifest, entrypoint, payload digest and Ed25519
signature, then copies the payload under `<root>\plugins\<name>`; it does not
enable it. `disable` is the quick containment. Sensor runs enforce the
manifest's `max_events`, `max_line_bytes` and `timeout_seconds`, log stderr to
`<root>\logs\plugin-<name>.log`, and quarantine a plugin after ten invalid
records.

**Ingest and export** are bounded adapters, not collectors:

```powershell
plasma ingest jsonl .\events.jsonl --max-events 500
plasma ingest evtx --channel System --since 15 --max-events 200
plasma ingest webhook --port 8787 --secret-env PLASMA_INGEST_SECRET --once
plasma export webhook --url https://siem.example/ingest --since 1h
plasma export syslog --host 192.0.2.10 --port 514 --protocol udp
```

A failed export spools the unsent tail under `<root>\export-spool` with a
5,000-line cap. Drain and retry; do not raise the cap indefinitely.

**Responder actions** stay plan-gated:

```powershell
plasma plugin actions
plasma plugin act acme.restart_agent --args-file args.json
plasma plugin act acme.restart_agent --args-file args.json --apply --plan <id> --reason "change window"
plasma plugin undo <journal-id> --reason "rollback"
```

Apply checks the kill switch and the enabled flag, runs only the declared argv,
verifies and journals the rollback. Paths must sit under the plugin's declared
filesystem roots.

## Estate ledger

The estate ledger is the scheduled, estate-wide counterpart to `fleet pull`.
Each host reduces its recent store to a hash-sealed count ledger; the desk merges
the newest ledger per host and correlates identity fan-out and stale hosts.

```powershell
plasma estate sync --inventory inventory.json --out-dir C:\PlasmaEstate --interval 300 --loop
plasma estate findings --ledger C:\PlasmaEstate\estate.json --threshold 5
plasma estate status   --ledger C:\PlasmaEstate\estate.json
```

Run it on the same cadence as `watch` (typically 5–15 minutes). Check
`failures` in each sync summary: a host that cannot build a ledger is a
coverage problem, not a quiet host. A `stale_host` finding means the desk has
not refreshed that host inside `--max-age`.

Check the coverage findings as well. `estate_identity_blind` (9) means the
identity pull failed or stopped inside the window; `estate_identity_unverified`
(7) means other telemetry flowed but there was no identity evidence at all.
Neither is a clean result. `estate_no_telemetry` (8) means a fresh ledger with
zero rows. `estate_kerberos_blind` (8) is role-aware: only hosts marked
`--role dc` are expected to produce 4768/4769. `estate_identity_stale` (8)
means the pull marker is older than `--max-identity-age`. A score-7 user fan-out is a
same-name pattern until a shared source address proves otherwise; escalate to
`plasma fleet pull` for the hosts involved before acting.

Keep `estate.json` and `hosts/` on the desk, not on endpoints. Replace-in-place
means the view is current, not historical — copy a snapshot into a case
directory if it must be retained. See [Estate edge ledger](estate-ledger.md).

## Updates

```powershell
plasma update auto --check-only   # exit 2 when an update is available
plasma update auto                # apply if due
plasma update auto --force        # reinstall even if the version matches
plasma update auto --ring canary  # override the configured ring
plasma update check
plasma update apply
plasma rollback
```

The installer registers `PlasmaUpdate`, a daily SYSTEM task with a random
minute inside the 02:00–05:00 maintenance window. It applies **signed**
releases only, through the same SHA256 + Authenticode + install + rotate
path as `update apply`. `broad` hosts wait 24 hours after publication;
`canary` hosts update first; `rollback` hosts never auto-update. The kill
switch pauses updates. A host's explicit ring assignment wins over the
configured default. Around the swap Plasma stops the tasks that hold the
binary (`PlasmaServe`, `PlasmaWatch`, `PlasmaWhidsWatchdog`,
`PlasmaIdentityPull`), stops every other `plasma*` process so no child can
keep the old image on port 9999, retries a locked image, preserves a stale
`.old` backup, restores the previous binary if the swap fails, and restarts
the tasks afterwards — so `PlasmaServe` serves the new version. A
serve-launched update skips `PlasmaServe` to avoid killing its own process
tree. The previous binary is kept, so `plasma rollback` still restores it.
`update-journal.jsonl` and `update-state.json` record every attempt.

`--no-autoupdate` on install removes the task and disables automatic
updates. See [Updates and signing](update-signing.md).

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
plasma identity pull --events <store> --since 60 [--host NAME] \
                    [--ids 4624,4625,4688,4768,4769,4776] [--max-events 2000]
```

Reads the Security channel from the local host, normalizes auth and process
records onto the event contract, and appends with dedupe. `--host` labels the
rows when the store is shared. Kerberos IDs are only meaningful on a domain
controller; on a member server they return zero rows by design.

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

## Canaries and tokens

```powershell
plasma canary deploy --root C:\ProgramData\Plasma [--dir D:\Finance]
plasma canary verify --root C:\ProgramData\Plasma   # exit 2 when tripped
plasma canary status --root C:\ProgramData\Plasma
plasma canary token create --root C:\ProgramData\Plasma --kind dns --domain assets.internal
plasma canary sysmon --root C:\ProgramData\Plasma --apply
plasma canary token create --root C:\ProgramData\Plasma --kind http --base-url http://collector:8088
plasma canary serve --root C:\ProgramData\Plasma --host 127.0.0.1 --port 8088
plasma canary collect --root C:\ProgramData\Plasma
plasma canary hits --root C:\ProgramData\Plasma
```

Deploy file canaries once per node (and on data shares with `--dir`). The
default layout is randomized and the content is a valid document, so the
decoy does not announce itself. `watch` verifies them from then on.

DNS tokens need a narrow Sysmon include: run `canary sysmon --apply` after
creating them. It writes Plasma's baseline plus the token include and
replaces the current Sysmon config, so review a custom config first. It logs
only queries ending in a registered token suffix; ordinary DNS traffic stays
out of the channel. HTTP tokens point at one
local collector; bind it to loopback or a management VLAN, never the
internet. Hits are appended to the event store by `watch` or `canary
collect`, and deduplicated across sweeps.

Add canary accounts to `config.json`:

```json
{"canary": {"accounts": ["svc-print-archive"]}}
```

A tripped canary is evidence. Snapshot and isolate before investigating;
the enforcement policy keeps `isolate_host` behind approval.

## Memory scanning

```powershell
plasma memory status
plasma memory scan --pid 4832
plasma memory scan --pname powershell.exe,rundll32.exe --deep
plasma memory scan --all --timeout 120
plasma memory list
```

HollowsHunter/PE-sieve is a pinned, on-demand probe for in-memory implants.
Target a PID or a small name set; `--all` is explicit. No dumps are written
by default. `--dump` is local, explicit and refused with `--all`. Findings
land in the event store as `source="memory"` alerts; a clean scan is a
point-in-time result, not proof of innocence.

## Interception

```powershell
plasma intercept status
plasma intercept rules add --file rules.json
plasma intercept evaluate --events C:\ProgramData\Plasma\data\events.jsonl
plasma intercept protect-canary
plasma intercept protect-canary --apply --plan 7 --reason "canary protection"
plasma intercept apply block-test-net --apply --plan 12 --reason "IR-42"
plasma intercept rollback --id 12 --apply --plan 15 --reason "test complete"
```

Shadow evaluation reports would-block decisions without changing the host.
Canary protection adds an NTFS deny ACE; normal Administrator tokens may
not hold `SeSecurityPrivilege`, so the audit rule can be skipped while the
deny still applies. Firewall rules are outbound blocks by destination.
Every apply is dry-run first, single-use plan-bound, journaled and
reversible.

## Scheduling

Task Scheduler (or cron on a desk) runs, at minimum:

```text
*/15 * * * *   plasma whids pull --root "C:\Program Files\Whids" --out <store>
0 * * * *      plasma identity pull --events <store> --since 70
0 */6 * * *    plasma watch once
```

After every `watch`, re-arm the alert watermark by pulling; otherwise the
watchman will (correctly) keep reporting growth.
