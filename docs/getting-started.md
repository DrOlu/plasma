# Getting started

## Requirements

| Requirement | Notes |
|---|---|
| Windows | Server 2016+ or Windows 10/11, x64. PowerShell 5.1 is assumed. |
| Privileges | Administrator (sensors, services, ETW, firewall). |
| Network | Optional. With internet, the installer provisions Sysmon automatically; without it, Plasma runs a reduced mode. |
| Disk | ~200 MB for the app plus bounded event stores. |
| Python | None at runtime — the release is a single self-contained exe. |

## Install

```powershell
.\plasma-<version>-windows-x64.exe install
```

The installer is **intelligent** — it inspects the box and picks a mode:

| Observed state | Decision | Result |
|---|---|---|
| No WHIDS, no Sysmon, internet | `full` | Sysmon downloaded (EULA accepted), WHIDS registered and started |
| WHIDS service present, Sysmon missing | `full` + **repair** | Sysmon installed, WHIDS (re)started — the broken-install case |
| No internet / `--skip-whids` | `skipped` (MINIMAL, degraded) | Identity + ETW tap carry detection |
| Both present | `already_present` | Installer verifies and leaves services alone |

Always preview first:

```powershell
.\plasma-<version>-windows-x64.exe install --dry-run
```

Useful flags:

```powershell
plasma install --force                 # replace the current install
plasma install --root D:\Plasma        # custom root
plasma install --skip-whids            # force MINIMAL mode
plasma install --skip-sysmon-check     # do not attempt the Sysmon download
plasma install --require-whids         # fail (exit 3) instead of degrading
```

The installer:

1. verifies the embedded payload against its SHA-256 manifest;
2. decides FULL or MINIMAL from the box's actual state;
3. installs Sysmon when needed (official package, EULA accepted non-interactively);
4. provisions WHIDS in **detect-only** mode and registers the service;
5. writes `config.json` (sensors, paths, install mode);
6. flips `instances\current` to the new version atomically;
7. reports the whole decision as JSON.

## First checks

```powershell
plasma health          # verdict: ok | degraded | down, with per-check detail
plasma status --events C:\ProgramData\Plasma\data\events.jsonl
```

Healthy output (FULL node):

```json
{"status": "ok", "failed": [], "checks": [
  {"check": "events_store", "ok": true},
  {"check": "whids_service", "ok": true, "detail": "service Running"},
  {"check": "sysmon_feed", "ok": true, "detail": "newest Sysmon event 0.0 min old"},
  {"check": "sysmon_service", "ok": true, "detail": "service Running"},
  {"check": "tap_sidecar", "ok": true},
  {"check": "sensor_heartbeat", "ok": true, "detail": "newest event 2 min old"}
]}
```

A MINIMAL node reports `"install_mode": "MINIMAL mode — expected reduced
coverage"` and is **not** penalized for lacking WHIDS.

## Collect something real

```powershell
# logons from the Security channel into the store
plasma identity pull --events C:\ProgramData\Plasma\data\events.jsonl --since 60

# alerts WHIDS already wrote — normalize them into the same store
plasma whids pull --root "C:\Program Files\Whids" --out C:\ProgramData\Plasma\data\events.jsonl

# a bounded live ETW window (no service, no persistence)
plasma tap run --providers powershell,dns --for 10s --max-matches 200

# every auto-start location, with signature status
plasma deep persistence --json-out C:\ProgramData\Plasma\deep-persistence.json
```

## Ask questions

```powershell
plasma ask --prompt "critical alerts" --events C:\ProgramData\Plasma\data\events.jsonl
plasma probe --tool plasma_recent --events C:\ProgramData\Plasma\data\events.jsonl
plasma observe attest      # can this box even see itself?
plasma drift record attest # record today's truth as the baseline
```

## Schedule the watchman

```powershell
plasma watch once     # health + drift + new alerts + chains → verdict
```

Exit codes: `0` clean, non-zero when findings exist — ideal for Task
Scheduler. Configure Telegram/webhook delivery in
`C:\ProgramData\Plasma\notify.json` (see [Operations](operations.md)).

## Upgrade

```powershell
plasma update check     # anonymous; exit 0 = current, 2 = update available
plasma update apply     # downloads, verifies SHA-256 *and* the signer, installs
```

From 1.2.0 onward the downloaded exe must be signed by a pinned certificate
or the update is refused before execution.
