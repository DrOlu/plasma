# Troubleshooting

Diagnostics first:

```powershell
plasma health
plasma status --events C:\ProgramData\Plasma\data\events.jsonl
plasma watch once
Get-Service Whids, Sysmon64, TermService, WinRM | Format-Table Name, Status
```

## Health is `down`

| Failed check | What it means | Fix |
|---|---|---|
| `whids_service` | service expected but not Running | `Start-Service Whids`; check `Logs\whids.log` |
| `sysmon_service` | Sysmon missing/stopped | reinstall: `plasma install --force` (repair path) |
| `sysmon_feed` | service runs but no fresh events | check the Sysmon channel; the driver may be stopped |
| `events_store` | store unwritable | permissions on the root; disk space |
| `rdp_hardening_drift` | RDP disabled or security layer changed | see the RDP section below |

`degraded` with `install_mode: MINIMAL` is **expected** on boxes provisioned
without WHIDS — identity and the tap carry detection there.

### WHIDS stuck in StartPending

Seen in the field on Server 2022 with WHIDS 1.7.0: the service registers,
starts, and never reaches Running (deterministic init hang).

v1.4.0 handles it in three layers:

1. **Narrow channel list** — `channels = [...four explicit logs]` instead of
   `"all"`; subscribing to every channel on the host is the known trigger.
2. **Supervised start** — the installer waits up to
   `PLASMA_WHIDS_START_TIMEOUT` (default 60s) for `Running`; if the service
   is stuck in `StartPending`, it is force-stopped and the node is recorded
   as degraded/skipped instead of leaving a hung service behind.
3. **Diagnosis** — `plasma whids diagnose` reports service state, start
   mode, binary/config presence, channel readability, recent SCM errors and
   the tail of `whids.log`, with the likely cause stated as data.
4. **Watchdog (1.6.0)** — the installer registers the
   **PlasmaWhidsWatchdog** task (SYSTEM, every two minutes), which runs
   `plasma whids ensure`. That command is a no-op while Running; for
   `StartPending` it force-stops and starts the service (Start-Service
   alone cannot recover the hang); for `Stopped` it starts it. Actions are
   appended to `C:\ProgramData\Plasma\logs\whids-watchdog.log`.

```powershell
plasma whids ensure          # heal now, print what it did
plasma whids diagnose        # includes "watchdog": {"present": true}
```

Interim posture on an affected node: identity + tap carry detection.

## WinRM / management access

| Symptom | Cause | Fix |
|---|---|---|
| Port 5985 closed from outside | WinRM listener not configured | `winrm quickconfig -force` (locally) |
| `InvalidCredentials` | account disabled or password mismatch | `Enable-LocalUser`, reset password |
| Logon fails although credentials are right | `SeNetworkLogonRight` stripped | restore `*S-1-5-11,*S-1-5-32-544,*S-1-5-9` via `secedit`, reboot |
| RDP client: "NTLM authentication was blocked" (0x3707) | hardening set `RestrictReceivingNTLMTraffic=2` | set to `0` under `Lsa\MSV1_0`, reboot |
| Fleet pull works locally, not remotely | inventory missing `transport: "winrm"` | add it (file transport reads the desk's disk!) |

## RDP

Classic failure chain on a hardened box:

1. **No server certificate** — Schannel 36886 "no suitable default server
   credential". The RDP auto-cert path was broken by hardening.
2. **Key access failure** — Schannel 36870 `0x8009030D` while loading the
   private key. On a box with **LSA protection (`RunAsPPL=1`)**, a CNG key
   created by a tool can be unreadable to LSASS.
3. **Fix that worked in the field**:
   - create a cert with the legacy provider
     (`Microsoft Enhanced Cryptographic Provider v1.0`), so the key lives in
     `C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys` with the machine ACL;
   - publish it to the **Remote Desktop** store and bind its SHA-1
     thumbprint to `HKLM\SYSTEM\CurrentControlSet\Control\Terminal
     Server\WinStations\RDP-Tcp\SSLCertificateSHA1Hash`;
   - align `RunAsPPL` with the estate policy (if RDP must work with a CNG
     key, PPL off is the proven combination);
   - full reboot (TermService restart alone may not re-init the listener).
4. Verify from the desk: X.224 negotiation → TLS handshake completes and the
   presented certificate thumbprint equals the bound one.

## Detection looks quiet

- `plasma whids status --root "C:\Program Files\Whids"` — is WHIDS writing?
- `plasma store stats --events <store>` — rows growing? which kinds?
- `plasma coverage` — is the technique you expect actually watched?
- `plasma chain score --events <store>` — chains need the *sequence*;
  a single alert is not a chain.
- Tap rules need `plasma tap run` to be alive; it is deliberately
  on-demand, not a service.

## Update refused

```json
{"stage": "signature", "ok": false, "error": "signer thumbprint mismatch"}
```

The downloaded exe is not signed by a pinned certificate. Do **not** use
`--allow-unsigned` outside development. Check what the release actually
carries:

```powershell
Get-AuthenticodeSignature .\downloaded.exe | Select Status, SignerCertificate
```

After a legitimate signer rotation, set `PLASMA_SIGNER_THUMBPRINTS` or ship
a build with the new default pin.

## Fleet correlation errors

| Message | Meaning |
|---|---|
| `file not found: C:\...` | wrong transport — the desk tried to read a Windows path locally |
| `winrm failed: ...` | reachability, credentials, or NTLM policy |
| `no such case` | run `fleet pull` first |
| odd `lateral_hop` windows | check timestamps have `Z`/offsets; naive rows are treated as UTC |

## PowerShell 5.1 quirks Plasma works around

- **BOM** — PowerShell-written JSON can carry a UTF-8 BOM; Plasma reads
  configs with `utf-8-sig`.
- **`-Raw` + `-Tail`** cannot be combined; the fleet transport reads bytes
  via base64 and falls back to line mode.
- **Codepage mojibake** — subprocess output is decoded as UTF-8 with
  replacement; non-ASCII never crashes an apply.
- **Junctions** — PS 5.1 `Remove-Item` can hang on reparse points; Plasma
  uses `cmd /c rmdir` and handles dangling junctions explicitly.

## DTrace

```powershell
plasma trace check        # installed? enabled? which build?
plasma trace selftest     # compile-only check of the reviewed scripts
plasma trace provision    # install the Microsoft package (direct download,
                          # no winget needed) + bcdedit /set dtrace on
```

`enabled: false` means the boot setting is off — tracing needs
`bcdedit /set dtrace on` and a restart. `available: false` means the
package is missing; `provision` downloads the official MSI directly when
winget is absent (the default on Server 2022) and reports
`reboot_required: true`.

Microsoft's current package is labelled 2.0 on the Download Center, but the
MSI still reports ProductVersion 1.1.0 and the tool prints
`Sun D 1.13.1`. That is expected: Plasma treats installed + enabled as
ready rather than chasing a version string.

If DTrace refuses to start on a modern host, verify virtualization-based
security (VBS) is enabled; Server 2025 ships the built-in build. A driver
that is loaded but exposes no providers usually needs one clean restart
after the MSI.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success / clean |
| 1 | data or input error (bad inventory, missing file, collection error) |
| 2 | refused / attention (update signer mismatch, drift found, update available) |
| 3 | execution failed (actuate payload/verification, required WHIDS missing) |
