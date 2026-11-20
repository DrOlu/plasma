# Memory scanning

File and process telemetry can tell you that a process started. It cannot
tell you what was later written into that process. `plasma memory scan`
covers that gap with HollowsHunter, the PE-sieve-based user-mode scanner
for hollowed or replaced PEs, reflective DLLs, shellcode, inline hooks and
in-memory patches.

It is an **on-demand probe**, not a standing service. No driver, no cloud
and no automatic memory lake.

## Scan targets

```powershell
plasma memory scan --pid 4832
plasma memory scan --pname powershell.exe,rundll32.exe
plasma memory scan --pid 4832 --deep
plasma memory scan --all --timeout 120
```

`--all` is explicit. Prefer a PID or a small name set: a full scan is slow,
noisy and can be evaded between scans.

`--deep` adds `--shellc` and thread-stack scanning. The default scan is
targeted and bounded by `--timeout` (default 300s).

## Reports and events

Each scan gets a directory under `<root>/memory/<timestamp>/` containing:

```text
stdout.txt       scanner output
stderr.txt       scanner errors
report.json      normalized JSON payload when present
meta.json        argv, target, elapsed time, counts
```

Findings become normal Plasma events:

```json
{
  "ts": "2026-11-20T10:00:00Z",
  "host": "WS1",
  "source": "memory",
  "kind": "alert",
  "event_id": 9100,
  "severity": "critical",
  "score": 0.95,
  "action": "logged",
  "technique": "T1055.012",
  "alert_id": "memory:hollowing:684:notepad.exe",
  "process": "notepad.exe",
  "pid": 684,
  "file_path": "C:\\Windows\\notepad.exe",
  "description": "HollowsHunter hollowing: notepad.exe"
}
```

`watch`, `chain`, `fleet` and the response policy consume these rows like
any other alert. The event store never contains raw memory images.

## Dumps

The scanner does not write files by default. `--dump` is explicit:

```powershell
plasma memory scan --pid 4832 --dump
```

Dumps can contain credentials, tokens and customer data. They are written
under `<root>/memory/`, governed by the Plasma root ACL, and refused with
`--all`. Treat them as evidence and apply your retention policy.

## JIT noise

The scanner can classify managed .NET JIT regions as shellcode. Plasma
suppresses those observations from the alert stream and reports the count
in `suppressed_managed_jit`. A PowerShell deep scan can therefore show
`suspicious_count: 1` with `findings: []`; that is intentional.

## Pinned payload

The Windows release bundles:

```text
sensors/memory/hollows_hunter64.exe
sensors/memory/hollows_hunter32.exe
sensors/memory/LICENSE
sensors/memory/VERSION
```

Both binaries are SHA-256 pinned. A mismatched binary is refused rather
than executed. The scanner is BSD-2-Clause; its notice travels with the
payload and is included in `plasma assurance sbom`.

## Limits

- User-mode only: kernel-mode malware, malicious drivers and direct
  syscalls remain outside the claim.
- Point-in-time: a short-lived implant can execute and vanish between
  scans.
- Protected processes may be unreadable.
- Full scans are expensive; targeted scans are the default.
- The scanner may be flagged by other security products; allowlist it
  deliberately.

## Status

```powershell
plasma memory status     # resolver, hash, last scan
plasma memory list       # archived scan metadata
```
