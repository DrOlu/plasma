# DTrace — the on-demand kernel microscope

Plasma already has two detection layers: WHIDS gene rules (always-on,
cheap) and the ETW tap (a bounded live window over selected providers).
**DTrace is the third, surgical layer**: kernel/user function and syscall
instrumentation for a specific question, for a bounded time, then gone.

It is integrated the same way as the tap — reviewed scripts, no service, no
persistence, same event contract — with one deliberate difference:
**provisioning is explicit**, because DTrace is a kernel tracer that needs a
boot-setting change and a restart. It is never installed silently by the
EDR installer.

## Availability

| Where | How to get it |
|---|---|
| Windows Server 2025 | built-in (`dtrace.exe`) |
| Windows Server 2022 / Windows 10-11 | Microsoft **DTrace 2.0 MSI** (`Microsoft.DTrace`, amd64) |

```powershell
plasma trace check        # available? enabled? version?
plasma trace provision    # install/upgrade DTrace 2.0 + bcdedit /set dtrace on
```

`provision` reports `reboot_required: true`; after the restart:

```powershell
plasma trace check        # enabled: true
plasma trace selftest     # compile every reviewed script with `dtrace -e`
```

`provision` installs the official Microsoft DTrace 2.0 MSI directly when
winget is absent (the default on Server 2022), and upgrades an older
Sun D 1.13.1 preview in place. Plasma requires DTrace 2.x: the 1.x preview
cannot read `pid` in probe context. DTrace relies on virtualization-based
security (VBS) on modern Windows; if tracing fails to start, verify VBS is
enabled.

## Reviewed scripts

```powershell
plasma trace list
```

| Script | Technique | Score | What it prints |
|---|---|---|---|
| `syscall-errors` | T1106 | 6 | NT syscalls returning a non-success status: pid, image, function, status |
| `process-create` | T1059 | 5 | `NtCreateUserProcess` / `NtCreateThreadEx` entries: pid, image |
| `etw-kernel-process` | T1057 | 4 | ETW `Microsoft-Windows-Kernel-Process` events (header fields only) |

Scripts live in `sensors/dtrace/*.d`, carry metadata in `//` comments, and
are validated before use: an allowlisted provider is required, `system()`
and other destructive constructs are refused, and every script must emit
lines prefixed `plasma|{"…"}`.

Adding a script is a review, not a config change: drop a `.d` file in the
directory, keep the `plasma|` JSON contract, run `plasma trace selftest`.

## Bounded runs

```powershell
plasma trace run syscall-errors --for 10s --events C:\ProgramData\Plasma\data\events.jsonl
plasma trace run process-create --for 30s --max-rows 5000 --out C:\ProgramData\Plasma\trace\capture.jsonl --events <store>
```

- Wall-clock window (`--for`, 1s–5m) — the process is killed at the end.
- Row cap (`--max-rows`, default 2000).
- Raw capture optionally kept (`--out`); normalized rows appended to the
  events store with content-hash dedupe.
- `-w` (DTrace's destructive mode) is never used.

Each normalized row has `kind: "trace"`, `source: "dtrace"`, the script's
technique and score, and the image/pid. That means **chains, drift, fleet
and watch consume DTrace evidence exactly like any other event**:

```text
chain: office spawn (Sysmon) → encoded PowerShell (tap) →
       syscall error on a finance file (dtrace)  =  one story, one store
```

## Why not always-on?

Kernel tracing is expensive and, on hosts without VBS, invasive. Plasma's
doctrine is the flashlight: tap for a cheap live window, DTrace when a case
needs the syscall boundary. Always-on depth belongs to Sysmon/WHIDS, which
are tuned for continuous collection.

## Coverage accounting

DTrace scripts are **on-demand evidence**, so they are not counted in the
always-on ATT&CK breadth number. The coverage report stays honest about
what runs continuously; trace evidence shows up in findings and chains
whenever an operator opens a window.

## Troubleshooting

| Symptom | Meaning |
|---|---|
| `trace check` → available, enabled: false | run `bcdedit /set dtrace on` and restart |
| `selftest` fails on a script | a probe name is not available on this build; the stderr names it |
| `run` returns 0 rows | the filtered probe did not fire in the window (expected on a quiet box) |
| DTrace start error mentioning VBS/hypervisor | enable virtualization-based security, or use Server 2025's built-in build |
