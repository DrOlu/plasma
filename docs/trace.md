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
| Windows Server 2022 / Windows 10-11 | Microsoft DTrace package (`Microsoft.DTrace`, amd64) |

```powershell
plasma trace check        # installed? enabled? which build?
plasma trace provision    # download/install the package + bcdedit /set dtrace on
```

`provision` reports `reboot_required: true`; after the restart:

```powershell
plasma trace check        # enabled: true
plasma trace selftest     # compile every reviewed script with `dtrace -e`
```

`provision` installs the official Microsoft MSI directly when winget is
absent (the default on Server 2022). It is idempotent: installed + enabled
means ready, and only a missing or disabled install triggers action.

Microsoft's Download Center labels the current package **2.0**, but the MSI
still reports ProductVersion 1.1.0 and the tool prints `Sun D 1.13.1`.
Plasma deliberately does not chase that version string — capability is what
matters. Across the Windows Server builds in the estate, `pid` is readable
on some and rejected with "invalid user access" on others, so the shipped
scripts emit `tid`, which is portable and is carried in the normalized
event description. DTrace relies on virtualization-based security (VBS) on
modern Windows; if tracing fails to start, verify VBS is enabled and give
the driver one clean restart after the MSI.

## Reviewed scripts

```powershell
plasma trace list
```

| Script | Technique | Score | What it prints |
|---|---|---|---|
| `syscall-errors` | T1106 | 6 | NT syscalls returning a non-success status: tid, image, function, status |
| `process-create` | T1059 | 5 | `NtCreateUserProcess` / `NtCreateThreadEx` entries: tid, image |
| `etw-kernel-process` | T1057 | 4 | ETW `Microsoft-Windows-Kernel-Process` events (header fields only) |
| `inject-rwx` | T1055 | 5 / 8 | `NtProtectVirtualMemory` granting RWX (base `arg3 & 0xff == 0x40`): tid, image, raw protection, self flag. Self-access scores 5; cross-process scores 8 |
| `inject-remote-thread` | T1055 | 6 | `NtCreateThreadEx` with a target handle other than the caller: tid, image |
| `inject-apc` | T1055 | 5 (chain 9) | `NtQueueApcThread`, `NtQueueApcThreadEx` or `NtQueueApcThreadEx2`: tid, image, syscall |
| `inject-hijack` | T1055 | 5 (chain 8) | `NtSetContextThread` on a thread other than the caller (`NtCurrentThread` is -2): tid, image |
| `inject-hollow` | T1055 | 6 (chain 9) | `NtUnmapViewOfSection` against another process (arg0): tid, image |
| `inject-section` | T1055 | 5 (chain 9) | `NtMapViewOfSection` into another process (arg1 is the ProcessHandle; arg0 is the SectionHandle): tid, image |
| `inject-write` | T1055 | 5 (chain 9) | `NtWriteVirtualMemory` into another process (arg0): tid, image |

Scripts live in `sensors/dtrace/*.d`, carry metadata in `/* */` block
comments, and are validated before use: an allowlisted provider is required,
`system()` and other destructive constructs are refused, and every script
must emit lines prefixed `plasma|{"…"}`.

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

### Process-injection evidence (T1055)

A single RWX allocation is not a verdict: JIT compilers and some installers
create executable writable pages legitimately. Trace both halves of the
story and let the chain decide.

```powershell
plasma trace run inject-rwx --for 30s --events C:\ProgramData\Plasma\data\events.jsonl
plasma trace run inject-remote-thread --for 30s --events C:\ProgramData\Plasma\data\events.jsonl
plasma chain score --events C:\ProgramData\Plasma\data\events.jsonl
```

`inject-rwx` fires on `NtProtectVirtualMemory` when the base protection is
RWX (`arg3 & 0xff == 0x40`). Matching the low byte is deliberate: `0x140`,
`0x240` and `0x440` add `PAGE_GUARD`, `PAGE_NOCACHE` or `PAGE_WRITECOMBINE`
and are at least as suspicious as plain RWX. `arg0` is the target process
handle, so the row distinguishes a process flipping its **own** page (JIT,
.NET, V8 — score 5, medium) from one flipping **another process's** page
(injection — score 8, high).

`inject-remote-thread` fires on `NtCreateThreadEx` when the target handle is
not the caller's pseudo-handle. It compares only the low 32 bits, which is
stable across DTrace builds and avoids the untyped 64-bit literal problem.

`inject-apc` covers the `NtQueueApcThread` family (including
`NtQueueApcThreadEx2`, which modern `QueueUserAPC` uses). A thread handle
does not reveal its owning process at this boundary, so it is evidence at
score 5. **It is high-volume:** every APC a process queues to its own threads
(threadpool dispatch, .NET, routine `QueueUserAPC`) produces a row. Use short
windows and a row cap.

`injection_apc_chain` escalates only the meaningful shape: a cross-process
RWX flip (`self=0`) followed by an APC from the same image within 30 seconds,
score 9. Self-RWX cannot start the chain.

`injection_chain` requires a **cross-process** RWX row (`"self": 0`) followed
by remote thread creation, both from the same image, inside 120 seconds.
The chain binds on the image name because thread creation in another process
is ordinary system activity (System, svchost, the EDR itself); without
binding, unrelated events would collide.

**False positives:** self-RWX is normal in JIT-heavy software, and remote
thread creation is normal for system services. Treat the same-image,
cross-process chain as the signal, not either single event — that is why
the individual scripts stay at 5/6/5.

**Coverage of the family:** the reviewed set now covers the classic
`CreateRemoteThread` path, RWX permission flips, APC queueing, thread
context rewriting, process hollowing, section mapping and remote writes into
already-executable memory. Four chains bind each primitive to a remote
thread from the same image:

| Chain | Steps | Score |
|---|---|---|
| `injection_chain` | RWX flip → remote thread | 9 |
| `injection_apc_chain` | RWX flip → APC | 9 |
| `injection_hollow_chain` | unmap → write → remote thread | 9 |
| `injection_section_chain` | section map → remote thread | 9 |
| `injection_write_chain` | remote write → remote thread | 9 |
| `injection_hijack_chain` | context rewrite → remote thread | 8 |

The write chain is the one that leaves neither an RWX flip nor a new thread
on its own; it still requires the remote thread to complete the story.

**Volume:** `inject-section` is the noisiest primitive. `NtMapViewOfSection`
is used by every memory-mapped file and .NET assembly load; the predicate
requires a remote process handle (arg1), and the chain requires a remote
thread, but expect rows on hosts that map sections heavily. The other three
scripts are low-volume by comparison.

**This is evidence, not prevention.** DTrace observes the syscall boundary;
it cannot block an injection. `raise(` remains forbidden in reviewed
scripts, so Plasma can witness an injection but never stop it.

Each normalized row has `kind: "trace"`, `source: "dtrace"`, the script's
technique and score, and the image/tid. That means **chains, drift, fleet
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
