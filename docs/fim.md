# File integrity monitoring (FIM)

Canaries answer "did something destroy a decoy?" — impact. FIM answers the
compliance question: **did a critical file change?** Plasma records
`(path, sha256, size)` for a configurable set of paths and diffs it on demand
or during every `watch` sweep.

This is the control PCI DSS 11.5.1 asks for; it is deliberately separate
from the canary machinery because the two answer different questions.

## Commands

```powershell
plasma fim baseline --root C:\ProgramData\Plasma
plasma fim verify   --root C:\ProgramData\Plasma   # exit 2 when changed
plasma fim status   --root C:\ProgramData\Plasma
```

Add your own critical paths (files or globs):

```powershell
plasma fim baseline --root C:\ProgramData\Plasma `
  --path "C:\Windows\System32\drivers\etc\*" `
  --path "D:\Apps\gateway\config\*.yaml"
```

The baseline is stored at `<root>\fim.json`. Re-run `baseline` after an
approved change; otherwise the change is reported, which is the point.

## Default paths

| Path | Why |
|---|---|
| `C:\Windows\System32\drivers\etc\hosts` | name resolution tampering |
| `...\etc\services`, `...\etc\networks` | service/port tampering |
| `C:\ProgramData\Plasma\config.json` | sensor configuration |
| `C:\Program Files\Whids\config.toml` | detection configuration |

Bounds: 5,000 files and 32 MB per file. Paths are expanded as globs and
de-duplicated by resolved path.

## Findings

| Change | Type | Score |
|---|---|---|
| Hash changed | `fim_modified` | 8 |
| File removed | `fim_removed` | 8 |
| New file matched a monitored glob | `fim_added` | 6 |

`watch` lifts these into its finding list, so a modified critical file makes
the verdict `act now` (score ≥ 8). A missing baseline is not an error storm:
`verify` returns a hint to run `plasma fim baseline`, and `watch` ignores the
collector until a baseline exists.

## Scope

FIM watches **content of named paths**, not every file on the disk. It is
not a replacement for AIDE/Tripwire on a Linux estate; on Windows it covers
the high-value configuration and boot-adjacent files an operator can name.
