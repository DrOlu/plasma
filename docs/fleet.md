# Fleet — one desk, many computers

Cross-host correlation is where a per-box tool becomes an estate tool. The
desk pulls a bounded event tail from each host, then joins them locally.

## Inventory

```json
{
  "hosts": [
    {
      "name": "WS1",
      "endpoint": "44.197.31.152:5985",
      "transport": "winrm",
      "username": "Administrator",
      "password_env": "WS1PW",
      "events_path": "C:\\ProgramData\\Plasma\\data\\events.jsonl"
    },
    {
      "name": "WS2",
      "endpoint": "52.3.242.251:5985",
      "transport": "winrm",
      "username": "Administrator",
      "password_env": "WS2PW",
      "events_path": "C:\\ProgramData\\Plasma\\data\\events.jsonl"
    }
  ]
}
```

Rules:

- `transport: "winrm"` pulls over WinRM/NTLM; omit it (or use `"file"`) to
  read a local copy.
- Passwords are **never in the file** — `password_env` names an environment
  variable on the desk.
- Both transports produce the same rows; the WinRM path reads the file
  **byte-exact via base64** (PS text output re-encodes through the console
  codepage and can corrupt JSON), with a `-Tail` fallback for locked files.

## Pull → correlate → report

```powershell
plasma fleet pull      --inventory inventory.json --case incident-42 --cap 300 --window 21600
plasma fleet correlate --case incident-42 --window 21600
plasma fleet report    --case incident-42
```

State lives under `<root>/fleet-cases/<case>/`:

```text
case.json                    window, canaries, created
answers/WS1.events.jsonl     pulled tails
answers/*.attest.json        optional observatory answers per host
report.md                    rendered dossier
```

## Correlation scores

| Finding | Score | Rule |
|---|---|---|
| `canary_tripped` | 10 | a canary account appears on any host |
| `lateral_hop` | 9 | the same user on **2+ hosts** within the window |
| `shared_hash` | 8 | the same file hash on 2+ hosts |
| `blind_host` | 8 | a host's self-check reports blindness or an unhealthy sensor |
| `shared_domain` | 7 | the same DNS query on 2+ hosts |
| `shared_ip` | 7 | the same destination IP on 2+ hosts |

Notes:

- Window is in **seconds** (default 1800; a 6-hour incident review uses
  21600).
- Timestamps are normalized to UTC; naive rows are treated as UTC so mixed
  formats correlate instead of crashing.
- `--canary alice --canary bob` (or config in the existing case) marks
  accounts that must never appear; `--window` and `--canary` on an existing
  case update it rather than being silently ignored.
- The report is Markdown, deterministic, and sized for pasting into a
  ticket.

## Example finding

```text
[9/10] lateral_hop
  user 'administrator' on 2 hosts within 85 min: WS2 -> WS1
```

That is a genuine correlation from a two-host estate: the ordering comes
from first-seen timestamps, so the report tells you the direction of travel.
