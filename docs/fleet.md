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

- `transport: "winrm"` pulls over WinRM/NTLM. **HTTPS is required**
  (`https://host:5986`) because NTLM over plain HTTP is relay-prone. A
  controlled lab may set `"allow_insecure_winrm": true` to opt into HTTP.
  Omit the transport (or use `"file"`) to
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
| `canary_token_hit` | 9 | a DNS/HTTP canary token fired on a host |
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

## Continuous estate ledger

`fleet` answers an incident question from a bounded event tail. The **estate
edge ledger** answers the standing question — *who is touching how many hosts
right now?* — at a cadence, from counts only.

```powershell
plasma estate sync --inventory inventory.json --out-dir C:\PlasmaEstate `
  --window 60 --workers 8 --threshold 5 --interval 300 --loop
plasma estate findings --ledger C:\PlasmaEstate\estate.json
plasma estate status   --ledger C:\PlasmaEstate\estate.json
```

Each host reduces its own store to a small hash-sealed ledger (users, sources,
`user>process` counts and hashes). The desk replaces that host's previous
ledger, merges everything and raises:

| Finding | Score | Meaning |
|---|---|---|
| `estate_user_fanout` | 9 / 7 | one account on many hosts; 9 only when a source address links at least two |
| `estate_source_fanout` | 9 | one source address across many hosts |
| `estate_stale_host` | 8 | a host stopped refreshing its ledger |
| `estate_hash_fanout` | 8 | the same file hash on many hosts |
| `estate_new_host_edge` | 7 | a user/host pair absent from `--baseline` |
| `estate_identity_blind` | 9 | the identity pull failed, or the feed stopped inside the window and its last pull brought nothing |
| `estate_identity_unverified` | 7 | other telemetry flowed but there is no identity evidence |
| `estate_no_telemetry` | 8 | the host returned zero rows |

Coverage findings keep “no fan-out” separate from “the identity source could
not answer”. Each ledger carries the last identity pull result and a
`--max-identity-age` check. See [Estate edge ledger](estate-ledger.md#coverage-quiet-is-not-clean).

The event diary never leaves the box; only the counts do. See
[Estate edge ledger](estate-ledger.md) for the schema, caps, scale and
residency model.

## Plugin events

Plugin sensor events and detector findings are ordinary rows in the local
store, so `fleet pull` carries them like any other event. A plugin finding is
an `alert` row with `alert_id=plugin:<name>`; fleet correlation does not need
to know the plugin existed.

## Example finding

```text
[9/10] lateral_hop
  user 'administrator' on 2 hosts within 85 min: WS2 -> WS1
```

That is a genuine correlation from a two-host estate: the ordering comes
from first-seen timestamps, so the report tells you the direction of travel.
