# Estate edge ledger

The estate ledger answers the questions a single endpoint cannot — one account
on fifty machines in an hour, one source address across a subnet, a host that
went quiet — **without moving raw events and without a central log lake**.

Each host reduces a bounded window of its own store into a small, hash-sealed
*identity ledger*. The desk pulls those ledgers, replaces the previous copy for
that host, and merges them into one continuously updated estate view.

```text
host store (events.jsonl)                 desk
┌────────────────────────┐        ┌──────────────────────────────┐
│ last 60 min, ≤ 20k rows│        │ pull one ledger per host     │
│ who / from where /     │  ───▶  │ replace → merge → correlate  │
│ which process and hash │ counts │ estate.json + findings.json  │
└────────────────────────┘        └──────────────────────────────┘
```

## What a host ledger contains

The ledger is deliberately lossy. It stores **counts**, never command lines,
file paths, raw descriptions, or the event diary itself.

| Field | Meaning |
|---|---|
| `host`, `role` | stable host name and estate role |
| `generated_at` | when this reduction ran |
| `window` | minutes covered, start and end |
| `n` | rows considered inside the window |
| `users` | per account: `count`, `first`, `last`, bounded `sources`, `logon_types` |
| `processes` | `user>process` counts, capped at 200 |
| `hashes` | file hash counts, capped at 100 |
| `truncated` | how many identities were dropped by the caps |
| `coverage` | rows seen, identity/Kerberos counts, last event times, event kinds, and the last identity pull result |
| `integrity` | SHA-256 over the ledger body |

Caps are absolute: 200 users, 10 source addresses per user, 200 process pairs,
100 hashes and a 256 KiB ledger. If the blob still exceeds the byte cap, hashes
are dropped and process pairs are trimmed to 50, and `size_after_trim` records
the result. A host ledger is normally a few kilobytes.

Machine and service accounts (`HOST$`, `SYSTEM`, `LOCAL SERVICE`,
`NETWORK SERVICE`) are excluded, and `DOMAIN\user` and UPN forms collapse to
the same account name.

## Build a ledger

```powershell
plasma estate build `
  --events C:\ProgramData\Plasma\data\events.jsonl `
  --window 60 --max-rows 20000 `
  --host WS1 --role member `
  --out C:\ProgramData\Plasma\estate\WS1.json
```

Local and remote builds use the same code. `sync` runs exactly this command on
each Windows host over WinRM and reads the result back byte-exact (base64), so
the console code page cannot corrupt it, then deletes the temporary file.

## Merge and correlate

```powershell
plasma estate merge --dir .\estate\hosts --out .\estate\estate.json
plasma estate findings --ledger .\estate\estate.json --threshold 5
plasma estate status --ledger .\estate\estate.json
```

`merge` keeps the **newest ledger per host**, so a re-run replaces that host's
previous view instead of double-counting it. Merging the same set twice
produces the same estate ledger. Per-host state survives a desk restart: the
ledger files under `hosts/` are the state.

`--max-age` (default 180 minutes) marks a host ledger **stale** when it has not
been refreshed; stale is a finding, not a silent gap.

## Findings

| Finding | Score | Rule |
|---|---|---|
| `estate_user_fanout` | 9 | one account on ≥ threshold hosts **with a source address shared across ≥ 2 of them** |
| `estate_user_fanout` | 7 | same-name pattern on ≥ threshold hosts, no shared source — verify before acting |
| `estate_source_fanout` | 9 | one source address touching ≥ threshold hosts |
| `estate_hash_fanout` | 8 | the same file hash on ≥ threshold hosts |
| `estate_stale_host` | 8 | ledger older than `--max-age` |
| `estate_new_host_edge` | 7 | a user/host pair absent from `--baseline`, for users seen on 2+ hosts |
| `estate_identity_blind` | 9 | identity pull failed, or identity events existed before the window but none inside it |
| `estate_identity_unverified` | 7 | non-identity rows flowed but there is no identity evidence — quiet, unconfigured, or blocked |
| `estate_no_telemetry` | 8 | the host reported zero rows in the window |
| `estate_kerberos_blind` | 8 | a host with `--role dc` recorded no 4768/4769 events |
| `estate_identity_stale` | 8 | the last identity pull is older than `--max-identity-age` |

The score split matters. A name appearing in many places is not proof of one
identity: `Administrator`, `admin` and `svc-backup` are reused across estates
by design. The ledger therefore only raises a fan-out to 9 when the **same
source address** links at least two of those appearances. Otherwise it reports
7 and says `same-name pattern; verify`.

`--baseline` points at a previous `estate.json`. New user/host edges are the
drift signal — an account that has never been on a host before.

## Coverage: quiet is not clean

A zero-fan-out result is only meaningful if the identity feed was actually
answering. The ledger therefore carries a `coverage` block:

```json
"coverage": {
  "rows": 498,
  "identity_events": 15,
  "kerberos_events": 4,
  "last_event": "2026-11-24T00:24:02Z",
  "last_identity_event": "2026-11-24T00:23:51Z",
  "kinds": {"auth": 15, "process": 480, "network": 3},
  "identity_before_window": true,
  "identity_pull": {
    "ts": "2026-11-24T00:25:01Z",
    "ok": true,
    "events_seen": 22,
    "written": 15,
    "error": null
  }
}
```

`identity_pull` comes from a small sidecar file —
`<events-dir>\identity-pull.json` — that `plasma identity pull` writes on
**every attempt**, success or failure. The event store cannot express “the
Security channel query failed”, so the marker carries that fact:

| Marker state | Meaning |
|---|---|
| `ok: true`, `events_seen > 0` | the identity source answered |
| `ok: true`, `events_seen: 0` | it answered and there were no events |
| `ok: false` | it could not answer; `error` says why |

That gives the desk three honest outcomes instead of one ambiguous silence:

1. **No fan-out** — identity events were seen on the hosts, nothing crossed them.
2. **Blind** — the pull failed, or identity events existed before the window
   and stopped inside it. Score 9; do not treat the estate as clean.
3. **Unverified** — other telemetry flowed but there is no identity evidence
   at all. Score 7; the estate cannot claim there was no fan-out.

Two related checks cover the rest:

- `estate_no_telemetry` (8) — the host reported a fresh ledger with zero rows.
  That is a coverage question, not a clean bill of health.
- `estate_kerberos_blind` (8) — only when the inventory/role says `dc`. Member
  servers legitimately have no 4768/4769 events; flagging them would be noise.
- `estate_identity_stale` (8) — the last pull marker is older than
  `--max-identity-age` (default 180 minutes), so the coverage evidence is old.

```powershell
plasma estate findings --ledger estate.json --max-identity-age 120
```

A failed pull is not silently re-sealed by the desk: `sync` verifies each
remote ledger's SHA-256 before accepting it, and the marker's error travels
with the coverage block.

## Continuous sync

```powershell
plasma estate sync --inventory inventory.json --out-dir C:\PlasmaEstate `
  --window 60 --workers 8 --threshold 5 --max-age 180 `
  --max-identity-age 180 --interval 300 --loop
```

`sync` pulls one ledger per host in parallel, saves `hosts/<name>.json`,
merges to `estate.json`, writes `findings.json`, and returns one JSON summary.
With `--loop` it prints one summary line per cycle and sleeps for `--interval`
seconds (minimum 10). A failed host is recorded in `failures` and the cycle
continues; a cycle only fails when **no** host ledger could be built.

Inventory is the same file used by `plasma fleet`:

```json
{
  "hosts": [
    {"name": "WS1", "endpoint": "44.197.31.152:5985", "transport": "winrm",
     "username": "Administrator", "password_env": "WS1PW",
     "events_path": "C:\\ProgramData\\Plasma\\data\\events.jsonl"},
    {"name": "WS2", "endpoint": "52.3.242.251:5985", "transport": "winrm",
     "username": "Administrator", "password_env": "WS2PW",
     "events_path": "C:\\ProgramData\\Plasma\\data\\events.jsonl"}
  ]
}
```

Passwords stay in environment variables. HTTPS WinRM is recommended for a
real domain (see [Fleet](fleet.md)); a controlled lab may set
`"allow_insecure_winrm": true`. `transport: "file"` accepts either
`events_path` (reduce a local store) or `ledger_path` (read a ledger produced
elsewhere), which makes air-gapped and test environments first-class.

## Scale

The work is linear in hosts and bounded in memory:

- Each host sends one small ledger, not an event tail. There is no growing
  central index and no per-event insert on the desk.
- `merge` and `findings` are single passes over the ledgers. A 1,000-host
  estate with 10,000 distinct accounts merges and correlates in a couple of
  seconds on a laptop; the resulting estate ledger stays in the low megabytes.
- Estate caps (5,000 users, 5,000 process pairs, 5,000 hashes, 20,000 hash/host pairs) and the
  `truncated` counters keep a pathological domain from exhausting memory.
- Pulls are parallel but capped at 32 workers. Old copies are replaced, so
  disk use is proportional to the number of hosts, not to time.

A 300-second cadence over 1,000 hosts is roughly 3.3 ledger pulls per second —
well inside a desk-side process. For larger estates, shard the inventory by
site and merge the shard ledgers with `plasma estate merge --ledgers`.

## Integrity and residency

- Every ledger carries a SHA-256 over its canonical body. `load`,
  `merge --dir` and `status` recompute it and refuse a modified ledger. This
  detects corruption and casual edits; it is **not a signature**. The trust
  boundary is the desk's filesystem ACL and the WinRM channel.
- The desk receives identities, counts and source/destination addresses — not
  command lines, file paths, event descriptions or full event rows.
- Old ledgers are replaced in place, so the estate view is a **current
  snapshot**, not a history. Keeping history is an explicit choice: copy
  `estate.json` into a case directory if you need it.
- Findings are ordinary JSON and can be fed to `plasma export webhook|syslog`
  or any SIEM without shipping the store.

## Limits

- The ledger correlates what sensors record. Coverage findings name a blind or
  unverified identity feed, but pair them with `plasma fleet` attestation for
  the full sensor picture.
- On a member server, zero Kerberos events are normal. Set `--role dc` only
  for domain controllers that should be producing 4768/4769.
- Counts cannot explain *why*. When a fan-out finding matters, pull the
  bounded event tail for those hosts with `plasma fleet pull` and read it.
- Same-name accounts are common. Treat score 7 as a question, not a verdict.
- The ledger is not a substitute for a SIEM's long retention; it is the
  estate-wide view that a lake-less design can honestly maintain.
