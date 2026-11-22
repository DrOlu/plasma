# Behavioural profiles and anomaly scores

Plasma's detection has always been deterministic: gene rules, chains, drift
checks and fleet joins. Profiles add the missing baseline layer without
adding a log lake.

## The two tiers

**Tier 1 — the host.** `plasma profile build` reduces a bounded tail of the
local JSONL store into counts: images, parent→child edges, identity→image
pairs, destination families, registry and file families, command-line
shapes, and robust hourly volume per entity. The result is tens of
kilobytes. It never contains event rows, full command lines, file paths or
URLs.

**Tier 2 — the estate.** `plasma fleet profiles` asks each host to build its
own profile and brings back only that profile. Host profiles merge into one
estate profile, so a desk can ask "rare here" and "rare in the estate"
separately. A thousand hosts is megabytes, not a lake.

## What a profile holds

| Table | Key example | Why |
|---|---|---|
| `image` | `chrome.exe` | which programs this host runs |
| `parent_child` | `explorer.exe>cmd.exe` | the strongest Windows behaviour edge |
| `user_image` | `corp\olu>powershell.exe` | identity-to-program shape |
| `dest` | `chrome.exe>p:443` | port, else a /24 family — never a raw address |
| `registry` | `currentversion\run\evil` | persistence-shaped key families |
| `file` | `documents.ps1` | sensitive-path families |
| `shape` | `powershell -enc <b64>` | behaviour, not literals |
| `hourly` | `image:chrome.exe`, hour 9 | median/MAD per day, per hour |

Command lines are reduced before they are counted. Paths, URLs, addresses,
GUIDs, long hex blobs, quoted strings and numbers collapse to placeholders;
`net user bob <pw>` becomes `net user bob <cred>`. A profile is a behaviour
label, not a transcript.

Profiles carry a SHA-256 over their body. `plasma profile verify` recomputes
it, so a tampered baseline is visible rather than trusted.

## Scoring

`plasma anomaly score` compares recent rows with a profile and returns a
0–10 score built from named components:

| Component | Weight | Signal |
|---|---|---|
| `edge` | 1.5 | parent→child rarity |
| `image` | 1.0 | program rarity |
| `user_image` | 0.8 | identity/program rarity |
| `dest` | 0.7 | destination family rarity |
| `registry` | 0.8 | registry family rarity |
| `file` | 0.4 | file family rarity |
| `shape` | 0.8 | command-shape rarity |
| `volume` | 1.2 | robust z of the day's hourly count |
| `estate` | 1.5 | rarity in the merged estate profile |

Each component reports `count`/`total`, `first_seen`, and the key that
produced it. The score is the weighted mean of the components that could be
computed. Nothing is learned online and no opaque model sits in the path.

Routine Windows servicing (`services.exe`, `svchost.exe`, `wuauclt.exe` and
similar) is damped by 0.55. A rare child of a service host still appears, at
triage level, instead of turning a patched server red. Plasma's own binaries
are skipped by default (`--include-self` shows them), so an upgrade cannot
dominate its own ranking. Bands are critical at 9.0+, high at 7.5+, medium
at 6.0+.

**Cold start is explicit.** Below 50 observations, or when no table has
data, the score is `null` with `cold_start: true`. Plasma would rather say
"I do not know yet" than manufacture confidence.

## Traces

`plasma anomaly trace` joins process spans into trees using PID/PPID within
one host. A parent link is the most recent earlier span with that PID on
that host, which handles PID reuse. Traces never cross hosts: an RDP or SMB
hop creates a new logon and therefore a new tree. Cross-host identity joins
belong to `fleet`.

With `--profile`, each trace is scored by the rarity of its parent→child
edges. First-seen edges are listed explicitly.

## Learning lifecycle

1. **Observe.** Run the identity pull and WHIDS for at least a week.
2. **Learn.** `plasma profile build --since 7d --out profile.json`.
3. **Freeze.** Diff against the previous profile; investigate new edges
   before accepting them.
4. **Detect.** `plasma anomaly score --profile profile.json --since 1h`.
5. **Re-learn** deliberately after a role change or a long patch window.
   A stale baseline is worse than a cold one.

## What this is not

- **Not an auto-containment trigger.** Scores are for triage. Response stays
  plan-gated and explicit.
- **Not a replacement for rules or chains.** A signature still catches the
  obvious intrusion faster than a baseline notices the shape.
- **Not poison-proof by itself.** Sign profiles, and re-baseline through a
  change window rather than during one. An attacker who can rewrite the
  baseline can normalise themselves.
- **Not a log shipper.** Only counts cross the wire.

## Related commands

```text
plasma profile build   --events events.jsonl --role member --out profile.json
plasma profile show    --profile profile.json
plasma profile diff    --old last-week.json --new profile.json
plasma profile merge   --profiles ws1.json ws2.json --out estate.json
plasma profile verify  --profile estate.json
plasma anomaly score   --events events.jsonl --profile profile.json --estate estate.json
plasma anomaly explain --events events.jsonl --profile profile.json --contains powershell
plasma anomaly trace   --events events.jsonl --profile profile.json --min-spans 3
plasma fleet profiles  --inventory hosts.json --out-dir estate
```
