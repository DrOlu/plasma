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

Three calibration rules keep the bands honest (1.32.0):

- **Identity novelty is capped.** A name being new in a table is the weakest
  evidence there is — first-seen `image`/`edge`/`user_image`/`estate`
  components are capped at 0.85, and a row whose novelty is *only* identity
  (no behaviour shape, no destination/registry/file family, no volume fact)
  cannot cross 8.9. A benign first-run of software lands in the high band,
  not the critical band; the critical band needs a content signal
  (`shape`/`dest`/`registry`/`file` at 0.95+) or a volume spike.
- **Volume is spikes only.** A drop in activity is quiet, not novel. Hours
  with no baseline never score, and a constant baseline needs a real step
  (≥ 3× the median + 5). A lone volume spike with nothing else caps at 8.5.
- **One strong signal is not diluted away.** The weighted mean no longer
  lets zero-value components hide a novel C2 destination on a familiar
  binary; the score floors at half of the strongest component.

Routine Windows servicing (`services.exe`, `svchost.exe`, `wuauclt.exe` and
similar) is damped by 0.55 — but only for **familiar** children. A
first-seen child of a service host is exactly where service-installed
payloads run, so it keeps its full weight. Only the shipped Plasma binaries
are skipped by default (`--include-self` shows them; the updater matches
exactly, so `plasma-updater.exe` is scored like any look-alike). A single
novel signal on an otherwise familiar row is floored at half its strength
instead of being averaged into invisibility, and trace scores are led by the
rarest edge (0.7 max, 0.3 mean) so one malicious hop among familiar ones is
visible.

Two poisoning guards: a table count is trusted only up to 50 inside the
rarity math (500 planted runs cannot buy familiarity), and a merged estate
profile deduplicates repeated hosts. A merged estate that contains only the
scored host is not used at all — the same evidence twice is not corroboration.
Bands are critical at 9.0+, high at 7.5+, medium at 6.0+.

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
- **Not poison-proof by itself.** Rarity trusts at most 50 occurrences of a
  key regardless of how many times it ran, but a determined insider can still
  shape what the baseline thinks is normal. Sign profiles, and re-baseline
  through a change window rather than during one.
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
