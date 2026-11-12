# Detection

Detection in Plasma is written rules and written sequences — nothing is
learned in the detection path. Every statement carries a fixed score and an
ATT&CK technique where one applies.

## Scores and verdicts

| Score | Meaning | Typical source |
|---|---|---|
| 10 | act now | canary tripped, health down |
| 9 | act now | lateral hop, persistence-after-privilege, phish chain |
| 8 | act now | shared hash, blind host, office-spawn, brute-force success |
| 7 | investigate | shared domain/IP, unusual service paths |
| 5–6 | investigate | drift changes, new alert growth, encoded command |
| 0 | clean | nothing crossing a threshold |

`watch` maps the top score to **clean / investigate / act now** and only
delivers alerts when the score crosses `min_score` (default 7) in
`notify.json`.

## Gene rules (always-on, WHIDS)

Fifteen baseline rules with ATT&CK tags, criticality 6–9. See
[Sensors](sensors.md) for the table. They run on every Sysmon event, cost
almost nothing, and produce alert rows with a criticality that becomes the
event `score`.

Adding a rule is a one-line JSON object in `sensors/plasma-baseline.gen`
(schema 1.0.0) followed by a reinstall; regexes are validated by tests that
compile every expression **and** assert positive/negative behavior.

## Tap rules (live windows)

31 rules for PowerShell script blocks, WMI persistence, DNS tunnels, .NET
assembly loads and more. They only exist while `plasma tap run` is alive.
Rules are rendered into the 7-field pipe format the C++ tap consumes, with
fields validated against pipes and newlines.

## Chains — stories, not events

A single alert says "something happened". A chain says "this, then this,
then this". Chains are ordered matchers over the events tail with a gap
window between adjacent steps, plus optional **count** steps.

| Chain | Score | Story (in time order) |
|---|---|---|
| `phish_spawn_chain` | 9 | Office app → script host (powershell/wscript/cscript/mshta) → encoded command or egress, all within 15 min |
| `brute_force_success` | 8 | ≥5 failed logons for one user, then a success, within 60 min |
| `persistence_after_privilege` | 9 | account/group change → persistence-shaped command (schtasks, service, run key, WMI), within 60 min |

```powershell
plasma chain score --events C:\ProgramData\Plasma\data\events.jsonl
plasma chain score --events ... --window 1800 --max-rows 5000
```

Semantics worth knowing:

- Matching is on **timestamps**, not file order; input order is irrelevant.
- The matcher backtracks: a dead-end candidate does not hide a later match.
- Each built-in chain carries its own `gap_seconds`; the `--window` flag is
  the default for chains that do not specify one.
- Every match reports the span, the users involved and the matched rows.
- Chains also run inside every `watch` sweep.

## Drift — what changed since I last looked

```powershell
plasma drift record attest    # snapshot today's truth
plasma drift score  attest    # diff now vs baseline, 0-10
plasma drift list
```

`attest` compares the observatory's self-view (sensor states, blind spots,
identity/privilege surface). Score 0 means "nothing changed"; every change
is a finding with its own score. Drift refuses to baseline on a failed
collection — a broken baseline is worse than none.

## Coverage — knowing your holes

```powershell
plasma coverage
```

Diffs the shipped rules (tap + gene baseline + IOC feed) against a curated
list of 36 core on-box ATT&CK techniques. It reports:

- `coverage_pct` — **88.9%** (32/36) with ATT&CK parent rollup
  (a parent counts when any sub-technique is covered);
- `coverage_exact_pct` — **72.2%** (26/36) counting only exact tags;
- `weighted_pct` — **80.6%**, discounting low/medium-fidelity rules
  (weights 1.0 / 0.7 / 0.4);
- `covered` — technique → rules + per-rule fidelity + `via_subtechnique`;
- `blind` — the four honest gaps: **T1056 / T1056.001** (input capture —
  needs kernel hooks), **T1112** (generic registry edits — not worth a
  noisy checkbox), **T1486** (impact — canary files are the honest
  detector, not a heuristic);
- `extra_coverage` — techniques watched outside the core list.

Breadth is deliberately reported alongside fidelity: a report cannot reach
100% by adding a weak rule, because the weighted number would fall, not
rise.

This is the anti-marketing page: a product that cannot list its blind spots
is not measuring anything.

## IOC push

```powershell
plasma whids pull --events store.jsonl                  # alerts → store
plasma whids push --events store.jsonl --min-confidence 8
plasma whids push --events store.jsonl --min-confidence 8 --apply --reason "..."
```

`push` extracts high-confidence indicators (SHA-256 file hashes, public
destinations, DNS queries, excluding private and benign domains) and
regenerates `plasma-iocs.gen`. Dry-run first; `--apply` replaces the live
rule file atomically. The default threshold matches the gene 0–10 scale.

## Event-level scoring

Raw Plasma rows carry 0–1 scores; `_row_score` maps them to the 0–10
criticality WHIDS expects (`score * 10`, severity fallback). At the finding
layer everything is 0–10. The scale conversion is unit-tested — a mismatch
here once caused a default `push` to extract zero indicators.
