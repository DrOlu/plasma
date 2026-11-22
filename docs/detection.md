# Detection

Detection in Plasma is written rules and written sequences — nothing is
learned in the detection path. Every statement carries a fixed score and an
ATT&CK technique where one applies.

Detection feeds three consumers: `watch` (operator sweep), `chain` (story
matching) and `enforce` (policy-gated containment). Only the last can change
a host, and only when you have enabled it. See
[Prevention and blocking](prevention.md).

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

Twenty-five baseline rules with ATT&CK tags, criticality 6–9. See
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

## Detector plugins

A detector plugin runs over a bounded event tail and prints findings:

```powershell
plasma plugin run acme-detector --since 1h --max-rows 5000
```

Findings become `kind=alert` rows with `alert_id=plugin:<name>`, a clamped
score, the technique and bounded evidence. The runner enforces a timeout and
the manifest's `max_score`. Declarative gene/Sigma packs are validated with the
existing harness:

```powershell
plasma detect validate --rules C:\plugins\acme\rules\pack.gen
```

Plugin findings enter the same store, so chains, query and the anomaly scorer
see them without a second pipeline. They do not drive automatic containment.

## Identity — standing pulls

The shipped product registers a SYSTEM task (`PlasmaIdentityPull`) that runs
the bounded Security-log pull every 15 minutes, so authentication and
process-lineage events reach the store between operator sweeps: 4624/4625
logons, 4648 explicit credentials, 4720/4722/4724 account lifecycle,
4728/4732/4756 group membership, 4768/4769/4770/4771 Kerberos, 4776 NTLM and
4688 process creation with parent PID. Directory-service access (4662) and
special privileges (4672) are supported but excluded from the default pull
because they are high-volume; ask for them explicitly with `--ids`.
Kerberos events exist only on a KDC, so a member server reports zero of them —
that is data, not an error. Manage the task explicitly with:

```powershell
plasma identity schedule --root C:\ProgramData\Plasma --every 15
plasma identity schedule-status
plasma identity unschedule
```

The task is registered by `install`/`update` and is independent of `watch`.

## DTrace — on-demand syscall evidence

`plasma trace run <script> --for 10s` opens a bounded DTrace window (kernel
syscalls, process creation, ETW) and normalizes matches into the same store
(`kind: "trace"`). It is surgical evidence, not always-on coverage, so it is
deliberately **not** counted in the ATT&CK breadth number. See
[DTrace](trace.md).

## Chains — stories, not events

A single alert says "something happened". A chain says "this, then this,
then this". Chains are ordered matchers over the events tail with a gap
window between adjacent steps, plus optional **count** steps.

| Chain | Score | Story (in time order) |
|---|---|---|
| `phish_spawn_chain` | 9 | Office app → script host (powershell/wscript/cscript/mshta) → encoded command or egress, all within 15 min |
| `brute_force_success` | 8 | ≥5 failed logons for one user, then a success, within 60 min |
| `persistence_after_privilege` | 9 | account/group change → persistence-shaped command (schtasks, service, run key, WMI), within 60 min |
| `account_creation_privilege` | 9 | a new account (4720) → privileged group membership (4728/4732/4756), within 30 min |

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

## Detection engineering — validate, diff, replay

```powershell
plasma detect validate --rules sensors/plasma-baseline.gen
plasma detect test
plasma detect diff --old old.gen --new candidate.gen
plasma detect replay --events captured.jsonl
```

`validate` compiles every `~=` regex, checks condition variables and names
duplicates. `test` runs a built-in suite of positive and negative chain
cases (phishing, brute force, Kerberos spray, privilege-to-persistence,
account creation, injection) and exits 2 if any case breaks. `diff` compares
rule sets by name and canonical hash, so an added, removed or silently
changed rule is visible before promotion. `replay` runs the chain engine and
a bounded summary over a captured store; the model is not involved.
Promotion stays on the install/WHIDS path.

## Coverage — knowing your holes

```powershell
plasma coverage
```

Diffs the shipped rules (tap + gene baseline + IOC feed + the 259-rule
Sigma corpus) against a curated list of 37 core on-box ATT&CK techniques.
It reports:

- `coverage_pct` — **94.6%** (35/37) with ATT&CK parent rollup
  (a parent counts when any sub-technique is covered);
- `coverage_exact_pct` — **89.2%** (33/37) counting only exact tags;
- `weighted_pct` — **85.9%**, discounting low/medium-fidelity rules
  (weights 1.0 / 0.7 / 0.4), halving purely keyword-only evidence, and
  counting only rules whose event IDs the shipped Sysmon config enables;
- `weighted_all_pct` — the same number without the telemetry filter, for
  comparison;
- `telemetry_breakdown` — techniques by `live` / `partial` / `dormant` /
  `unknown`, derived from each rule's `Meta.EventIDs` against the config;
- `dormant_techniques` — techniques backed only by rules that cannot fire;
- `covered` — technique → rules + per-rule fidelity + `evidence` + `via_subtechnique`;
- `keyword_only` — the 4 techniques still backed solely by literal string
  matches; they count for breadth but not full weight. The label is
  derived from the rule shape (a rule whose only match key is `substr`),
  never hand-set, so it cannot drift from the rules themselves;
- `blind` — the two honest gaps: **T1056 / T1056.001** (input capture —
  needs kernel hooks). **T1486** is covered by the canary capability
  (`canary:verify`), reported with its own provenance. A rule you cannot
  fire is inventory, not coverage: the telemetry axis makes that explicit;
- `extra_coverage` — techniques watched outside the core list.

Breadth is deliberately reported alongside fidelity: a report cannot reach
100% by adding a weak rule, because the weighted number would fall, not
rise.

This is the anti-marketing page: a product that cannot list its blind spots
is not measuring anything.

### What the always-on plane now reads

Beyond process creation and registry events, the gene baseline consumes
three Sysmon events that were previously ignored:

| Event | Rule | Technique |
|---|---|---|
| 10 ProcessAccess | LSASS opened with credential-dump access rights | T1003.001 |
| 6 DriverLoad | unsigned driver loaded from a user-writable path | T1014 |
| 17/18 PipeCreated | named pipe shaped like PsExec/Cobalt/Beacon | T1021, T1090 |

Sigma rules can be converted mechanically into the same gene format; see
[Sigma conversion](sigma.md). Critical-file integrity is covered by
[FIM](fim.md).

## Canaries — impact and access tripwires

```powershell
plasma canary deploy [--dir D:\Finance]   # realistic decoys + hash manifest
plasma canary verify                        # exit 2 when a canary is touched
plasma canary status
plasma canary token create --kind dns --domain assets.internal
plasma canary sysmon --apply                # narrow Sysmon EID 22 include
plasma canary token create --kind http --base-url http://collector:8088
plasma canary serve --host 127.0.0.1 --port 8088
plasma canary collect
plasma canary hits
```

File canaries are valid xlsx/csv/docx/pdf documents with random
subdirectories and names. The body never says "canary"; the manifest is the
only marker. `watch` verifies them on every sweep: a **missing or modified
canary is a score-10 finding** (`canary_tripped`) — the honest detector for
destructive impact that does not depend on guessing at encryption bursts.
Deploy them to user-data shares as well as the default `Documents` folder.

DNS tokens are unique hostnames. Give the suffix a matching internal DNS
record (usually a wildcard/sinkhole) so the query reaches a resolver. A
query is observed through a narrow Sysmon EID 22 include (only the
configured token suffixes) or any normalized event carrying `dns_query`;
`watch` emits `canary_dns_tripped` at score 8.
HTTP tokens are Windows `.url` shortcuts pointing at `plasma canary serve`;
the hit is recorded locally and becomes `canary_http_tripped` at score 8.
No Docker, cloud service or external callback is involved.

Registry canaries are decoy keys under `Software\PlasmaDecoy`. The active
shield (`plasma canary shield install`) adds only the recorded file basenames
and registry fragments to a narrow Sysmon FileCreate/FileDelete/RegistryEvent
include and runs a one-minute SYSTEM sweep. It verifies the live PID and
image, refuses protected/trusted processes, then kills a process that
creates, deletes or registry-writes a canary. Reads do not trigger; an
in-place overwrite is still caught by `canary verify` as a hash change,
without process attribution.

Configured canary accounts are queried on every watch sweep:
`config.json`:

```json
{"canary": {"accounts": ["svc-print-archive"]}}
```

A 4624/4625/4771/4776 for that account becomes
`canary_account_tripped` at score 10. A canary hit is evidence, not an
automatic kill: the response policy still requires approval for host
isolation.

## Memory scanning

```powershell
plasma memory scan --pid 4832
plasma memory scan --pname powershell.exe,rundll32.exe --deep
```

HollowsHunter/PE-sieve looks inside running processes for hollowing,
implanted PEs, shellcode, code patches and IAT hooks. It is on-demand and
bounded; the scanner is hash-pinned. Findings are `source="memory"` alerts
with T1055/T1055.012/T1620 as appropriate. No dumps by default.

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
