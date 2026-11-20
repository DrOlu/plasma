# Investigation

Plasma is lake-less, but an investigation still needs to answer precise
questions, follow lineage, keep the evidence and hand over a sealed artifact.
Four local surfaces cover that loop: `query`, `tree`, `summarize` and
`case`. They read the same bounded JSONL store and never send it anywhere.

## Typed query

```powershell
plasma query --process powershell.exe --since 1h
plasma query --kind alert --min-score 0.7 --count-by process
plasma query --host WS1 --user CORP\olu --since 24h
plasma query --spec incident-42-query.json
```

The query language is closed. A typo in a field name is an error, not a
silent widening of the search:

| Field | Meaning |
|---|---|
| `host`, `user`, `kind`, `source`, `action`, `severity` | exact match |
| `event_id`, `pid` | integer match |
| `process`, `parent`, `image` | basename match, case-insensitive, `*`/`?` globs |
| `technique` | ATT&CK ID, e.g. `T1055` |
| `contains` | case-insensitive substring across description, command line, image, path, DNS and alert ID |
| `regex` | explicit regular expression over the same fields |
| `since`, `until` | ISO timestamp or duration (`15m`, `1h`, `2d`) |
| `min_score`, `max_score` | 0–1 event score |
| `count_by` | aggregate over `host`, `user`, `kind`, `process`, `event_id` and more |
| `limit`, `max_rows`, `order` | bound the result and the tail read |

The reader is bounded to the last `--max-rows` (default 5000) within an
8 MiB tail. `--out` writes the full result locally.

## Process lineage

```powershell
plasma tree --pid 4832
plasma tree --process powershell.exe --depth 2
```

`tree` builds parent/child edges only from explicit `pid`/`ppid` pairs.
Sysmon EID 1 and Security 4688 both populate `ppid` when the audit policy
records it. A missing parent is reported as an orphan root; Plasma does not
guess lineage from a process name.

Depth is capped at 10 and the result at 500 nodes. Truncation is explicit.

## A bounded digest

```powershell
plasma summarize --since 1h
plasma summarize --since 24h --limit 50 --rare-max 1
```

`summarize` is the orientation step before a query or a case: process
first/last seen, parent→child frequencies, top users and hosts, score bands,
event sources and rare command lines. It is a map, not the territory, and
every section is capped.

## Case workspace

A case is a directory under `<root>/cases/<name>`:

```
case.json          metadata and counts
events.jsonl       selected event rows
findings.jsonl     selected findings
notes.md           operator notes
report.md          rendered Markdown report
manifest.json      sealed per-file hashes + chain hash
```

```powershell
plasma case open IR-2026-042 --host WS1 --title "LSASS access"
plasma case add IR-2026-042 --process lsass.exe --since 2h
plasma case add IR-2026-042 --technique T1055 --min-score 0.7
plasma case note IR-2026-042 "Confirmed with the user"
plasma case timeline IR-2026-042
plasma case report IR-2026-042
plasma case seal IR-2026-042
plasma case verify IR-2026-042
```

`case add` refuses to run without a filter: a case is a selection, not a
copy of the diary. Duplicate rows are not appended twice. Reopening a case
never clears evidence.

`case seal` hashes every artifact and writes a chain hash. `case verify`
recomputes it and exits 2 on any changed or missing file. Sealing is tamper
evidence, not encryption.

## Detection engineering

```powershell
plasma detect validate --rules sensors/plasma-baseline.gen
plasma detect test
plasma detect diff --old old.gen --new candidate.gen
plasma detect replay --events captured.jsonl
```

`validate` compiles every regex expression and checks condition variables;
`test` runs deterministic hit/miss chain cases; `diff` reports rules added,
removed and changed by name and content hash; `replay` runs the chain engine
and a bounded summary over a captured store.
Promotion stays on the existing install/WHIDS path, so a rule cannot reach a
live sensor without passing that gate.

## What this does not do

- It does not create a database or index. Every read is a bounded tail.
- It does not infer lineage from process names.
- It does not sign or encrypt a case; it seals it with SHA-256 hashes.
- It does not call a model. All four surfaces are deterministic.
