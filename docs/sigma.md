# Sigma conversion

Plasma's gene schema and Sigma's `detection:` block describe the same thing:
a log source, one or more selections, and a boolean condition. `plasma sigma
convert` derives a `.gen` rule from that structure instead of hand-copying
rules, and reports every rule it cannot translate.

```powershell
plasma sigma convert --in .\sigma-rules --out sensors\plasma-sigma.gen
plasma sigma convert --in rule.yml --dry-run
```

Output is JSONL in the WHIDS gene schema, ready to drop into
`Database\Rules` (or `plasma whids push` for indicators). Duplicate names
are refused; the converter prints `converted`, `files` and a `skipped` list
with the reason for each refusal.

## Supported subset

| Piece | Support |
|---|---|
| Log sources | Windows/Sysmon categories: `process_creation` (1), `image_load` (7), `driver_load` (6), `file_event`/`file_create` (11), `network_connection` (3), `pipe_created` (17/18), `process_access` (10), `registry_event`/`registry_set` (12/13/14) |
| Explicit `EventID` | Wins over the category default |
| Selections | maps, and lists of maps (OR) |
| Field modifiers | `contains`, `startswith`, `endswith`, `re`, `all` |
| Conditions | selection names with `and` / `or` / `not` and parentheses |
| Metadata | title, description, level → criticality, `attack.tXXXX` tags |

## Refused, with a reason

- non-Windows log sources;
- `1 of selection*` / `all of them` quantified conditions;
- selection shapes other than maps or lists of maps;
- rules with no EventID and no mapped category.

Refusals are data: they appear in the `skipped` list rather than disappearing.

## Why this shape

Adding rules by hand does not scale and quietly drifts from the upstream
corpus. A converter keeps the mapping mechanical: every generated rule has a
source file, a condition, and a technique tag. It also makes coverage growth
honest — a converted rule is real evidence in the always-on plane, not a
relabelled keyword.
