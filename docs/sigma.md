# Sigma conversion

Plasma's gene schema and Sigma's `detection:` block describe the same thing:
a log source, one or more selections, and a boolean condition. `plasma sigma
convert` derives a `.gen` rule from that structure instead of hand-copying
rules, and reports every rule it cannot translate.

```powershell
plasma sigma convert --in .\sigma-rules --out sensors\plasma-sigma.gen
plasma sigma convert --in rule.yml --dry-run
```

PyYAML is loaded only when this command runs. Every other Plasma command
starts and works without it; if it is missing here you get one clear message
instead of an import traceback at startup.

Output is JSONL in the WHIDS gene schema, ready to drop into
`Database\Rules` (or `plasma whids push` for indicators). Duplicate names
are refused; the converter prints `converted`, `files` and a `skipped` list
with the reason for each refusal.

## The vendored corpus

Plasma ships **259 converted SigmaHQ rules** in
`sensors/plasma-sigma.gen`, selected from the Windows/Sysmon tree at commit
`54967d64` (15 November 2026). Selection is mechanical and reproducible:

- Windows/Sysmon categories only, Sysmon event IDs 1/3/6/7/10/11/12/13/14/17/18;
- level medium or higher (26 critical, 150 high, 83 medium);
- one primary ATT&CK technique per rule, deduplicated, at most two per
  technique, capped at 300;
- 168 techniques represented; every rule keeps its upstream author and
  names its source file in `Meta.Comment`.

The corpus is **data under the Detection Rule License (DRL) 1.1**, not MIT.
The licence text ships as `sensors/SIGMA-DRL-1.1.md`; provenance and the
selection counts are in `sensors/sigma-sources.json`. Rebuild it with:

```bash
git clone https://github.com/SigmaHQ/sigma /tmp/sigma
python tools/sync_sigma_corpus.py --source /tmp/sigma/rules/windows \
    --commit "$(git -C /tmp/sigma rev-parse HEAD)"
```

Field check: WHIDS 1.7.0 loaded **278 rules** (19 baseline/IOC + 259 Sigma)
on WS2 with no compile errors.

## Supported subset

| Piece | Support |
|---|---|
| Log sources | Windows/Sysmon categories: `process_creation` (1), `image_load` (7), `driver_load` (6), `file_event`/`file_create` (11), `network_connection` (3), `pipe_created` (17/18), `process_access` (10), `registry_event`/`registry_set` (12/13/14) |
| Explicit `EventID` | Wins over the category default |
| Selections | maps, and lists of maps (OR) |
| Field modifiers | `contains`, `startswith`, `endswith`, `re`, `all`, `i` |
| Conditions | selection names with `and` / `or` / `not` and parentheses (emitted as gene `!`) |
| Metadata | title, description, level → criticality, `attack.tXXXX` tags |

## Refused, with a reason

- non-Windows log sources;
- `1 of selection*` / `all of them` quantified conditions;
- selection shapes other than maps or lists of maps;
- rules with no EventID and no mapped category;
- unsupported field modifiers (`windash`, `cidr`, `base64offset`, `fieldref`)
  — refused rather than silently mistranslated.

Refusals are data: they appear in the `skipped` list rather than disappearing.

## Why this shape

Adding rules by hand does not scale and quietly drifts from the upstream
corpus. A converter keeps the mapping mechanical: every generated rule has a
source file, a condition, and a technique tag. It also makes coverage growth
honest — a converted rule is real evidence in the always-on plane, not a
relabelled keyword.
