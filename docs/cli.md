# CLI reference

Every command prints JSON. Exit codes are part of the contract:
`0` success/clean, `1` data or input error, `2` refused/attention needed,
`3` execution or verification failure.

## Endpoint commands

### install

```text
plasma install [--dry-run] [--force] [--root PATH] [--skip-whids]
              [--skip-sysmon-check] [--require-whids]
```

Intelligent installer: verifies the payload manifest, decides FULL/MINIMAL,
installs Sysmon when possible, provisions WHIDS, writes `config.json`, flips
the `current` junction, and reports the decision. `--require-whids` makes a
degraded decision fail with exit 3.

### health / status / probe / ask

```text
plasma health [--root PATH]
plasma status [--events FILE]
plasma probe --tool NAME --events FILE
plasma ask --prompt "..." --events FILE
```

`health` = checks + verdict. `status` = bundle identity + probe menu.
`probe`/`ask` = run one named probe, or let the on-device model choose one.
Refusals are structured, never guesses.

### identity

```text
plasma identity pull --events FILE [--host NAME] [--since MINUTES]
```

Reads 4624/4625 through the Event Log API, UTC-normalized, deduped.

### whids

```text
plasma whids pull    --root DIR --out FILE
plasma whids push    --events FILE [--min-confidence N] [--max-indicators N] [--apply] [--reason TEXT]
plasma whids status  --root DIR --events FILE
plasma whids diagnose [--root DIR]
plasma whids ensure  [--root DIR] [--wait SECONDS]
```

`push` is dry-run by default; `--apply` replaces `plasma-iocs.gen`
atomically. Default confidence is 8 on the gene 0–10 scale.

`ensure` is the watchdog body: Running is a no-op; a hung `StartPending` is
force-stopped and restarted; a stopped service is started. Actions are
appended to `logs/whids-watchdog.log`. The installer registers
`PlasmaWhidsWatchdog` (SYSTEM, every 2 minutes) to run it.

### trace

```text
plasma trace list
plasma trace check
plasma trace selftest [--root DIR]
plasma trace run <script> --events FILE [--for 5s] [--max-rows N] [--out FILE]
plasma trace provision
```

Reviewed, bounded DTrace runs normalized into the event store.
`provision` installs the Microsoft package (direct MSI when winget is
absent), enables `bcdedit /set dtrace on`, and reports
`reboot_required: true`. Installed + enabled is ready; versions are not
chased. Scripts emit `tid` for estate portability.

### tap

```text
plasma tap list
plasma tap selftest [--rules FILE] [--tap-exe PATH]
plasma tap run [--providers LIST] [--for DURATION] [--max-matches N] [--out-dir DIR]
```

Bounded live ETW window. Exit 3 = the session could not start.

### deep

```text
plasma deep persistence [--json-out FILE] [--cap N]
```

One bounded pass over every auto-start location with Authenticode status.

### watch / notify

```text
plasma watch once
plasma watch loop --every SECONDS
plasma notify show [--root PATH]
plasma notify test [--root PATH] [--host NAME]
```

`watch` = health + drift + new alerts + chains → verdict; exits non-zero
when findings exist. `notify` validates and tests delivery channels.

### drift

```text
plasma drift record QUESTION [--root PATH] [--canary ACCOUNT...]
plasma drift score  QUESTION [--root PATH]
plasma drift list   [--root PATH]
```

`record` snapshots; `score` diffs (exit 2 on drift, 1 on collection error).

### chain / store / coverage

```text
plasma chain score --events FILE [--window SECONDS] [--max-rows N]
plasma store rotate  --events FILE [--max-mb N] [--keep N]
plasma store compact --events FILE [--out FILE]
plasma store stats   --events FILE
plasma coverage [--sensors DIR]
```

Chains scan the tail; store commands keep the diary bounded; coverage
reports ATT&CK coverage incl. blind spots.

### observe

```text
plasma observe attest|sketch|edges|explain|pslogs|attackmap|...
```

Read-only self-knowledge questions (identity surface, logon edges, network
edges, PowerShell logs, attack map). `attest` includes the blind check.

## Desk-side commands

### fleet

```text
plasma fleet pull      --inventory FILE --case NAME [--cap N] [--window SECONDS] [--canary ACCOUNT...]
plasma fleet correlate --case NAME [--window SECONDS]
plasma fleet report    --case NAME
```

Correlates lateral hops, shared indicators, canaries and blind hosts.

### actuate / playbook

```text
plasma actuate apply <action> [--target T] --reason TEXT [--apply --plan ID]
plasma actuate undo  --id ID [--apply]
plasma actuate journal [--last N]
plasma actuate apply --list
plasma playbook list
plasma playbook apply <name> [--target T] --reason TEXT [--apply --plan ID]
plasma playbook undo  --id ID [--apply]
```

`--apply` requires `--plan` from a seen dry-run of the same action + target.

### update

```text
plasma update check [--repo OWNER/NAME] [--token-env VAR]
plasma update apply [--bin PATH] [--root PATH] [--allow-unsigned]
```

Anonymous against the public repo; signature-pinned.

### manifest / bundle

```text
plasma manifest verify <path>
plasma bundle create   [--out FILE]
```

Integrity tooling for the embedded payload.

## Common environment variables

| Variable | Used by |
|---|---|
| `PLASMA_GITHUB_TOKEN` | optional token for private forks |
| `PLASMA_SIGNER_THUMBPRINTS` | override the pinned update signers |
| `PLASMA_TG_TOKEN` | Telegram alert token (via `notify.json` `token_env`) |
| `WS1PW`, `WS2PW`, … | fleet inventory `password_env` values |
